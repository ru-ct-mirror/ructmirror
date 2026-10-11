// Package ctclient is a minimal RFC 6962 read-only client.
package ctclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"

	"github.com/ru-ct-mirror/ructmirror/internal/config"
)

const userAgent = "ru-ct-mirror (+https://github.com/ru-ct-mirror/ru-ct-mirror)"

// Client talks to CT logs, choosing trust anchors per log.
//
// A request that fails with a 5xx, a 429, a transport error or a body that is
// not JSON is retried up to Retries times. The wait before retry n is
// Backoff·2^(n-1), with ±20% jitter so shards on one host do not retry in
// step, raised to the server's Retry-After when it asks for longer, and never
// more than MaxBackoff. A 4xx other than 429 is the log's answer and is
// returned at once.
//
// A host that exhausted every retry on a 5xx or a transport error is marked
// down for the rest of the Client's life: later requests to it make a single
// attempt, and any answer below 500 clears the mark. The six yearly shards of
// one operator share a host, so without this one outage costs six full
// backoff windows; with it the first shard waits and the rest only check.
type Client struct {
	system     *http.Client
	russian    *http.Client
	Retries    int
	Backoff    time.Duration
	MaxBackoff time.Duration
	// Log, when set, receives one line per retry and per request cut short
	// by a host marked down.
	Log io.Writer

	mu   sync.Mutex
	down map[string]bool
}

// New builds a client. rootsDir holds PEM files: names containing "root" are
// trust anchors, names containing "sub" are intermediates that the
// digital.gov.ru servers omit from their TLS chain.
func New(rootsDir string) (*Client, error) {
	roots := x509.NewCertPool()
	inters := x509.NewCertPool()
	files, err := filepath.Glob(filepath.Join(rootsDir, "*.pem"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no PEM files in %s", rootsDir)
	}
	for _, f := range files {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(f)
		var ok bool
		switch {
		case strings.Contains(base, "root"):
			ok = roots.AppendCertsFromPEM(pem)
		case strings.Contains(base, "sub"):
			ok = inters.AppendCertsFromPEM(pem)
		default:
			return nil, fmt.Errorf("%s: file name must contain \"root\" or \"sub\"", f)
		}
		if !ok {
			return nil, fmt.Errorf("%s: no certificate found", f)
		}
	}
	mk := func(cfg *tls.Config) *http.Client {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = cfg
		return &http.Client{Timeout: 90 * time.Second, Transport: t}
	}
	// Go's tls.Config has no "extra intermediates" knob, so verification for the
	// pinned mode is done by hand: skip the built-in check, then verify the
	// served chain against our root with our intermediates and the SNI host name.
	pinned := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			for _, c := range cs.PeerCertificates[1:] {
				inters.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: inters,
				DNSName:       cs.ServerName,
			})
			return err
		},
	}
	return &Client{
		system:  mk(nil),
		russian: mk(pinned),
		// 2+4+8+16+32+60 s: about two minutes per request before giving up.
		Retries:    6,
		Backoff:    2 * time.Second,
		MaxBackoff: time.Minute,
		down:       map[string]bool{},
	}, nil
}

func (c *Client) httpFor(l config.Log) *http.Client {
	if l.TLS == config.TLSRussianTrusted {
		return c.russian
	}
	return c.system
}

// get fetches l.URL+path with retries and decodes JSON into out.
func (c *Client) get(ctx context.Context, l config.Log, path string, out any) error {
	u := l.URL + path
	return c.do(ctx, c.httpFor(l), u, 64<<20, func(body []byte) error {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("GET %s: bad JSON: %w", u, err)
		}
		return nil
	})
}

// do GETs u with the retry policy described on Client and hands a 200 body,
// read up to limit bytes, to accept. An error from accept is retried like a
// server error, since a truncated or garbled response is usually transient.
func (c *Client) do(ctx context.Context, hc *http.Client, u string, limit int64, accept func([]byte) error) error {
	var host string
	if pu, err := url.Parse(u); err == nil {
		host = pu.Host
	}
	retries := c.Retries
	if c.isDown(host) {
		retries = 0
		c.logf("%s did not answer earlier in this run; trying %s once\n", host, u)
	}
	var (
		last error
		wait time.Duration
		// hostFault is true when the last failure says nothing came back
		// from the host that it meant: no response, a 5xx or a 429.
		hostFault bool
	)
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			c.logf("retry %d/%d in %s: %v\n", attempt, retries, wait.Round(100*time.Millisecond), last)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			last, hostFault = err, true
			wait = c.delay(attempt, "", time.Now())
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		resp.Body.Close()
		if err != nil {
			last, hostFault = err, true
			wait = c.delay(attempt, "", time.Now())
			continue
		}
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			last = fmt.Errorf("GET %s: HTTP %d: %.200s", u, resp.StatusCode, body)
			hostFault = true
			wait = c.delay(attempt, resp.Header.Get("Retry-After"), time.Now())
			continue
		}
		// Anything below 500 is the host answering.
		c.setDown(host, false)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: HTTP %d: %.200s", u, resp.StatusCode, body)
		}
		if err := accept(body); err != nil {
			last, hostFault = err, false
			wait = c.delay(attempt, "", time.Now())
			continue
		}
		return nil
	}
	if hostFault {
		c.setDown(host, true)
	}
	return fmt.Errorf("GET %s failed after %d attempts: %w", u, retries+1, last)
}

// delay is the wait after failed attempt number attempt (0-based) before the
// next one. retryAfter is the response's Retry-After header, if any.
func (c *Client) delay(attempt int, retryAfter string, now time.Time) time.Duration {
	d := c.Backoff
	for i := 0; i < attempt && (c.MaxBackoff <= 0 || d < c.MaxBackoff); i++ {
		d *= 2
	}
	if c.MaxBackoff > 0 && d > c.MaxBackoff {
		d = c.MaxBackoff
	}
	d += time.Duration(float64(d) * (rand.Float64()*0.4 - 0.2))
	if ra := parseRetryAfter(retryAfter, now); ra > d {
		d = ra
	}
	if c.MaxBackoff > 0 && d > c.MaxBackoff {
		d = c.MaxBackoff
	}
	return d
}

// parseRetryAfter reads a Retry-After value, either delay-seconds or an
// HTTP-date (RFC 9110 §10.2.3). It returns 0 for anything else.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseUint(v, 10, 32); err == nil {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

func (c *Client) isDown(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.down[host]
}

func (c *Client) setDown(host string, down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down == nil {
		c.down = map[string]bool{}
	}
	if down {
		c.down[host] = true
	} else {
		delete(c.down, host)
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.Log != nil {
		fmt.Fprintf(c.Log, format, args...)
	}
}

// GetSTH returns the raw get-sth response and its parsed form.
func (c *Client) GetSTH(ctx context.Context, l config.Log) (*ct.GetSTHResponse, *ct.SignedTreeHead, error) {
	var raw ct.GetSTHResponse
	if err := c.get(ctx, l, "ct/v1/get-sth", &raw); err != nil {
		return nil, nil, err
	}
	sth, err := raw.ToSignedTreeHead()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: parsing STH: %w", l.Name(), err)
	}
	return &raw, sth, nil
}

// GetEntries fetches entries [start, end] inclusive; the log may return fewer.
func (c *Client) GetEntries(ctx context.Context, l config.Log, start, end uint64) ([]ct.LeafEntry, error) {
	var resp ct.GetEntriesResponse
	if err := c.get(ctx, l, fmt.Sprintf("ct/v1/get-entries?start=%d&end=%d", start, end), &resp); err != nil {
		return nil, err
	}
	if len(resp.Entries) == 0 {
		return nil, fmt.Errorf("%s: get-entries %d-%d returned no entries", l.Name(), start, end)
	}
	if uint64(len(resp.Entries)) > end-start+1 {
		return nil, fmt.Errorf("%s: get-entries %d-%d returned %d entries", l.Name(), start, end, len(resp.Entries))
	}
	return resp.Entries, nil
}

// GetConsistency returns the consistency proof between tree sizes first and second.
func (c *Client) GetConsistency(ctx context.Context, l config.Log, first, second uint64) ([][]byte, error) {
	var resp ct.GetSTHConsistencyResponse
	if err := c.get(ctx, l, fmt.Sprintf("ct/v1/get-sth-consistency?first=%d&second=%d", first, second), &resp); err != nil {
		return nil, err
	}
	return resp.Consistency, nil
}

// GetJSON fetches an arbitrary URL with the system trust store (used for
// ctlog.json), with the same retries as the log endpoints. The body is
// returned as served; checking it is JSON is left to the caller.
func (c *Client) GetJSON(ctx context.Context, u string) ([]byte, error) {
	var out []byte
	err := c.do(ctx, c.system, u, 8<<20, func(body []byte) error {
		out = body
		return nil
	})
	return out, err
}
