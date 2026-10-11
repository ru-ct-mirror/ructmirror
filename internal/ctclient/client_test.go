package ctclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ru-ct-mirror/ructmirror/internal/config"
)

func TestPinnedModeRejectsForeignCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tree_size":0,"timestamp":0,"sha256_root_hash":"","tree_head_signature":""}`))
	}))
	defer srv.Close()
	roots := t.TempDir()
	// Use the real pinned roots so the test exercises the production pool.
	// testdata holds copies of the anchors the mirror repository pins in
	// roots/; the run itself reads that directory, not these.
	for _, f := range []string{"russian_trusted_root_ca.pem", "russian_trusted_sub_ca_2024.pem"} {
		b, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(roots, f), b, 0o644)
	}
	cl, err := New(roots)
	if err != nil {
		t.Fatal(err)
	}
	cl.Retries = 0
	l := config.Log{Operator: "x", Shard: "1", URL: srv.URL + "/", TLS: config.TLSRussianTrusted}
	_, _, err = cl.GetSTH(context.Background(), l)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("pinned client must reject httptest's self-signed cert, got %v", err)
	}
	l.TLS = config.TLSSystem
	_, _, err = cl.GetSTH(context.Background(), l)
	if err == nil {
		t.Fatal("system client must also reject an unknown CA")
	}
}

func TestNewRejectsUnnamedPEM(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "something.pem"), []byte("x"), 0o644)
	if _, err := New(dir); err == nil {
		t.Fatal("PEM files must be named root or sub")
	}
}

// retryClient builds a client over the system pool with millisecond backoff,
// so retry tests run fast. httptest's plain HTTP server needs no trust anchor.
func retryClient(t *testing.T) (*Client, *strings.Builder) {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join("testdata", "russian_trusted_root_ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "russian_trusted_root_ca.pem"), b, 0o644)
	cl, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cl.Backoff = time.Millisecond
	cl.MaxBackoff = 5 * time.Millisecond
	var log strings.Builder
	cl.Log = &log
	return cl, &log
}

const sthJSON = `{"tree_size":0,"timestamp":0,"sha256_root_hash":"","tree_head_signature":""}`

// scripted serves the given status codes in order, then 200 with body.
func scripted(t *testing.T, body string, codes ...int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)) - 1
		if i < len(codes) {
			w.WriteHeader(codes[i])
			w.Write([]byte("Service unavailable"))
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestRetriesServerErrorsThenSucceeds(t *testing.T) {
	cl, log := retryClient(t)
	srv, n := scripted(t, sthJSON, 503, 504)
	l := config.Log{Operator: "x", Shard: "1", URL: srv.URL + "/", TLS: config.TLSSystem}
	var out map[string]any
	if err := cl.get(t.Context(), l, "ct/v1/get-sth", &out); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 3 {
		t.Fatalf("want 3 requests, got %d", n.Load())
	}
	if strings.Count(log.String(), "retry ") != 2 || !strings.Contains(log.String(), "HTTP 504") {
		t.Fatalf("retries must be logged with their cause, got:\n%s", log)
	}
}

func TestClientErrorIsNotRetried(t *testing.T) {
	cl, _ := retryClient(t)
	srv, n := scripted(t, sthJSON, 404, 404)
	l := config.Log{Operator: "x", Shard: "1", URL: srv.URL + "/", TLS: config.TLSSystem}
	var out map[string]any
	err := cl.get(t.Context(), l, "ct/v1/get-sth", &out)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") || n.Load() != 1 {
		t.Fatalf("404 must fail after one request, got %v after %d", err, n.Load())
	}
}

func TestDownHostGetsOneAttemptUntilItAnswers(t *testing.T) {
	cl, log := retryClient(t)
	cl.Retries = 2
	var fail atomic.Bool
	fail.Store(true)
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		w.Write([]byte(sthJSON))
	}))
	defer srv.Close()
	a := config.Log{Operator: "x", Shard: "2026", URL: srv.URL + "/2026/", TLS: config.TLSSystem}
	b := config.Log{Operator: "x", Shard: "2027", URL: srv.URL + "/2027/", TLS: config.TLSSystem}
	var out map[string]any
	if err := cl.get(t.Context(), a, "ct/v1/get-sth", &out); err == nil {
		t.Fatal("want failure")
	}
	if n.Load() != 3 {
		t.Fatalf("first shard must use every retry, got %d requests", n.Load())
	}
	n.Store(0)
	if err := cl.get(t.Context(), b, "ct/v1/get-sth", &out); err == nil || !strings.Contains(err.Error(), "after 1 attempts") {
		t.Fatalf("second shard on a down host must try once, got %v", err)
	}
	if n.Load() != 1 || !strings.Contains(log.String(), "did not answer earlier") {
		t.Fatalf("got %d requests, log:\n%s", n.Load(), log)
	}
	// The host comes back: one answer clears the mark and retries return.
	fail.Store(false)
	if err := cl.get(t.Context(), b, "ct/v1/get-sth", &out); err != nil {
		t.Fatal(err)
	}
	if cl.isDown(strings.TrimPrefix(srv.URL, "http://")) {
		t.Fatal("an answer must clear the down mark")
	}
}

func TestGetJSONRetries(t *testing.T) {
	cl, _ := retryClient(t)
	srv, n := scripted(t, `{"version":"1"}`, 502)
	b, err := cl.GetJSON(t.Context(), srv.URL+"/ctlog.json")
	if err != nil || string(b) != `{"version":"1"}` || n.Load() != 2 {
		t.Fatalf("got %q, %v after %d requests", b, err, n.Load())
	}
}

func TestDelay(t *testing.T) {
	cl := &Client{Backoff: 2 * time.Second, MaxBackoff: time.Minute}
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	for attempt, want := range []time.Duration{2, 4, 8, 16, 32} {
		want *= time.Second
		d := cl.delay(attempt, "", now)
		if d < want*8/10 || d > want*12/10 {
			t.Errorf("attempt %d: %s outside %s ±20%%", attempt, d, want)
		}
	}
	for i := 0; i < 100; i++ {
		if d := cl.delay(10, "", now); d < 48*time.Second || d > time.Minute {
			t.Fatalf("must sit within 20%% under MaxBackoff, got %s", d)
		}
	}
	if d := cl.delay(0, "30", now); d != 30*time.Second {
		t.Errorf("Retry-After seconds must win when longer, got %s", d)
	}
	if d := cl.delay(0, now.Add(45*time.Second).Format(http.TimeFormat), now); d != 45*time.Second {
		t.Errorf("Retry-After date, got %s", d)
	}
	if d := cl.delay(0, "3600", now); d != time.Minute {
		t.Errorf("Retry-After must be capped, got %s", d)
	}
	if d := cl.delay(0, "soon", now); d > 3*time.Second {
		t.Errorf("garbage Retry-After must be ignored, got %s", d)
	}
}
