// Package config loads logs.json, the mirror's own list of CT log shards.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// DefaultMMD is the maximum merge delay assumed for a shard whose logs.json
// entry does not state one. Every log on Yandex's list declares 86400.
const DefaultMMD = 24 * time.Hour

// maxMMDSeconds bounds what logs.json may declare. Every log on Yandex's
// list says 86400 and Chrome's policy caps RFC 6962 logs at four hours, so a
// week is already far outside anything a real log publishes; the bound is
// here so that an MMD read from a file can be turned into a time.Duration and
// added to without overflowing.
const maxMMDSeconds = 7 * 24 * 60 * 60

// TLSMode selects which trust anchors are used for a log's HTTPS endpoint.
type TLSMode string

const (
	// TLSSystem uses the operating system trust store.
	TLSSystem TLSMode = "system"
	// TLSRussianTrusted uses only the pinned Russian Trusted Root CA from roots/.
	TLSRussianTrusted TLSMode = "russian-trusted"
)

// Log describes one CT log shard.
type Log struct {
	Operator    string `json:"operator"`
	Shard       string `json:"shard"`
	Description string `json:"description"`
	URL         string `json:"url"`
	LogID       string `json:"log_id"`
	Key         string `json:"key"`
	// MMDSeconds is the log's declared maximum merge delay, copied from
	// ctlog.json. Zero means unstated; use MMD rather than reading it.
	MMDSeconds int64   `json:"mmd,omitempty"`
	TLS        TLSMode `json:"tls"`
	KeySource  string  `json:"key_source"`
	Disabled   bool    `json:"disabled,omitempty"`
	Note       string  `json:"note,omitempty"`
}

// Operator tells the mirror how to take on a new shard that ctlog.json lists
// under one operator's name. Only an operator named here can have shards
// adopted without a maintainer, and only on the hosts it names.
type Operator struct {
	// Operator is the slug used in shard names and data/ paths.
	Operator string `json:"operator"`
	// TLS is the mode the operator's log servers need.
	TLS TLSMode `json:"tls"`
	// Hosts are the host names, or suffixes beginning with a dot, that the
	// operator's logs are served from.
	Hosts []string `json:"hosts"`
}

// ServesHost reports whether host is one of the operator's hosts.
func (o Operator) ServesHost(host string) bool {
	host = strings.ToLower(host)
	for _, h := range o.Hosts {
		h = strings.ToLower(h)
		if host == h || (strings.HasPrefix(h, ".") && strings.HasSuffix(host, h)) {
			return true
		}
	}
	return false
}

// Name is the operator/shard pair used in paths and messages.
func (l Log) Name() string { return l.Operator + "/" + l.Shard }

// MMD is the log's maximum merge delay. RFC 6962 §3.5 requires a log to
// produce on demand an STH no older than this, signing the same root with a
// fresh timestamp when nothing was submitted, so an STH older than the MMD is
// a breach of the log's own published terms and not merely a quiet log.
func (l Log) MMD() time.Duration {
	if l.MMDSeconds <= 0 {
		return DefaultMMD
	}
	return time.Duration(l.MMDSeconds) * time.Second
}

// KeyDER returns the log's SubjectPublicKeyInfo, or nil when unknown.
func (l Log) KeyDER() ([]byte, error) {
	if l.Key == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(l.Key)
}

// File is the top-level structure of logs.json.
type File struct {
	LogListURL string `json:"log_list_url"`
	// Operators maps an operator's name exactly as ctlog.json spells it to
	// what adopting one of its shards needs.
	Operators map[string]Operator `json:"operators,omitempty"`
	Logs      []Log               `json:"logs"`
}

// Load reads and validates logs.json.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// Validate checks everything Load requires of a parsed file. Save calls it
// too, so the mirror can never write a file it would refuse to read back.
func (f *File) Validate() error {
	for name, o := range f.Operators {
		if o.Operator == "" || strings.ContainsAny(o.Operator, "/\\ ") {
			return fmt.Errorf("operator %q: slug must be non-empty and path-safe", name)
		}
		switch o.TLS {
		case TLSSystem, TLSRussianTrusted:
		default:
			return fmt.Errorf("operator %q: unknown tls mode %q", name, o.TLS)
		}
		if len(o.Hosts) == 0 {
			return fmt.Errorf("operator %q: no hosts", name)
		}
	}
	seen := map[string]bool{}
	for _, l := range f.Logs {
		if l.Operator == "" || l.Shard == "" || l.URL == "" {
			return fmt.Errorf("log %q lacks operator, shard or url", l.Description)
		}
		if strings.ContainsAny(l.Operator+l.Shard, "/\\ ") {
			return fmt.Errorf("%s: operator/shard must be path-safe", l.Name())
		}
		if !strings.HasSuffix(l.URL, "/") {
			return fmt.Errorf("%s: url must end with /", l.Name())
		}
		if seen[l.Name()] {
			return fmt.Errorf("duplicate log %s", l.Name())
		}
		seen[l.Name()] = true
		if l.MMDSeconds < 0 || l.MMDSeconds > maxMMDSeconds {
			return fmt.Errorf("%s: mmd must be between 0 and %d seconds, got %d",
				l.Name(), maxMMDSeconds, l.MMDSeconds)
		}
		switch l.TLS {
		case TLSSystem, TLSRussianTrusted:
		default:
			return fmt.Errorf("%s: unknown tls mode %q", l.Name(), l.TLS)
		}
		der, err := l.KeyDER()
		if err != nil {
			return fmt.Errorf("%s: bad key: %w", l.Name(), err)
		}
		if der != nil {
			id := sha256.Sum256(der)
			if got := base64.StdEncoding.EncodeToString(id[:]); got != l.LogID {
				return fmt.Errorf("%s: log_id %s does not match sha256(key) %s", l.Name(), l.LogID, got)
			}
		}
	}
	return nil
}

// Save writes f to path in the layout logs.json is kept in: two-space
// indent, no HTML escaping, a trailing newline. A file loaded and saved
// unchanged comes back byte for byte, so a run that adopts or retires a
// shard leaves a diff that shows only that.
func (f *File) Save(path string) error {
	if err := f.Validate(); err != nil {
		return fmt.Errorf("%s: refusing to write: %w", path, err)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
