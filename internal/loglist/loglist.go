// Package loglist fetches Yandex Browser's ctlog.json and compares it with logs.json.
package loglist

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"

	"github.com/ru-ct-mirror/ructmirror/internal/config"
)

// Diff describes how the published list disagrees with logs.json.
type Diff struct {
	// Unknown lists logs present in ctlog.json but absent from logs.json.
	Unknown []string
	// Changed lists logs whose key or log_id differs between the two files.
	Changed []string
	// Retimed lists logs whose published MMD differs from the one logs.json
	// records. The MMD is what makes an STH stale, so a silent change to it
	// changes what the mirror accepts.
	Retimed []string
	// Dropped lists enabled logs.json shards that ctlog.json no longer
	// carries, by operator/shard name. Yandex lists only current shards, so
	// this is ordinary for a closed shard and not drift in itself.
	Dropped []string
	// Candidates holds the logs behind Unknown, in the same order, with what
	// Adopt needs to decide whether to take them on.
	Candidates []Candidate
	// Version and Published identify the list the diff was taken against.
	Version   string
	Published time.Time
}

// Candidate is a log ctlog.json lists that logs.json does not.
type Candidate struct {
	Operator    string // the operator's name as ctlog.json spells it
	Description string
	URL         string
	Key         string // base64 SubjectPublicKeyInfo
	LogID       string // base64
	MMDSeconds  int64
	Start       time.Time // temporal_interval.start_inclusive; zero when absent
	Status      loglist3.LogStatus
	// Line is the Unknown entry this candidate produced, for messages.
	Line string
}

// Empty reports whether the lists agree. Dropped shards do not count: a
// shard leaving the list is expected once its year is over.
func (d Diff) Empty() bool {
	return len(d.Unknown) == 0 && len(d.Changed) == 0 && len(d.Retimed) == 0
}

// Compare parses ctlog.json (Chrome log_list v3 schema) and checks it against cfg.
func Compare(ctlogJSON []byte, cfg *config.File) (Diff, error) {
	var d Diff
	ll, err := loglist3.NewFromJSON(ctlogJSON)
	if err != nil {
		return d, fmt.Errorf("parsing ctlog.json: %w", err)
	}
	d.Version, d.Published = ll.Version, ll.LogListTimestamp
	listed := map[string]bool{}
	byURL := map[string]config.Log{}
	for _, l := range cfg.Logs {
		byURL[l.URL] = l
	}
	for _, op := range ll.Operators {
		for _, l := range op.Logs {
			key := base64.StdEncoding.EncodeToString(l.Key)
			id := base64.StdEncoding.EncodeToString(l.LogID)
			listed[l.URL] = true
			known, ok := byURL[l.URL]
			if !ok {
				line := fmt.Sprintf("%s %s (%s) key=%s", op.Name, l.Description, l.URL, key)
				d.Unknown = append(d.Unknown, line)
				c := Candidate{Operator: op.Name, Description: l.Description, URL: l.URL,
					Key: key, LogID: id, MMDSeconds: int64(l.MMD), Status: l.State.LogStatus(), Line: line}
				if l.TemporalInterval != nil {
					c.Start = l.TemporalInterval.StartInclusive
				}
				d.Candidates = append(d.Candidates, c)
				continue
			}
			if known.Key != key || known.LogID != id {
				d.Changed = append(d.Changed, fmt.Sprintf("%s: ctlog.json key=%s log_id=%s, logs.json key=%s log_id=%s", known.Name(), key, id, known.Key, known.LogID))
			}
			// A log that publishes no mmd is read as RFC 6962's own default,
			// the same value config.Log.MMD falls back to, so an absent field
			// on either side is agreement rather than drift.
			published := time.Duration(l.MMD) * time.Second
			if l.MMD <= 0 {
				published = config.DefaultMMD
			}
			if published != known.MMD() {
				d.Retimed = append(d.Retimed, fmt.Sprintf("%s: ctlog.json mmd=%s, logs.json mmd=%s", known.Name(), published, known.MMD()))
			}
		}
	}
	for _, l := range cfg.Logs {
		if !l.Disabled && !listed[l.URL] {
			d.Dropped = append(d.Dropped, l.Name())
		}
	}
	return d, nil
}

// Adopt decides which of d's candidates can join logs.json without a
// maintainer, and returns them as logs.json entries. A candidate is adopted
// only when ctlog.json files it under an operator logs.json names, on one of
// that operator's hosts, as a working log with a temporal interval whose
// starting year is a free shard name, and with a key that hashes to its
// log_id. Every other candidate comes back in rejected with the reason, and
// stays the alert it always was.
func Adopt(d Diff, cfg *config.File) (added []config.Log, rejected []string) {
	taken := map[string]bool{}
	for _, l := range cfg.Logs {
		taken[l.Name()] = true
	}
	source := fmt.Sprintf("browser-resources.s3.yandex.net/ctlog/ctlog.json v%s (%s)",
		d.Version, d.Published.UTC().Format("2006-01-02"))
	for _, c := range d.Candidates {
		l, why := adoptOne(c, cfg, taken, source)
		if why != "" {
			rejected = append(rejected, fmt.Sprintf("%s: not adopted, %s", c.Line, why))
			continue
		}
		taken[l.Name()] = true
		added = append(added, l)
	}
	return added, rejected
}

func adoptOne(c Candidate, cfg *config.File, taken map[string]bool, source string) (config.Log, string) {
	op, ok := cfg.Operators[c.Operator]
	if !ok {
		return config.Log{}, fmt.Sprintf("operator %q is not in logs.json operators", c.Operator)
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return config.Log{}, "url is not an https URL"
	}
	if !op.ServesHost(u.Hostname()) {
		return config.Log{}, fmt.Sprintf("host %s is not one of %s's hosts", u.Hostname(), op.Operator)
	}
	switch c.Status {
	case loglist3.QualifiedLogStatus, loglist3.UsableLogStatus, loglist3.ReadOnlyLogStatus:
	default:
		return config.Log{}, fmt.Sprintf("state is %s", c.Status)
	}
	if c.Start.IsZero() {
		return config.Log{}, "no temporal_interval to name the shard by"
	}
	shard := strconv.Itoa(c.Start.UTC().Year())
	l := config.Log{
		Operator: op.Operator, Shard: shard, Description: c.Description, URL: c.URL,
		LogID: c.LogID, Key: c.Key, MMDSeconds: c.MMDSeconds, TLS: op.TLS, KeySource: source,
	}
	if taken[l.Name()] {
		return config.Log{}, fmt.Sprintf("shard name %s is already taken", l.Name())
	}
	der, err := base64.StdEncoding.DecodeString(c.Key)
	if err != nil || len(der) == 0 {
		return config.Log{}, "no usable key"
	}
	if id := sha256.Sum256(der); base64.StdEncoding.EncodeToString(id[:]) != c.LogID {
		return config.Log{}, "log_id is not sha256(key)"
	}
	if c.MMDSeconds < 0 {
		return config.Log{}, "negative mmd"
	}
	if !strings.HasSuffix(l.URL, "/") {
		return config.Log{}, "url does not end with /"
	}
	return l, ""
}
