package loglist

import (
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"

	"github.com/ru-ct-mirror/ructmirror/internal/config"
)

const sample = `{"version":"1.0","log_list_timestamp":"2026-01-01T00:00:00Z","operators":[{"name":"Yandex","email":["x@y"],"logs":[
{"description":"A","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw==","log_id":"Vh7HRN8a9wLmJoOt38SVz3WjGwxs6KDH6gEDMJC3SIU=","mmd":86400,"url":"https://a.example/1/","state":{"usable":{"timestamp":"2024-11-07T18:00:00Z"}},"temporal_interval":{"start_inclusive":"2026-01-01T00:00:00Z","end_exclusive":"2027-01-01T00:00:00Z"}},
{"description":"B","key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWPA3LO1jJwycQcruCqve2RM0M19HF7V9IFCBsekQTWg3ZB8m9OGEdVFVnNvf6T6kuLN2mRV6kfwlFiaurInyjw==","log_id":"GukWh2bX94qcsIb4xJw8Xc64yZMAqa9L/7CbB0+BLBc=","mmd":86400,"url":"https://a.example/2/","state":{"usable":{"timestamp":"2025-11-25T13:00:00Z"}},"temporal_interval":{"start_inclusive":"2027-01-01T00:00:00Z","end_exclusive":"2028-01-01T00:00:00Z"}}
],"tiled_logs":[]}]}`

func TestCompare(t *testing.T) {
	cfg := &config.File{Logs: []config.Log{{Operator: "a", Shard: "1", URL: "https://a.example/1/",
		Key:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw==",
		LogID: "Vh7HRN8a9wLmJoOt38SVz3WjGwxs6KDH6gEDMJC3SIU="}}}
	d, err := Compare([]byte(sample), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Unknown) != 1 || len(d.Changed) != 0 {
		t.Fatalf("want 1 unknown (B), got %+v", d)
	}
	cfg.Logs[0].Key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWPA3LO1jJwycQcruCqve2RM0M19HF7V9IFCBsekQTWg3ZB8m9OGEdVFVnNvf6T6kuLN2mRV6kfwlFiaurInyjw=="
	d, _ = Compare([]byte(sample), cfg)
	if len(d.Changed) != 1 {
		t.Fatalf("want key change detected, got %+v", d)
	}
}

// An unstated mmd on either side means RFC 6962's own 24 hours, so the two
// files agree until the published value actually moves.
func TestCompareChecksMMD(t *testing.T) {
	cfg := &config.File{Logs: []config.Log{{Operator: "a", Shard: "1", URL: "https://a.example/1/",
		Key:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw==",
		LogID: "Vh7HRN8a9wLmJoOt38SVz3WjGwxs6KDH6gEDMJC3SIU="}}}
	if d, _ := Compare([]byte(sample), cfg); len(d.Retimed) != 0 {
		t.Fatalf("86400 published against an unstated mmd is not drift, got %+v", d.Retimed)
	}
	cfg.Logs[0].MMDSeconds = 86400
	if d, _ := Compare([]byte(sample), cfg); len(d.Retimed) != 0 {
		t.Fatalf("matching mmd reported as drift: %+v", d.Retimed)
	}
	cfg.Logs[0].MMDSeconds = 3600
	d, _ := Compare([]byte(sample), cfg)
	if len(d.Retimed) != 1 || d.Empty() {
		t.Fatalf("want the mmd change detected, got %+v", d)
	}
}

// Two keys whose log_id is their SHA-256, for building candidates.
const (
	keyA = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw=="
	idA  = "Vh7HRN8a9wLmJoOt38SVz3WjGwxs6KDH6gEDMJC3SIU="
	keyB = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWPA3LO1jJwycQcruCqve2RM0M19HF7V9IFCBsekQTWg3ZB8m9OGEdVFVnNvf6T6kuLN2mRV6kfwlFiaurInyjw=="
	idB  = "GukWh2bX94qcsIb4xJw8Xc64yZMAqa9L/7CbB0+BLBc="
)

// adoptCfg knows operator Yandex on a.example and holds shard 1 (log A).
func adoptCfg() *config.File {
	return &config.File{
		Operators: map[string]config.Operator{"Yandex": {Operator: "yandex", TLS: config.TLSSystem, Hosts: []string{"a.example"}}},
		Logs: []config.Log{{Operator: "yandex", Shard: "2026", URL: "https://a.example/1/", Key: keyA, LogID: idA,
			MMDSeconds: 86400, TLS: config.TLSSystem}},
	}
}

func TestAdoptTakesANewShardOfAKnownOperator(t *testing.T) {
	cfg := adoptCfg()
	d, err := Compare([]byte(sample), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Candidates) != 1 || d.Version != "1.0" {
		t.Fatalf("want one candidate from list 1.0, got %+v", d)
	}
	added, rejected := Adopt(d, cfg)
	if len(rejected) != 0 || len(added) != 1 {
		t.Fatalf("added %+v, rejected %v", added, rejected)
	}
	l := added[0]
	if l.Name() != "yandex/2027" || l.URL != "https://a.example/2/" || l.Key != keyB || l.LogID != idB ||
		l.MMDSeconds != 86400 || l.TLS != config.TLSSystem || l.Description != "B" {
		t.Fatalf("adopted entry is wrong: %+v", l)
	}
	if l.KeySource != "browser-resources.s3.yandex.net/ctlog/ctlog.json v1.0 (2026-01-01)" {
		t.Fatalf("key_source %q", l.KeySource)
	}
}

func TestAdoptRejects(t *testing.T) {
	base := Candidate{Operator: "Yandex", Description: "B", URL: "https://a.example/2/", Key: keyB, LogID: idB,
		MMDSeconds: 86400, Start: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), Status: loglist3.UsableLogStatus, Line: "B"}
	for name, mut := range map[string]func(*Candidate){
		"unknown operator":   func(c *Candidate) { c.Operator = "Someone Else" },
		"foreign host":       func(c *Candidate) { c.URL = "https://b.example/2/" },
		"plain http":         func(c *Candidate) { c.URL = "http://a.example/2/" },
		"no interval":        func(c *Candidate) { c.Start = time.Time{} },
		"retired":            func(c *Candidate) { c.Status = loglist3.RetiredLogStatus },
		"pending":            func(c *Candidate) { c.Status = loglist3.PendingLogStatus },
		"no state":           func(c *Candidate) { c.Status = loglist3.UndefinedLogStatus },
		"name taken":         func(c *Candidate) { c.Start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		"log_id not its key": func(c *Candidate) { c.LogID = idA },
		"no key":             func(c *Candidate) { c.Key = "" },
	} {
		c := base
		mut(&c)
		added, rejected := Adopt(Diff{Candidates: []Candidate{c}}, adoptCfg())
		if len(added) != 0 || len(rejected) != 1 {
			t.Errorf("%s: added %+v, rejected %v", name, added, rejected)
		}
	}
	// The unmodified candidate is the control: it must pass.
	if added, rejected := Adopt(Diff{Candidates: []Candidate{base}}, adoptCfg()); len(added) != 1 {
		t.Fatalf("control rejected: %v", rejected)
	}
}

// Two candidates that would get the same name: the first wins, the second
// is left for a maintainer rather than overwriting it.
func TestAdoptDoesNotAdoptTheSameNameTwice(t *testing.T) {
	c := Candidate{Operator: "Yandex", URL: "https://a.example/2/", Key: keyB, LogID: idB,
		Start: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), Status: loglist3.UsableLogStatus}
	c2 := c
	c2.URL = "https://a.example/3/"
	added, rejected := Adopt(Diff{Candidates: []Candidate{c, c2}}, adoptCfg())
	if len(added) != 1 || len(rejected) != 1 || added[0].URL != c.URL {
		t.Fatalf("added %+v, rejected %v", added, rejected)
	}
}

func TestCompareReportsDroppedShards(t *testing.T) {
	cfg := adoptCfg()
	cfg.Logs = append(cfg.Logs,
		config.Log{Operator: "yandex", Shard: "2025", URL: "https://a.example/0/", TLS: config.TLSSystem},
		config.Log{Operator: "yandex", Shard: "2024", URL: "https://a.example/-1/", TLS: config.TLSSystem, Disabled: true})
	d, err := Compare([]byte(sample), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Dropped) != 1 || d.Dropped[0] != "yandex/2025" {
		t.Fatalf("want only the enabled unlisted shard dropped, got %v", d.Dropped)
	}
	if len(d.Unknown) != 1 || d.Empty() {
		t.Fatalf("a dropped shard must not hide the unknown one: %+v", d)
	}
}
