package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testdata/logs.json is a frozen copy of the file the mirror repository
// keeps at its root, so this exercises Load against a whole real list:
// every key parses and every log_id is the SHA-256 of its key. The live
// file stays with the data, where Load reads it on every run, so a shard
// added there and not copied here cannot break this test — refresh the
// copy when the shape of the file changes, not on every new shard.
func TestLoadRealLogsJSON(t *testing.T) {
	f, err := Load(filepath.Join("testdata", "logs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Logs) < 14 {
		t.Fatalf("only %d logs", len(f.Logs))
	}
}

func TestMMDFallsBackToTheDefault(t *testing.T) {
	if got := (Log{}).MMD(); got != DefaultMMD {
		t.Fatalf("unstated mmd gave %s, want %s", got, DefaultMMD)
	}
	if got := (Log{MMDSeconds: 3600}).MMD(); got != time.Hour {
		t.Fatalf("mmd 3600 gave %s", got)
	}
}

func TestLoadRejectsNegativeMMD(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs.json")
	os.WriteFile(p, []byte(`{"logs":[{"operator":"a","shard":"1","url":"https://x/","tls":"system","mmd":-1}]}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("negative mmd accepted")
	}
}

func TestLoadRejectsBadLogID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs.json")
	os.WriteFile(p, []byte(`{"logs":[{"operator":"a","shard":"1","url":"https://x/","tls":"system",
	"key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQAIwfEbBkUu1RDSLnlcGoVlMbRc8wQC1yusWLBDR8c3cJIyk0HtI+Uwfga99z4/7Mt8fkSwVTGQkMkiv4UsTw==","log_id":"nope"}]}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("mismatched log_id accepted")
	}
}

// The mirror rewrites logs.json when it adopts or retires a shard, so Save
// must reproduce a file it did not change byte for byte: anything else would
// bury the one line that matters in a reformatting diff.
func TestSaveRoundTripsTheRealFile(t *testing.T) {
	src := filepath.Join("testdata", "logs.json")
	f, err := Load(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Operators) != 3 {
		t.Fatalf("want 3 operators, got %d", len(f.Operators))
	}
	dst := filepath.Join(t.TempDir(), "logs.json")
	if err := f.Save(dst); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(src)
	got, _ := os.ReadFile(dst)
	if string(got) != string(want) {
		t.Fatalf("Save changed the file:\n%s", got)
	}
}

func TestSaveRefusesAnInvalidFile(t *testing.T) {
	f := &File{Logs: []Log{{Operator: "a", Shard: "1", URL: "https://x/", TLS: "bogus"}}}
	if err := f.Save(filepath.Join(t.TempDir(), "logs.json")); err == nil {
		t.Fatal("Save wrote a file Load would reject")
	}
}

func TestLoadValidatesOperators(t *testing.T) {
	for name, body := range map[string]string{
		"no hosts":     `{"operators":{"X":{"operator":"x","tls":"system","hosts":[]}},"logs":[]}`,
		"bad tls":      `{"operators":{"X":{"operator":"x","tls":"nope","hosts":["x.example"]}},"logs":[]}`,
		"unsafe slug":  `{"operators":{"X":{"operator":"x/y","tls":"system","hosts":["x.example"]}},"logs":[]}`,
		"missing slug": `{"operators":{"X":{"tls":"system","hosts":["x.example"]}},"logs":[]}`,
	} {
		p := filepath.Join(t.TempDir(), "logs.json")
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestServesHost(t *testing.T) {
	o := Operator{Hosts: []string{"ct-agate.yandex.net", ".mail.ru"}}
	for host, want := range map[string]bool{
		"ct-agate.yandex.net":   true,
		"CT-Agate.Yandex.net":   true,
		"ctlog2028.mail.ru":     true,
		"mail.ru":               false, // ".mail.ru" names subdomains only
		"evilmail.ru":           false,
		"ct-agate.yandex.net.":  false,
		"x.ct-agate.yandex.net": false,
	} {
		if got := o.ServesHost(host); got != want {
			t.Errorf("%s: got %v, want %v", host, got, want)
		}
	}
}
