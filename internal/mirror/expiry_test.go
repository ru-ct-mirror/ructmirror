package mirror

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ru-ct-mirror/ructmirror/internal/store"
)

func TestExpiry(t *testing.T) {
	ca := newTestCA(t)
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	old := time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)
	older := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	open := func(root, log string) *store.Store {
		st, err := store.Open(filepath.Join(root, "data", log))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	root := t.TempDir()
	writeTestChunk(t, root, "x/expired", 0, [][]byte{
		ca.precertLeaf(t, "a.example.ru", nil, older),
		ca.leaf(t, "b.example.ru", nil, old),
	})
	s, err := Expiry(open(root, "x/expired"), now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.AllExpired() || s.Entries != 2 || s.Valid != 0 || !s.NotAfter.Equal(old) {
		t.Fatalf("expired shard: %+v", s)
	}

	// One certificate past now is enough to keep a shard: the year in its
	// name does not bound what it holds.
	writeTestChunk(t, root, "x/live", 0, [][]byte{
		ca.precertLeaf(t, "a.example.ru", nil, old),
		ca.precertLeaf(t, "c.example.ru", nil, now.Add(24*time.Hour)),
	})
	s, err = Expiry(open(root, "x/live"), now)
	if err != nil {
		t.Fatal(err)
	}
	if s.AllExpired() || s.Valid != 1 {
		t.Fatalf("shard with a valid certificate: %+v", s)
	}

	// An empty shard has nothing to say it is finished.
	s, err = Expiry(open(root, "x/empty"), now)
	if err != nil {
		t.Fatal(err)
	}
	if s.AllExpired() {
		t.Fatalf("empty shard counted as expired: %+v", s)
	}
}

// An entry whose certificate does not parse has no expiry to read; a shard
// holding one is never called expired.
func TestExpiryUnparsedEntryBlocksRetirement(t *testing.T) {
	if (ExpiryStat{Entries: 2, Parsed: 1, Valid: 0}).AllExpired() {
		t.Fatal("unparsed entry ignored")
	}
}
