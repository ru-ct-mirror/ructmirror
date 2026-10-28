package mirror

import (
	"fmt"
	"time"

	"github.com/ru-ct-mirror/ructmirror/internal/store"
)

// ExpiryStat says how much of a shard still certifies anything.
type ExpiryStat struct {
	Entries  uint64    // entries read
	Parsed   uint64    // entries whose certificate could be parsed
	Valid    uint64    // parsed certificates whose NotAfter is after now
	NotAfter time.Time // latest NotAfter seen
}

// AllExpired reports whether the shard holds certificates and every one of
// them has expired. An entry whose certificate cannot be parsed has no
// expiry to read, so a shard with any such entry never counts as expired:
// retiring it would be a guess.
func (s ExpiryStat) AllExpired() bool {
	return s.Entries > 0 && s.Parsed == s.Entries && s.Valid == 0
}

// Expiry reads every stored entry of st and counts the certificates that are
// still valid at now. It is read from the entries, not from the shard's
// name: a yearly shard is not guaranteed to hold only that year's expiries.
func Expiry(st *store.Store, now time.Time) (ExpiryStat, error) {
	var s ExpiryStat
	_, err := st.ForEachEntry(func(e store.Entry) error {
		s.Entries++
		info, ok, err := ParseLeaf(e)
		if err != nil {
			return fmt.Errorf("entry %d: %w", e.Index, err)
		}
		if !ok {
			return nil
		}
		s.Parsed++
		if info.NotAfter.After(now) {
			s.Valid++
		}
		if info.NotAfter.After(s.NotAfter) {
			s.NotAfter = info.NotAfter
		}
		return nil
	})
	return s, err
}
