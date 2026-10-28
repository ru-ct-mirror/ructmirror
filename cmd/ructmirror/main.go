// Command ructmirror mirrors and verifies the Russian national CT logs.
//
//	ructmirror sync    [-root DIR] [-only operator/shard] [-batch N]
//	ructmirror verify  [-root DIR] [-only operator/shard]
//	ructmirror domains [-root DIR] [-only operator/shard] [-active]
//	ructmirror summary [-root DIR] CHUNK...
//
// DIR is the repository root: it must contain logs.json, roots/ and data/.
//
// summary prints, on stdout, the commit message for a run that added CHUNK...
// to the mirror: the entries and names those chunks carry, with the names the
// mirror had never seen before marked. Flags must come before CHUNK..., since
// flag parsing stops at the first argument that is not a flag.
//
// Exit status: 0 when everything verified, 2 when a log or the log list
// failed verification (evidence was written), 1 for any other error such as
// an unreachable log.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ru-ct-mirror/ructmirror/internal/config"
	"github.com/ru-ct-mirror/ructmirror/internal/ctclient"
	"github.com/ru-ct-mirror/ructmirror/internal/loglist"
	"github.com/ru-ct-mirror/ructmirror/internal/mirror"
	"github.com/ru-ct-mirror/ructmirror/internal/store"
)

const (
	// firstSeenTimeout bounds the scan of the rest of the mirror that decides
	// which names are new. The scan grows with the mirror; when it no longer
	// fits, the summary drops the markers rather than the commit.
	firstSeenTimeout = 2 * time.Minute
	// maxSummaryNames is how many names one commit message lists.
	maxSummaryNames = 100
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	root := fs.String("root", ".", "repository root (contains logs.json, roots/, data/)")
	only := fs.String("only", "", "limit to one log, as operator/shard")
	batch := fs.Uint64("batch", 256, "entries per get-entries request")
	active := fs.Bool("active", false, "domains: only names with a certificate that has not expired")
	fs.Parse(os.Args[2:])

	cfg, err := config.Load(filepath.Join(*root, "logs.json"))
	fatal(err)
	logs := cfg.Logs
	if *only != "" {
		logs = nil
		for _, l := range cfg.Logs {
			if l.Name() == *only {
				logs = append(logs, l)
			}
		}
		if len(logs) == 0 {
			fatal(fmt.Errorf("no log named %q in logs.json", *only))
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var failures, alerts int
	// failed names what each operational error was about, so the last line
	// of a run says which shards it is blind to without reading the log.
	var failed []string
	switch os.Args[1] {
	case "sync":
		cl, err := ctclient.New(filepath.Join(*root, "roots"))
		fatal(err)
		cl.Log = os.Stderr
		// dropped holds, for each shard ctlog.json no longer lists and that
		// was not retired, how many of its certificates are still valid.
		var dropped map[string]uint64
		if *only == "" {
			var drift bool
			dropped, drift, err = snapshotLogList(ctx, cl, cfg, *root, time.Now())
			// The list may have added or retired shards; sync what it holds now.
			logs = cfg.Logs
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				// Drift comes back as the error too; count it once, as an alert.
				if !drift {
					failures++
					failed = append(failed, "log list")
				}
			}
			if drift {
				alerts++
			}
		}
		for _, l := range logs {
			if l.Disabled {
				continue
			}
			st, err := store.Open(filepath.Join(*root, "data", l.Operator, l.Shard))
			fatal(err)
			res, err := mirror.Sync(ctx, cl, l, st, mirror.Options{Batch: *batch, Log: os.Stderr})
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				var a *mirror.Alert
				if errors.As(err, &a) {
					alerts++
				} else {
					failures++
					failed = append(failed, l.Name())
					if valid, ok := dropped[l.Name()]; ok && hostNotFound(err) {
						fmt.Fprintf(os.Stderr, "%s: host does not resolve and ctlog.json no longer lists this shard; "+
							"%d of its certificates are still valid, so it is not retired automatically. "+
							"Check the log by hand and mark it \"disabled\" in logs.json if it is gone (docs/OPERATIONS.md)\n",
							l.Name(), valid)
					}
				}
				continue
			}
			fmt.Fprintf(os.Stderr, "%s: ok, size %d -> %d, %d chunk(s), new STH: %v\n", l.Name(), res.OldSize, res.NewSize, res.ChunksWritten, res.NewSTH)
		}
	case "verify":
		for _, l := range logs {
			dir := filepath.Join(*root, "data", l.Operator, l.Shard)
			if _, err := os.Stat(dir); l.Disabled && os.IsNotExist(err) {
				continue
			}
			st, err := store.Open(dir)
			fatal(err)
			if err := mirror.Verify(l, st); err != nil {
				fmt.Fprintln(os.Stderr, "FAIL", err)
				alerts++
				continue
			}
			state, _, _ := st.LoadState()
			fmt.Fprintf(os.Stderr, "%s: ok, %d entries, root %s\n", l.Name(), state.TreeSize, state.RootHash)
		}
	case "domains":
		acc := map[string]*mirror.DomainStat{}
		for _, l := range logs {
			dir := filepath.Join(*root, "data", l.Operator, l.Shard)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				continue
			}
			st, err := store.Open(dir)
			fatal(err)
			if _, err := mirror.Domains(st, acc); err != nil {
				fatal(fmt.Errorf("%s: %w", l.Name(), err))
			}
		}
		now := time.Now()
		fmt.Println("domain\tcerts\tprecerts\tfirst_seen\tlatest_not_after\tissuers")
		for _, d := range mirror.SortedDomains(acc) {
			if *active && d.NotAfter.Before(now) {
				continue
			}
			var iss []string
			for name, n := range d.Issuers {
				iss = append(iss, fmt.Sprintf("%s(%d)", name, n))
			}
			sort.Strings(iss)
			fmt.Printf("%s\t%d\t%d\t%s\t%s\t%s\n", d.Domain, d.Certs, d.Precerts,
				d.FirstSeen.Format("2006-01-02"), d.NotAfter.UTC().Format("2006-01-02"), strings.Join(iss, ","))
		}
	case "summary":
		// -only filters logs before this switch, and a narrowed scan would call
		// every name new. The scan reads data/ directly, so refuse the flag
		// rather than let it look as though it scoped anything.
		if *only != "" {
			fatal(errors.New("summary: -only would not narrow the first-seen scan; drop it"))
		}
		var refs []mirror.ChunkRef
		for _, p := range fs.Args() {
			ref, err := mirror.ChunkRefFromPath(*root, p)
			fatal(err)
			refs = append(refs, ref)
		}
		s, err := mirror.Summarise(refs)
		fatal(err)
		scan, cancel := context.WithTimeout(ctx, firstSeenTimeout)
		done, err := mirror.MarkFirstSeen(scan, s, *root, refs, 0)
		cancel()
		fatal(err)
		s.Marked = done
		if !done {
			fmt.Fprintf(os.Stderr, "first-seen scan did not finish within %s; markers omitted\n", firstSeenTimeout)
		}
		// Render whole, then write once: a message that is half written and
		// then fails is worse than no message at all.
		var msg bytes.Buffer
		fatal(s.Render(&msg, time.Now(), maxSummaryNames))
		_, err = os.Stdout.Write(msg.Bytes())
		fatal(err)
	default:
		usage()
	}
	switch {
	case alerts > 0:
		fmt.Fprintf(os.Stderr, "%d verification failure(s), %d other error(s)", alerts, failures)
		if len(failed) > 0 {
			fmt.Fprintf(os.Stderr, ": %s", strings.Join(failed, ", "))
		}
		fmt.Fprintln(os.Stderr)
		os.Exit(2)
	case failures > 0:
		fmt.Fprintf(os.Stderr, "%d error(s): %s\n", failures, strings.Join(failed, ", "))
		os.Exit(1)
	}
}

// snapshotLogList downloads ctlog.json into loglist/ and reports drift from
// logs.json. drift is true when the published list disagrees with logs.json,
// which is a verification failure rather than an operational error.
//
// When the list holds nothing suspicious about the logs we already know, it
// also brings logs.json up to date and saves it: a new shard of a known
// operator is adopted (see loglist.Adopt), and a shard the list has dropped
// is retired once every certificate it holds has expired. cfg is updated in
// place. dropped maps each dropped shard that stays enabled to the number of
// its certificates still valid at now.
func snapshotLogList(ctx context.Context, cl *ctclient.Client, cfg *config.File, root string, now time.Time) (dropped map[string]uint64, drift bool, err error) {
	if cfg.LogListURL == "" {
		return nil, false, nil
	}
	// Room for the client's whole backoff window, about two minutes.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	b, err := cl.GetJSON(ctx, cfg.LogListURL)
	if err != nil {
		return nil, false, fmt.Errorf("log list: %w", err)
	}
	dir := filepath.Join(root, "loglist")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ctlog.json"), b, 0o644); err != nil {
		return nil, false, err
	}
	d, err := loglist.Compare(b, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("log list: %w", err)
	}

	// A list that changed a key or an MMD we hold is itself under suspicion;
	// it decides nothing about which shards to watch until a maintainer has
	// looked at it.
	trusted := len(d.Changed) == 0 && len(d.Retimed) == 0
	rejected := d.Unknown
	changed := false
	// Work on a copy: cfg changes only once logs.json holds the change, so a
	// run never syncs a shard the file it commits does not name.
	next := *cfg
	next.Logs = append([]config.Log(nil), cfg.Logs...)
	// A shard that cannot be judged stays as it is; it must not cost the
	// other shards their adoption or retirement.
	var judged []error
	if trusted {
		var added []config.Log
		added, rejected = loglist.Adopt(d, cfg)
		for _, l := range added {
			next.Logs = append(next.Logs, l)
			changed = true
			fmt.Fprintf(os.Stderr, "log list: adopted %s (%s) from ctlog.json v%s (%s)\n",
				l.Name(), l.URL, d.Version, d.Published.UTC().Format("2006-01-02"))
		}
		dropped = map[string]uint64{}
		if len(d.MissingOperators) > 0 {
			fmt.Fprintf(os.Stderr, "log list: ctlog.json carries no logs at all for %s; retiring nothing this run\n",
				strings.Join(d.MissingOperators, ", "))
		}
		for _, name := range d.Dropped {
			if len(d.MissingOperators) > 0 {
				dropped[name] = 0
				continue
			}
			retired, valid, err := retireIfExpired(&next, name, root, d, now)
			if err != nil {
				judged = append(judged, fmt.Errorf("log list: cannot tell whether %s is finished: %w", name, err))
				continue
			}
			if retired {
				changed = true
				continue
			}
			dropped[name] = valid
		}
	}
	if changed {
		if err := next.Save(filepath.Join(root, "logs.json")); err != nil {
			return nil, false, fmt.Errorf("log list: %w", err)
		}
		*cfg = next
	}

	if len(rejected) == 0 && len(d.Changed) == 0 && len(d.Retimed) == 0 {
		if len(judged) > 0 {
			return dropped, false, errors.Join(judged...)
		}
		fmt.Fprintln(os.Stderr, "log list: ctlog.json agrees with logs.json")
		return dropped, false, nil
	}
	for _, err := range judged {
		fmt.Fprintln(os.Stderr, err)
	}
	var errs []error
	for _, u := range rejected {
		errs = append(errs, fmt.Errorf("ALERT log list: log not in logs.json: %s", u))
	}
	for _, c := range d.Changed {
		errs = append(errs, fmt.Errorf("ALERT log list: key changed: %s", c))
	}
	for _, r := range d.Retimed {
		errs = append(errs, fmt.Errorf("ALERT log list: mmd changed: %s", r))
	}
	return dropped, true, errors.Join(errs...)
}

// retireIfExpired marks the named shard disabled in cfg when the mirror holds
// a verified tree for it and every certificate in that tree has expired. It
// reports whether it did, and otherwise how many certificates are still valid.
// A shard that was never synced is left alone: there is nothing to keep, and
// nothing to say it is finished.
func retireIfExpired(cfg *config.File, name, root string, d loglist.Diff, now time.Time) (retired bool, valid uint64, err error) {
	i := -1
	for j, l := range cfg.Logs {
		if l.Name() == name {
			i = j
		}
	}
	if i < 0 {
		return false, 0, errors.New("not in logs.json")
	}
	l := cfg.Logs[i]
	dir := filepath.Join(root, "data", l.Operator, l.Shard)
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		if os.IsNotExist(err) {
			return false, 0, nil
		}
		return false, 0, err
	}
	st, err := store.Open(dir)
	if err != nil {
		return false, 0, err
	}
	// Once disabled, the shard is never fetched again, so its stored tree
	// must be the one the log signed before the mirror stops looking.
	if err := mirror.Verify(l, st); err != nil {
		return false, 0, fmt.Errorf("stored tree does not verify: %w", err)
	}
	state, _, err := st.LoadState()
	if err != nil {
		return false, 0, err
	}
	ex, err := mirror.Expiry(st, now)
	if err != nil {
		return false, 0, err
	}
	if ex.Entries != state.TreeSize {
		return false, 0, fmt.Errorf("%d entries on disk, state.json says %d", ex.Entries, state.TreeSize)
	}
	if !ex.AllExpired() {
		return false, ex.Valid, nil
	}
	l.Disabled = true
	l.Note = fmt.Sprintf("Retired automatically on %s: no longer in ctlog.json (v%s, %s) and all %d certificates expired by %s. Final tree: %d entries, STH of %s.",
		now.UTC().Format("2006-01-02"), d.Version, d.Published.UTC().Format("2006-01-02"),
		ex.Entries, ex.NotAfter.UTC().Format("2006-01-02"),
		state.TreeSize, time.UnixMilli(int64(state.STHTimestamp)).UTC().Format("2006-01-02"))
	cfg.Logs[i] = l
	fmt.Fprintf(os.Stderr, "log list: retired %s: %s\n", name, l.Note)
	return true, 0, nil
}

// hostNotFound reports whether err comes down to the log's host name not
// resolving at all, as opposed to a host that answered badly or not in time.
func hostNotFound(err error) bool {
	var dns *net.DNSError
	return errors.As(err, &dns) && dns.IsNotFound
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ructmirror sync|verify|domains|summary [-root DIR] [-only operator/shard] [-batch N] [-active] [CHUNK...]")
	os.Exit(2)
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
