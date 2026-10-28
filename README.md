# ructmirror

The tool that mirrors and verifies the Certificate Transparency logs Yandex
Browser trusts for certificates from the Russian national CA. The mirror
itself — the entries, the observed Signed Tree Heads, the schedule that runs
this code and the explanation of why any of it exists — lives in
<https://github.com/ru-ct-mirror/ru-ct-mirror>, which pins this repository as
a submodule at the exact commit that produced each commit of data.

```
ructmirror sync    [-root DIR] [-only operator/shard] [-batch N]
ructmirror verify  [-root DIR] [-only operator/shard]
ructmirror domains [-root DIR] [-only operator/shard] [-active]
ructmirror summary [-root DIR] CHUNK...
```

`-root` is the mirror repository, not this one: it must hold `logs.json`, the
pinned TLS anchors in `roots/` and the mirror in `data/<operator>/<shard>/`.
It defaults to the working directory, so the usual way to run this code is to
build it into the root of the mirror and run it from there:

```
go build -C code -o ../ructmirror ./cmd/ructmirror
./ructmirror verify
```

`summary` takes chunk paths relative to the working directory rather than to
`-root`, which is the other reason to run the binary from the mirror root.

`verify` needs no network: it re-hashes every stored entry, checks the root
against `state.json` and the last STH, and checks that STH's signature.
`sync` is the only subcommand that talks to the logs. It is also the only one
that writes `logs.json`: when Yandex's `ctlog.json` lists a new shard of an
operator named under `operators` in `logs.json`, on one of that operator's
hosts, `sync` adopts it and mirrors it in the same run; when the list drops a
shard and every certificate the mirror holds for it has expired, `sync` marks
it `disabled` with a note. Each such change prints a `log list: adopted` or
`log list: retired` line. A list that changes a known key or MMD changes
nothing in `logs.json` and is reported as a verification failure, as is a new
log that does not meet those conditions. With `-only` the list is not read.
Exit status is 0 when
everything verified, 2 when a log or the log list failed verification and
evidence was written, and 1 for any other error.

Tests are self-contained (`go test ./...`); `internal/*/testdata` holds frozen
copies of the mirror's `logs.json` and pinned roots so the suite does not
reach for the data repository.

## License

Apache-2.0.
