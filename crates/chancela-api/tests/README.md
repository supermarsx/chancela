# API integration-test suites

`chancela-api` uses explicit domain suites instead of Cargo's default
one-executable-per-file integration-test discovery. This keeps the API's large
dependency graph from being linked into dozens of near-identical binaries.

Run every API test suite:

```console
cargo test -p chancela-api
```

Compile a suite without running it:

```console
cargo test -p chancela-api --test api-records --no-run
```

Run one domain suite:

```console
cargo test -p chancela-api --test api-signatures
```

Run one original module or one test by passing a harness filter after `--`:

```console
cargo test -p chancela-api --test api-records -- paper_import
cargo test -p chancela-api --test api-records -- paper_import::ocr_draft
```

The explicit suite targets are:

- `api-auth`
- `api-records`
- `api-archive-privacy`
- `api-signatures`
- `cmd_signing`
- `local_pkcs12_signing`
- `cmd_csc_failover`
- `remote_signing`
- `connector_allowlist`
- `data_key_ops`
- `scap`
- `seed_dataset`
- `termo_pkcs12_signing`

Every environment-mutating module remains in its own process. Module-local
mutexes cannot serialize process-global environment changes across modules in a
shared Rust test harness. The PostgreSQL seed target and the Termo PKCS#12
target also stay independent so their feature/environment assumptions and
focused workflows remain intact.
