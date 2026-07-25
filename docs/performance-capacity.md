# Performance and capacity evidence

Chancela's performance harness creates reproducible measurements; it does not
turn an unmeasured deployment into a capacity claim. Every report carries the
dataset counts and SHA-256 digests, per-operation latency/error measurements,
resource samples, topology inputs, and an explicit SLO assessment.

## Evidence profiles

| Profile | Users | Entities | Books | Signature-shaped subjects | Workload |
| --- | ---: | ---: | ---: | ---: | --- |
| `pr-smoke` | 4 | 8 | 16 | 6 | 8 seconds, 2 steady clients |
| `capacity` | **15,000** | **10,000** | **50,000** | **10,000** | 30-minute ramp, 64 clients |
| `soak` | **15,000** | **10,000** | **50,000** | **10,000** | 3-hour steady soak, 64 clients |

The PR smoke is a harness regression check. It is never labelled or reported as
the full capacity result. Scheduled and manual jobs generate the exact full
dataset from scratch and upload their reports even when the run fails or remains
incomplete.

### Signature boundary

The base exact-volume fixture's `signatures` rows are **unsigned act subjects**.
The seeder creates a real open book and draft act for each row, then the mixed
workload exercises `GET /v1/acts/{id}/signature`. This measures the application's
signature-status data shape at 10,000 subjects. It creates **zero cryptographic
signatures** and does not measure CMD, CSC/QTSP, smart-card, timestamp,
revocation, trust-list, or external-validator capacity. The manifest and report
state that boundary and record `cryptographic_signatures_created: 0`.

An explicit, manual-only local PKCS#12 mode is available for real cryptographic
PDF signing with a disposable software certificate. It prepares selected acts
through `Signing`, posts to the real local-PKCS#12 route, and separately reports
sign-operation p50/p95/p99, errors, throughput, and exact completion. This is
advanced local technical evidence only, not remote-provider or qualified-signing
evidence.

## Generate and verify the exact fixtures

Generation is streaming and deterministic: the timestamp in `manifest.json`
changes, but every JSONL digest is stable for the profile.

```sh
python scripts/perf/harness.py generate \
  --profile scripts/perf/profiles/capacity.json \
  --output-dir .perf-work/capacity/dataset

python scripts/perf/harness.py validate \
  --dataset-dir .perf-work/capacity/dataset
```

`manifest.json` records each file's exact line count, byte count, and SHA-256.
Validation re-parses every line, checks contiguous ordinals, recomputes digests,
and fails on a missing, added, reordered, or changed record.

## Run against the production-like test topology

The wrapper reuses the existing Postgres/Redis/three-node HA Compose services and
adds a leader-aware test gateway. Writes go to the node whose `/health` reports
`leader`; reads round-robin across healthy nodes. This gateway is test
infrastructure, not a production load balancer.

```sh
bash scripts/perf/run-compose.sh capacity .perf-work/capacity
```

The topology is intentionally explicit:

- three application replicas, one elected writer, and read followers;
- one TLS-enabled PostgreSQL service and Redis for cluster-shared auth state;
- an HTTP gateway on `127.0.0.1:18081`;
- a fresh volume on every normal run;
- configurable test-edge throttling via
  `CHANCELA_PERF_RATE_LIMIT_PER_SECOND` and
  `CHANCELA_PERF_RATE_LIMIT_BURST`.

The wrapper defaults those test-edge limits to 1,000 requests/s and burst 2,000
so exact-volume seeding is not principally a test of the default 50 requests/s
edge throttle. Those values are test inputs, not capacity thresholds. A separate
rate-limit profile is required to characterize throttle behavior.

Set `CHANCELA_PERF_KEEP=1` to retain containers/volumes after a run for
inspection. Otherwise the wrapper always captures Compose logs and tears down.

## Workload modes

Profiles must choose one explicit mode:

- `steady`: all configured clients remain active;
- `ramp`: active clients increase from one to the configured maximum;
- `spike`: quarter-load baseline with full concurrency during the middle 20%;
- `soak`: steady concurrency with a deliberately long duration.

The mixed workload includes health, entity/book/user lists, entity and book
reads, real authentication, entity writes, and signature-status reads. Each
operation reports request count, status distribution, error rate, p50, p95, p99,
maximum latency, and whether latency percentiles are exact or based on a bounded
reservoir. The overall report includes throughput and a one-second active-client
trace. Docker sampling records per-container maximum/average CPU and maximum
memory when Docker exposes those metrics.

## Optional real local cryptographic workload

This mode is never activated by a profile alone. Generate a disposable identity
and pass an explicit config:

```sh
export CHANCELA_PERF_PKCS12_PASSPHRASE='temporary-test-only-secret'
mkdir -p .perf-work
sh scripts/perf/generate-test-pkcs12.sh \
  .perf-work/test-signing-identity.p12

bash scripts/perf/run-compose.sh \
  capacity .perf-work/capacity "" \
  scripts/perf/cryptographic.example.json
```

The example requests 10,000 local software-certificate signatures. Lower
`count` for calibration. The PFX and passphrase are transient test inputs and
must never be committed or reused for real records.

For real provider evidence, provide an authority-approved non-production
CMD/CSC/QTSP tenant, provider credentials, test identities, OTP/SAD ceremony
automation allowed by that provider, network/TLS path, and reviewed rate/quota
limits. No deterministic repo-local mock can prove that external capacity.

## SLO evaluation

Thresholds are deliberately null by default. Running without `--slo`, or with a
file containing only nulls, yields:

```text
assessment: not_configured
```

That is not a pass. Copy `scripts/perf/slo.example.json`, replace only reviewed
thresholds, and pass it as the third wrapper argument:

```sh
bash scripts/perf/run-compose.sh \
  capacity .perf-work/capacity path/to/reviewed-slo.json
```

Supported checks are overall maximum error rate, minimum throughput,
per-operation p95/p99/error rate, and maximum observed container CPU/memory. A
configured failure makes the harness exit non-zero. Dataset exactness is a
separate mandatory gate.

## Reports and operational interpretation

Each run writes:

- `dataset/manifest.json` and four JSONL fixtures;
- `report/runtime-index.json` with observed server IDs;
- `report/report.json`, the machine-readable source of truth;
- `report/report.md`, a compact human summary;
- `logs/generate.json`, `validate.json`, gateway health, harness log, and all
  Compose logs.

Do not call a run capacity proof unless all of the following are true:

1. the exact seed says `exact: true`;
2. the intended workload mode and duration completed;
3. resource sampling was available or an equivalent external source is linked;
4. reviewed, non-null thresholds were supplied;
5. `slo.assessment` is `passed`;
6. the claim stays within the tested topology and signing-provider boundary.

An interrupted seed, unavailable dependency, `not_configured` SLO, failed
threshold, or unsigned signature-status run is useful evidence, but not proof of
the requested production capacity.
