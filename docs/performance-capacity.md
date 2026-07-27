# Performance and capacity evidence

Chancela's performance harness creates reproducible measurements; it does not
turn an unmeasured deployment into a capacity claim. Every report carries the
dataset counts and SHA-256 digests, per-operation latency/error measurements,
resource samples, topology inputs, and an explicit SLO assessment.

## Evidence profiles

| Profile | Proof eligible | Users | Entities | Books | Signature-shaped subjects | Workload |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `pr-smoke` | **No** | 4 | 8 | 16 | 6 | 8 seconds, including a 5-second peak plateau at 2 clients |
| `capacity` | Yes | **15,000** | **10,000** | **50,000** | **10,000** | 1m warm-up, 10m ramp, **18m peak plateau at 64 clients**, 1m cool-down |
| `soak` | Yes | **15,000** | **10,000** | **50,000** | **10,000** | 1m warm-up, 4m ramp, **174m peak plateau at 64 clients**, 1m cool-down |

The PR smoke is a harness regression check. It is never labelled or reported as
the full capacity result, even if it is run with a complete policy whose checks
pass. Every profile must declare `proof_eligible`; the harness additionally
hard-codes `pr-smoke` as evidence-only. Profile eligibility is necessary, but
does not replace any other proof prerequisite. Scheduled and manual jobs
generate the exact full dataset from scratch and upload their reports even when
the run fails or remains incomplete.

### Setup pacing boundary

Dataset seeding is setup, not the measured mixed workload. The `capacity`
profile caps setup at 12 concurrent requests to leave CPU headroom on the
elected leader, which receives every write. A local calibration run at commit
`05f44435bbc90339ba4e6ae8460e5fa9dd33fd5a` used 16 concurrent seed requests
and reached 194.17% leader CPU during user creation, above the reviewed 190%
ceiling, so it was stopped before the workload and is negative evidence rather
than capacity proof.

This setup pacing does not claim support for 16 concurrent product writers and
does not relax the proof. The exact dataset volumes, 64-client workload,
1,800-second duration, 1,080-second peak plateau, topology, resource sampler,
resource ceilings, and all other SLO thresholds remain unchanged. Resource
sampling and SLO enforcement still cover setup through mixed-workload
completion; final topology and cleanup are evidenced separately. Only a
complete fresh exact-source run can establish the capacity result.

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

Dispatch the exact final `main` revision with an explicit reviewed policy and
topology inputs:

```sh
gh workflow run performance.yml --ref main \
  -f profile=capacity \
  -f cryptographic_signatures=10000 \
  -f app_replicas=3 \
  -f app_cpus=2.0 \
  -f app_memory=1g \
  -f search_readiness_timeout_seconds=900 \
  -f keep_failed_topology=false
```

Manual `capacity` and `soak` dispatches and the weekly schedule always select
the committed `scripts/perf/slo.capacity.json` policy. The workflow exposes no
arbitrary SLO-path input: changing the policy used for proof requires a reviewed
repository change. The `pr-smoke` profile always receives a blank policy path
and can never inherit the capacity policy.

The exact-volume job targets a self-hosted runner carrying every one of these
labels: `self-hosted`, `linux`, `x64`, `chancela-capacity`, and `cpu-12-plus`.
Operators must apply the capacity labels only to a Linux x64 runner with a
working Docker/Compose installation, at least 12 host CPUs, at least 6 GiB RAM,
and enough free disk for fresh images, volumes, fixtures, logs, and artifacts.
Without that explicitly provisioned runner, capacity and soak jobs remain
queued; they do not fall back to a smaller GitHub-hosted machine. The separate
harness self-test remains on `ubuntu-latest` and is never capacity proof.

GitHub Actions evidence is proof eligible only when the report records
`source.ref: refs/heads/main` and a valid 40-hex `source.commit_sha`. Runs
dispatched from another branch or without a valid commit identity still produce
useful reports, but the harness adds a proof blocker. Local final-source runs
remain possible from a clean branch or detached commit: their report records
the local Git commit, branch or detached ref, working-tree dirty state, and
status-entry count. A missing or malformed commit, dirty tree, or unknown tree
state is disclosed and blocks local proof.

The repository contains both `slo.example.json`, whose null thresholds remain
`not_configured`, and the reviewed `slo.capacity.json` policy described below.

The topology is intentionally explicit:

- three application replicas, one elected writer, and read followers;
- one unscaled, socketless search projector, isolated from request-serving CPU;
- one TLS-enabled PostgreSQL service and Redis for cluster-shared auth state;
- an HTTP gateway on `127.0.0.1:18081`;
- a fresh volume on every normal run;
- a strict preflight that refuses missing replicas, unhealthy/restarted/OOM-killed
  containers, or any app/projector/database/cache/gateway service without
  positive CPU and memory limits;
- standalone API/SQLite-projector services may remain declared but inactive in
  rendered Compose output; the preflight captures them and fails only if one is
  actually running alongside the cluster topology;
- an aggregate-envelope gate: per-service limits multiplied by replica count
  must fit the captured Docker host CPU and RAM. Missing host facts or
  overcommit blocks proof; syntactically present Compose limits are not enough;
- a default limit of 2 CPUs and 1 GiB per application replica, overridable only
  as a recorded test input with `CHANCELA_PERF_APP_CPUS` and
  `CHANCELA_PERF_APP_MEMORY`;
- a default projector ceiling of 1.5 CPUs and 1 GiB, overridable as a recorded
  test input with `CHANCELA_PERF_SEARCH_PROJECTOR_CPUS` and
  `CHANCELA_PERF_SEARCH_PROJECTOR_MEMORY`;
- configurable test-edge throttling via
  `CHANCELA_PERF_RATE_LIMIT_PER_SECOND` and
  `CHANCELA_PERF_RATE_LIMIT_BURST`.

With three default application replicas, the required services request an
aggregate **11.5 CPUs** and **5,972,688,896 bytes (5.5625 GiB)** of memory.
Compose `g`/`m` RAM suffixes use binary multipliers here (`1g` is 1 GiB and
`320m` is 320 MiB). Use a Docker host with at least **12 CPUs and 6 GiB RAM**
for the default topology; that leaves 0.5 CPU and 448 MiB of aggregate-envelope
headroom, while larger hosts remain appropriate for runner overhead and
resource-sampling headroom. The workflow's `cpu-12-plus` label is an operator
assertion of this minimum; the topology preflight still measures and enforces
the live host envelope.

The wrapper defaults those test-edge limits to 1,000 requests/s and burst 2,000
so exact-volume seeding is not principally a test of the default 50 requests/s
edge throttle. Those values are test inputs, not capacity thresholds. A separate
rate-limit profile is required to characterize throttle behavior.

The preflight artifact contains the rendered Compose configuration and its
SHA-256, expected/observed replica counts, service limits, container/image IDs,
restart/OOM/health state, and safe host/Docker CPU, RAM, disk and version
metadata. A final topology snapshot is captured synchronously after the workload
and before SLO/proof classification. Missing replicas, changed container IDs,
restarts, OOM kills, or unhealthy state in that final snapshot makes the run
non-proof and non-zero. The shell `EXIT` trap captures it only as a fallback for
an interrupted harness.

Set `CHANCELA_PERF_KEEP=1` to retain containers/volumes after a run for
inspection. Otherwise the wrapper always captures both topology snapshots and
Compose logs before teardown.

## Workload phases

Capacity profiles use four explicit, contiguous phases whose durations must sum
to `duration_seconds`:

- `warmup_seconds`: bounded quarter-load baseline;
- `ramp_seconds`: linear increase to configured client concurrency;
- `peak_plateau_seconds`: non-zero sustained maximum concurrency;
- `cooldown_seconds`: bounded reduction from the maximum.

The mixed workload includes health, entity/book/user lists, entity and book
reads, real authentication, entity writes, signature-status reads, search
status, and known-record search queries. Each operation reports request count,
status distribution, error rate, p50, p95, p99, maximum latency, and whether
latency percentiles are exact or based on a bounded reservoir. The overall
report includes throughput, per-phase request counts, a one-second
phase/client trace, and whether the peak plateau completed.

This remains a closed-loop concurrency test: slow responses reduce the offered
request rate. It does not establish an open-loop arrival-rate ceiling or
saturation curve.

## Search readiness and query evidence

After exact seeding and before signing/load, the harness waits for
`GET /v1/search/status` to report an enabled, idle, non-partial, non-stale
generation. It requires at least the seeded entity + book + act count, records
generation, document/character/truncation counters, and then proves that known
seeded entity, book, and act identifiers are returned by `/v1/search`.

A broad seeded query must also return a nonempty first page and a distinct,
nonempty second page. Both pages must preserve the ready generation and a
coherent total, offset, `has_more`, and cursor chain. Empty/repeated hits,
generation changes, or inconsistent paging metadata are readiness failures.
Readiness times out rather than silently running against a stale or incomplete index.
`CHANCELA_PERF_SEARCH_READY_TIMEOUT_SECONDS` controls the bound. Query and status
requests continue throughout the mixed capacity and soak phases.

## Whole-run resources

Docker CPU and memory sampling begins before API seeding and continues through
search catch-up, optional cryptographic signing, and mixed load. Reports include
overall and phase-specific per-container averages/peaks for:

- `seed`;
- `search_catch_up`;
- `cryptographic_signing`;
- `mixed_workload`.

The sampler discovers containers by the exact
`com.docker.compose.project=<project>` label, so custom project names work and
unrelated containers whose names happen to contain `chancela` are excluded.

Unavailable sampling is explicit and keeps the assessment non-proof even when
latency thresholds pass. Sampling does not yet include disk I/O, network I/O,
PostgreSQL query plans, or queue-depth telemetry.

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

The generator pins its disposable PFX to a SHA-1 MAC and 3DES PKCS#12 PBE
profile because the application's bounded pure-Rust `p12` reader does not
decrypt OpenSSL 3's default PBES2/AES PFX profile. This compatibility choice is
strictly for the short-lived synthetic identity used by this harness. It is not
a recommendation for exporting, storing, or transporting real certificates.
The harness fails closed when the generator output or passphrase is unusable.

Immediately before the opt-in cryptographic phase, and only after exact seeding
and search-readiness checks complete, the harness reads the authenticated
whole settings document, preserves every operator-authored field, and clears
both `signing.tsa_url` and `signing.tsa_providers` through the normal settings
API. Read retries are bounded to the short clustered-session propagation seam;
the settings write and every signature are leader-routed. The returned settings
document must prove that timestamping is disabled and that non-TSA settings
were preserved, or the run stops before signing. The timestamp-override setup
evidence records only sanitized status/count fields, never the settings
document or provider URLs. This prevents the local-PKCS#12 measurement from
silently becoming a public-TSA network test. `run-compose.sh` starts from fresh
disposable volumes and removes them by default, so the override is scoped to
that performance topology.

When cryptographic signing is requested, proof classification additionally
requires every reviewed threshold in `cryptographic_signing`: minimum completed
count, maximum error rate, minimum throughput, p95, p99, maximum total duration,
and maximum signing-phase memory/CPU. Missing crypto thresholds keep
`assessment: not_configured`; the repository deliberately ships no invented
values.

Exactness is unconditional: `exact` must be true and `signed` must equal
`requested`. A lower `min_completed` SLO cannot turn a partial cryptographic run
into proof, and the JSON/Markdown summaries are marked non-proof before the
harness returns its dedicated exactness failure.

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

The repository also carries `scripts/perf/slo.capacity.json`, the pre-run
acceptance policy for the committed `capacity` profile. It requires 100
requests/s overall, a maximum 0.5% aggregate error rate, bounded p95/p99/error
rates for every exercised operation, and per-container CPU and memory
headroom. Its cryptographic section additionally requires all 10,000 requested
local software-certificate signatures, zero signing errors, at least two
signatures/s, bounded latency and resource use, and completion within two
hours. These are acceptance thresholds fixed before evidence is collected,
not values derived from a result. They are a repository test policy rather
than a promise about untested production hardware or external providers.

Run the reviewed capacity policy with:

```sh
bash scripts/perf/run-compose.sh \
  capacity .perf-work/capacity scripts/perf/slo.capacity.json
```

The SLO file uses schema version 1. Its top-level and nested sections are
strictly typed objects; thresholds are finite non-negative numbers (or null),
error rates are in `[0,1]`, operation names/fields are known, and unknown fields
are rejected. Malformed SLO input produces a normal harness failure report,
never an uncaught attribute/type exception.

Supported checks are overall maximum error rate, minimum throughput,
per-operation p95/p99/error rate, maximum observed container CPU/memory, and the
complete cryptographic signing threshold set above. A configured failure makes
the harness exit non-zero. Dataset exactness, search readiness, topology
preflight, completed peak plateau, and resource availability are separate
mandatory proof prerequisites.

Capacity proof requires a complete reviewed policy, not merely one passing
threshold: both global error-rate and throughput thresholds, both container
CPU/memory thresholds, and p95, p99, and error-rate thresholds for every
operation measured by the workload must all be non-null. An all-null or partial
policy remains valid evidence with `assessment: not_configured` and
`proof_ready: false` when its configured checks pass. When cryptographic signing
is enabled, its complete threshold set remains an additional requirement.

## Deterministic wall-clock budget

Before generation or Compose startup, the wrapper writes
`report/duration-budget.json` and refuses a run whose deterministic allowances
do not fit the workflow timeout. The sum includes dataset/topology startup,
exact-volume seeding, the configured search-readiness timeout, the full workload
duration, optional per-signature cryptographic allowance, and a dedicated
cleanup/artifact-upload reserve. The self-hosted exact-volume job retains the
workflow's 360-minute bound (`CHANCELA_PERF_JOB_TIMEOUT_SECONDS=21600`). The
three-hour soak fits with
its reserves, but combining that soak with 10,000 cryptographic signatures is
rejected before startup rather than being credibly cancelled near the job
deadline. Run those as separate evidence jobs, or use an explicitly larger
approved runner and matching timeout configuration outside this workflow. This
is scheduling headroom, not a performance claim or an SLO.

## Reports and operational interpretation

Each run writes:

- `dataset/manifest.json` and four JSONL fixtures;
- `report/runtime-index.json` with observed server IDs;
- `report/topology-initial.json` and `report/topology-final.json`;
- `report/duration-budget.json`;
- `report/report.json`, the machine-readable source of truth, including profile
  eligibility and hosted/local source context;
- `report/report.md`, a compact human summary;
- `logs/generate.json`, `validate.json`, gateway health, harness log, and all
  Compose logs.

Do not call a run capacity proof unless all of the following are true:

1. the profile declares `proof_eligible: true`; `pr-smoke` is always excluded;
2. a GitHub Actions run records `source.ref: refs/heads/main`, every run records
   a valid 40-hex commit SHA, and a local run records a known-clean working tree
   (a detached clean commit is allowed);
3. the exact seed says `exact: true`;
4. search readiness passed and known entity/book/act records plus cursor paging
   were observed;
5. the intended phases completed, including the sustained peak plateau;
6. whole-run resource sampling was available;
7. strict topology preflight passed and the final snapshot has no restart/OOM
   regression;
8. a complete reviewed, non-null latency/throughput/error/resource policy was
   supplied for every measured operation;
9. when cryptographic signing was requested, every required crypto threshold
   was configured and the exact requested count completed;
10. `slo.assessment` is `passed`;
11. the claim stays within the tested topology and signing-provider boundary.

An interrupted seed, unavailable dependency, `not_configured` SLO, failed
threshold, or unsigned signature-status run is useful evidence, but not proof of
the requested production capacity.

The remaining boundaries are explicit: this harness does not yet model
open-loop arrival rates, authenticate as many distinct users during the mixed
phase, inject HA faults during exact-volume load, or prove CMD/CSC/QTSP,
smart-card, TSA, revocation, and external-validator provider capacity.
