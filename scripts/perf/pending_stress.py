#!/usr/bin/env python3
"""t57 B2 -- pending-acts stress: a large `ActState::Signing` backlog plus the durable
`pending_cmd_sessions` table, stressed on the read/list/status/dashboard paths and on
boot rehydration.

Companion to ``harness.py``, not a replacement -- it imports and reuses the existing
HTTP client, retry policy, latency reservoir/percentile plumbing, weighted-workload phase
model, and evidence/proof-governance helpers rather than duplicating them, so a
``pending-acts`` run is held to the same honesty rules a capacity run is: an unconfigured
SLO threshold is ``not_configured``, never an invented pass, and a partial backlog is
never reported as a completed one.

Scope, and one B2-specific finding recorded here (read at commit
``1178706c2292fee0aaa86860c7479542bbf3777e``, tree shared with active peers -- see the
t57-e3 log for the full writeup):

* **Backlog of acts awaiting signature** (`ActState::Signing`, `acts_awaiting_signature` --
  `dashboard.rs:124-135`) is fully seedable through the real HTTP API: draft, one PATCH,
  five ``advance`` calls per act (mirrors the existing pattern in
  ``harness.run_cryptographic_signing``). No blocker.

* **The durable `pending_cmd_sessions` table has no HTTP-reachable seam for synthetic
  volume.** ``POST /v1/acts/{id}/signature/cmd/initiate`` (`signature.rs:1618`) dispatches
  a real network call to the CCMovelSign provider and a real OTP to a real phone per
  session -- the same CMD non-automatability the plan's own assumptions already state for
  B1 (`plan.md` Sec 8, Assumption 3). Unlike the local-PKCS12 path, there is also no
  env-configurable substitute transport reachable from outside the process:
  ``AppState.cmd_transport`` (`lib.rs:888`) is only ever set by Rust-internal test code
  that constructs `AppState` in-process; the compiled server binary run by
  ``docker-compose.perf.yml`` always resolves the real `HttpScmdTransport`. So this module
  seeds `pending_cmd_sessions` **directly at the store layer** -- the exact column set at
  `schema.rs:479-491` -- rather than faking an HTTP flow that does not exist. Every such
  row is tagged ``synthetic_fixture: true`` end to end and must never be reported as a
  real CMD signing session or a cryptographic operation. See
  ``seed_pending_cmd_sessions_sqlite`` below for the mechanism and its own boundary: it
  requires a host-reachable SQLite `CHANCELA_DATA_DIR`. The clustered, Postgres-backed
  perf topology (`docker-compose.perf.yml` + `docker/docker-compose.cluster.yml`) is
  **not** reachable this way today -- Postgres is not published to the host and this
  harness has no `psycopg` dependency. Against that topology this stage is reported
  ``not_measured``, never faked; see ``pending_cmd_sessions_not_measured``.

This module only builds and unit-tests the above (see ``tests/test_pending_stress.py``).
Per the t57 coordinator's explicit instruction, nothing here is executed against a live
duration-based load or a real Docker topology by this work -- ``t57-e5`` runs it, after an
explicit written release.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import pathlib
import random
import sqlite3
import sys
import threading
import time
import uuid
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from harness import (  # noqa: E402  (see sys.path.insert above)
    ApiClient,
    HarnessError,
    HttpResult,
    OperationStats,
    Reservoir,
    ResourceSampler,
    SeedStage,
    capture_source_context,
    decode_json,
    parallel_seed,
    percentile,
    proof_context_blockers,
    read_json,
    safe_retry_request,
    utc_now,
    weighted_operations,
    workload_phase_and_clients,
    workload_phase_report,
    write_json,
)
import readiness  # noqa: E402
import topology  # noqa: E402


SCHEMA_VERSION = 1
DEFAULT_PASSWORD = "Perf-Only-Password-2026!"

# The `pending_cmd_sessions` column order, verbatim from `schema.rs:479-491` /
# `pg.rs:1749-1758` (both backends share the same column set and order in their SELECT).
PENDING_CMD_SESSION_COLUMNS = (
    "session_id",
    "act_id",
    "actor",
    "status",
    "masked_phone",
    "doc_name",
    "signer_capacity_evidence_json",
    "session_json",
    "prepared_json",
    "created_at",
    "expires_at",
)

# The act state-machine hops a fresh act must clear to reach Signing (`act.rs:54-64`),
# in order. Mirrors `harness.run_cryptographic_signing`'s `setup_requests` shape.
ADVANCE_SEQUENCE = ("Review", "Convened", "Deliberated", "TextApproved", "Signing")

READ_STRESS_EXPECTED_SUCCESS = {
    "act_get": {200},
    "signature_status": {200},
    "book_acts_list": {200},
    "dashboard": {200},
}


class PendingStressError(HarnessError):
    pass


# --------------------------------------------------------------------------------------
# Profile
# --------------------------------------------------------------------------------------


def validate_profile(profile: dict[str, Any]) -> None:
    """Schema check for `profiles/pending-acts.json`. Deliberately a separate, narrower
    schema from `harness.validate_profile` -- this profile has no `dataset`/`workload`
    shape, it has `backlog` / `pending_cmd_sessions` / `read_stress` / `rehydration`."""

    if profile.get("schema_version") != SCHEMA_VERSION:
        raise PendingStressError("pending-acts profile schema_version must be 1")
    if profile.get("name") != "pending-acts":
        raise PendingStressError("pending-acts profile name must be 'pending-acts'")

    backlog = profile.get("backlog")
    if not isinstance(backlog, dict):
        raise PendingStressError("profile.backlog must be an object")
    for field in (
        "target_acts_in_signing",
        "users",
        "entities",
        "books",
        "advance_concurrency",
    ):
        value = backlog.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise PendingStressError(
                f"profile.backlog.{field} must be a positive integer"
            )
    if backlog["books"] > backlog["target_acts_in_signing"]:
        raise PendingStressError(
            "profile.backlog.books must not exceed target_acts_in_signing"
        )
    if not 1 <= backlog["advance_concurrency"] <= 64:
        raise PendingStressError(
            "profile.backlog.advance_concurrency must be between 1 and 64"
        )

    pending = profile.get("pending_cmd_sessions")
    if not isinstance(pending, dict):
        raise PendingStressError("profile.pending_cmd_sessions must be an object")
    target_count = pending.get("target_count")
    if not isinstance(target_count, int) or isinstance(target_count, bool) or target_count < 1:
        raise PendingStressError(
            "profile.pending_cmd_sessions.target_count must be a positive integer"
        )
    if pending.get("seed_mode") not in {"store_direct_sqlite", "unsupported"}:
        raise PendingStressError(
            "profile.pending_cmd_sessions.seed_mode must be 'store_direct_sqlite' or "
            "'unsupported' -- there is no HTTP-reachable way to create these at volume "
            "(see module docstring)"
        )
    if pending.get("synthetic_fixture") is not True:
        raise PendingStressError(
            "profile.pending_cmd_sessions.synthetic_fixture must be true -- these rows "
            "are never real CMD signing sessions and must never be represented as such"
        )

    read_stress = profile.get("read_stress")
    if not isinstance(read_stress, dict):
        raise PendingStressError("profile.read_stress must be an object")
    for field in (
        "mode",
        "duration_seconds",
        "warmup_seconds",
        "ramp_seconds",
        "peak_plateau_seconds",
        "cooldown_seconds",
        "clients",
        "request_timeout_seconds",
        "max_latency_samples_per_operation",
        "weights",
    ):
        if field not in read_stress:
            raise PendingStressError(f"profile.read_stress.{field} is required")
    weights = read_stress["weights"]
    if not isinstance(weights, dict) or not weights:
        raise PendingStressError("profile.read_stress.weights must be a non-empty object")
    unknown = set(weights) - set(READ_STRESS_EXPECTED_SUCCESS)
    if unknown:
        raise PendingStressError(
            f"profile.read_stress.weights has unknown operations: {sorted(unknown)}"
        )
    if not any(int(weight) > 0 for weight in weights.values()):
        raise PendingStressError("profile.read_stress.weights must have at least one positive weight")

    rehydration = profile.get("rehydration")
    if not isinstance(rehydration, dict):
        raise PendingStressError("profile.rehydration must be an object")
    if not isinstance(rehydration.get("service"), str) or not rehydration["service"]:
        raise PendingStressError("profile.rehydration.service must be a non-empty string")


# --------------------------------------------------------------------------------------
# Backlog seeding: entities, books, and acts driven to `Signing` -- all through the real
# HTTP API. No blocker; mirrors `harness.seed_dataset` / `harness.run_cryptographic_signing`.
# --------------------------------------------------------------------------------------


def _entity_request(ordinal: int) -> dict[str, Any]:
    return {
        "name": f"Pending Stress Entity {ordinal:05d}, Lda",
        "nipc": f"8{ordinal:08d}"[-9:],
        "seat": "Lisboa",
        "kind": "SociedadePorQuotas",
        "allow_invalid_nipc": True,
    }


def _book_request(ordinal: int) -> dict[str, Any]:
    # `one_shot: true` opens the book immediately with no declared page capacity
    # (`book.rs:441-462`: capacity is only ever set by an executed termo de abertura), so
    # it never hits the capacity-exhausted 409 (`acts.rs:65-70`) no matter how many acts
    # this stress backlog drafts into it.
    return {
        "kind": "AssembleiaGeral",
        "purpose": f"Pending stress book {ordinal:05d}",
        "opening_date": "2026-01-15",
        "required_signatories": ["Administrador"],
        "one_shot": True,
        "actor": "perf-pending-stress",
    }


def _act_patch_body() -> dict[str, Any]:
    return {
        "meeting_date": "2026-03-30",
        "meeting_time": "10:00",
        "place": "Sede social",
        "mesa": {
            "presidente": "Pending Stress President",
            "secretarios": ["Pending Stress Secretary"],
        },
        "agenda": [{"number": 1, "text": "Pending-acts backlog stress fixture"}],
        "attendance_reference": "Synthetic pending-acts stress fixture",
        "deliberations": "Synthetic pending-acts stress fixture approved.",
    }


def bootstrap_owner(client: ApiClient, password: str) -> dict[str, Any]:
    owner_request = {
        "username": "pending-stress-owner",
        "display_name": "Pending Stress Owner",
        "email": "pending-stress-owner@example.test",
        "send_welcome_email": False,
        "password": password,
    }
    result = safe_retry_request(
        client, "POST", "/v1/users", owner_request, authenticated=False
    )
    if result.status not in {200, 201}:
        raise PendingStressError(f"bootstrap owner failed: status={result.status}")
    owner = decode_json(result, "bootstrap owner")
    login = client.request(
        "POST",
        "/v1/session",
        {"user_id": owner["id"], "password": password},
        authenticated=False,
    )
    if login.status not in {200, 201}:
        raise PendingStressError(f"bootstrap login failed: status={login.status}")
    client.session_token = decode_json(login, "bootstrap login")["token"]
    return owner


def seed_entities_and_books(
    client: ApiClient,
    backlog: dict[str, Any],
) -> tuple[dict[str, Any], list[str], list[str]]:
    concurrency = backlog["advance_concurrency"]

    def create_entity(record: dict[str, Any]) -> tuple[int, HttpResult, str | None]:
        result = safe_retry_request(client, "POST", "/v1/entities", record["request"])
        identifier = None
        if result.status in {200, 201}:
            identifier = decode_json(result, f"entity {record['ordinal']}").get("id")
        return record["ordinal"], result, identifier

    entity_records = (
        {"ordinal": ordinal, "request": _entity_request(ordinal)}
        for ordinal in range(backlog["entities"])
    )
    entity_stage, entity_ids = parallel_seed(
        entity_records, backlog["entities"], concurrency, create_entity, {200, 201}
    )
    entity_report = entity_stage.report()
    if not entity_report["exact"]:
        raise PendingStressError("entity seed for pending-acts backlog was not exact")

    def create_book(record: dict[str, Any]) -> tuple[int, HttpResult, str | None]:
        request = dict(record["request"])
        request["entity_id"] = entity_ids[record["entity_ordinal"]]
        result = safe_retry_request(client, "POST", "/v1/books", request)
        identifier = None
        if result.status in {200, 201}:
            identifier = decode_json(result, f"book {record['ordinal']}").get("id")
        return record["ordinal"], result, identifier

    book_records = (
        {
            "ordinal": ordinal,
            "entity_ordinal": ordinal % len(entity_ids),
            "request": _book_request(ordinal),
        }
        for ordinal in range(backlog["books"])
    )
    book_stage, book_ids = parallel_seed(
        book_records, backlog["books"], concurrency, create_book, {200, 201}
    )
    book_report = book_stage.report()
    if not book_report["exact"]:
        raise PendingStressError("book seed for pending-acts backlog was not exact")

    return {"entities": entity_report, "books": book_report}, entity_ids, book_ids


def draft_and_advance_to_signing(
    client: ApiClient,
    ordinal: int,
    book_id: str,
) -> tuple[int, HttpResult, str | None]:
    """One act, driven `Draft -> ... -> Signing`: draft, one PATCH, five `advance` calls
    (`ADVANCE_SEQUENCE`). Mirrors `harness.run_cryptographic_signing.prepare_and_sign`
    exactly up to (not including) the final sign call, which B2 has no reason to make."""

    draft_result = safe_retry_request(
        client,
        "POST",
        "/v1/acts",
        {
            "book_id": book_id,
            "title": f"Pending Stress Act {ordinal:06d}",
            "channel": "Physical",
            "actor": "perf-pending-stress",
        },
    )
    if draft_result.status not in {200, 201}:
        return ordinal, draft_result, None
    act_id = decode_json(draft_result, f"act {ordinal}").get("id")
    if not act_id:
        return ordinal, draft_result, None

    patch_result = safe_retry_request(
        client, "PATCH", f"/v1/acts/{act_id}", _act_patch_body()
    )
    if patch_result.status != 200:
        return ordinal, patch_result, None

    last_result = patch_result
    for target_state in ADVANCE_SEQUENCE:
        last_result = safe_retry_request(
            client, "POST", f"/v1/acts/{act_id}/advance", {"to": target_state}
        )
        if last_result.status != 200:
            return ordinal, last_result, None
    return ordinal, last_result, act_id


def seed_backlog_to_signing(
    client: ApiClient,
    backlog: dict[str, Any],
    book_ids: list[str],
) -> tuple[dict[str, Any], list[str]]:
    target = backlog["target_acts_in_signing"]
    concurrency = backlog["advance_concurrency"]
    stage = SeedStage(requested=target)
    act_ids: dict[int, str] = {}
    lock = threading.Lock()
    started = time.perf_counter()

    def task(ordinal: int) -> None:
        book_id = book_ids[ordinal % len(book_ids)]
        result_ordinal, result, act_id = draft_and_advance_to_signing(
            client, ordinal, book_id
        )
        with lock:
            stage.record(result_ordinal, result, {200})
            if act_id is not None:
                act_ids[result_ordinal] = act_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(task, ordinal) for ordinal in range(target)]
        for future in concurrent.futures.as_completed(futures):
            future.result()
    stage.duration_seconds = time.perf_counter() - started
    ordered_ids = [act_ids[key] for key in sorted(act_ids)]
    report = stage.report()
    report["realization"] = "act_advanced_to_signing_via_http"
    return report, ordered_ids


# --------------------------------------------------------------------------------------
# `pending_cmd_sessions` synthetic seeding -- store-direct, SQLite only (see module
# docstring for why, and for the Postgres/cluster boundary).
# --------------------------------------------------------------------------------------


def synthetic_pending_cmd_session(
    ordinal: int,
    act_id: str,
    created_at: str,
    expires_at: str,
) -> dict[str, Any]:
    # `uuid5` over a fixed namespace + ordinal, not `uuid4`: reruns against the same
    # ordinal produce the same session id, matching this harness's other deterministic
    # fixture generation (`harness.py` USER_NAMESPACE).
    session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"pending-stress-session:{ordinal}"))
    return {
        "session_id": session_id,
        "act_id": act_id,
        "actor": "perf-pending-stress",
        "status": "otp_pending",
        "masked_phone": f"+351 9{ordinal % 10}X XXX {ordinal % 1000:03d}",
        "doc_name": f"Pending Stress Act {ordinal:06d}",
        "signer_capacity_evidence_json": None,
        "session_json": json.dumps(
            {"synthetic_fixture": True, "ordinal": ordinal}, separators=(",", ":")
        ),
        "prepared_json": json.dumps(
            {"synthetic_fixture": True, "ordinal": ordinal}, separators=(",", ":")
        ),
        "created_at": created_at,
        "expires_at": expires_at,
    }


def pending_cmd_sessions_not_measured(target_count: int, reason: str) -> dict[str, Any]:
    """The honest non-answer for a topology `seed_pending_cmd_sessions_sqlite` cannot
    reach (the clustered Postgres perf topology today). Mirrors the shape of a completed
    stage report so callers can still assemble a report, but `measured: false` and
    `exact` is deliberately absent -- there is nothing to assert exactness about."""

    return {
        "requested": target_count,
        "measured": False,
        "seed_mode": "unsupported",
        "synthetic_fixture": True,
        "reason": reason,
    }


def seed_pending_cmd_sessions_sqlite(
    db_path: pathlib.Path,
    act_ids: list[str],
    count: int,
) -> dict[str, Any]:
    """Insert `count` structurally real, content-synthetic `pending_cmd_sessions` rows
    directly at the store layer. Column set matches `schema.rs:479-491` exactly, so the
    boot-rehydration read path (`Store::all_pending_cmd_sessions`, `lib.rs:1478-1479`)
    sees genuine rows -- only the JSON payload content is a placeholder, and rehydration
    never deserializes `session_json`/`prepared_json` (`row_to_pending_session`,
    `lib.rs:8778-8807`, treats them as opaque `String`s).

    **Ordering requirement, left to the caller**: run this while the server process that
    owns `db_path` is stopped. A second SQLite connection against a file the server has
    open risks lock contention against the server's own connection, and more importantly
    this is *meant* to seed the durable state a boot then rehydrates from -- the
    measurement is the boot after seeding, not a live write during serving.
    """

    if not db_path.is_file():
        raise PendingStressError(f"sqlite store file does not exist: {db_path}")
    if count > len(act_ids):
        raise PendingStressError(
            f"pending_cmd_sessions target_count {count} exceeds {len(act_ids)} seeded "
            "backlog acts"
        )
    now = dt.datetime.now(dt.timezone.utc)
    created_at = now.isoformat().replace("+00:00", "Z")
    # An hour out: long enough that the read-stress window (profile.read_stress) never
    # crosses into "expired" (`find_pending_for_act` + the `expires_at` check,
    # `signature.rs:6489-6491`, would silently report `status: "unsigned"` instead of
    # `"pending"` past expiry, which would misrepresent what this stage is testing).
    expires_at = (now + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")

    rows = [
        tuple(
            synthetic_pending_cmd_session(ordinal, act_ids[ordinal], created_at, expires_at)[
                column
            ]
            for column in PENDING_CMD_SESSION_COLUMNS
        )
        for ordinal in range(count)
    ]
    column_list = ", ".join(PENDING_CMD_SESSION_COLUMNS)
    placeholders = ", ".join("?" for _ in PENDING_CMD_SESSION_COLUMNS)

    connection = sqlite3.connect(str(db_path))
    try:
        connection.executemany(
            f"INSERT INTO pending_cmd_sessions ({column_list}) VALUES ({placeholders})",
            rows,
        )
        connection.commit()
        (inserted,) = connection.execute(
            "SELECT COUNT(*) FROM pending_cmd_sessions"
        ).fetchone()
    finally:
        connection.close()

    return {
        "requested": count,
        "measured": True,
        "inserted_total_in_table": inserted,
        "exact": inserted >= count,
        "seed_mode": "store_direct_sqlite",
        "synthetic_fixture": True,
        "claim_boundary": (
            "These are structurally valid pending_cmd_sessions rows written directly at "
            "the store layer for boot-rehydration read-path measurement. They are NOT "
            "real CMD signing sessions: no OTP was dispatched, no CCMovelSign call was "
            "made, and no phone received anything. Never report this count as signing "
            "sessions performed or as cryptographic operations."
        ),
    }


def pending_cmd_sessions_exactness_blocker(report: dict[str, Any]) -> str | None:
    if not report.get("measured"):
        return f"pending_cmd_sessions not measured: {report.get('reason', 'unknown')}"
    if report.get("exact") is True:
        return None
    return (
        "pending_cmd_sessions synthetic seed did not reach the exact requested volume "
        f"(requested={report.get('requested')!r}, "
        f"inserted_total_in_table={report.get('inserted_total_in_table')!r})."
    )


# --------------------------------------------------------------------------------------
# Read-path stress: act status, signature status, book-acts list, dashboard -- over the
# seeded backlog. Reuses harness's weighted-workload phase model and latency plumbing.
# --------------------------------------------------------------------------------------


def execute_read_operation(
    name: str,
    client: ApiClient,
    act_ids: list[str],
    book_ids: list[str],
    rng: random.Random,
) -> HttpResult:
    if name == "act_get":
        return client.request("GET", f"/v1/acts/{rng.choice(act_ids)}")
    if name == "signature_status":
        return client.request("GET", f"/v1/acts/{rng.choice(act_ids)}/signature")
    if name == "book_acts_list":
        return client.request("GET", f"/v1/books/{rng.choice(book_ids)}/acts")
    if name == "dashboard":
        return client.request("GET", "/v1/dashboard")
    raise PendingStressError(f"unimplemented read-stress operation {name}")


def run_read_stress(
    client: ApiClient,
    profile: dict[str, Any],
    act_ids: list[str],
    book_ids: list[str],
    resource_sampler: ResourceSampler | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    read_stress = profile["read_stress"]
    duration = float(read_stress["duration_seconds"])
    clients = int(read_stress["clients"])
    sample_limit = int(read_stress.get("max_latency_samples_per_operation", 200000))
    operations = weighted_operations(read_stress["weights"])
    if not act_ids:
        raise PendingStressError("read-stress cannot run without seeded backlog act ids")
    if "book_acts_list" in read_stress["weights"] and not book_ids:
        raise PendingStressError("read-stress cannot run book_acts_list without book ids")

    lock = threading.Lock()
    stats: dict[str, OperationStats] = {
        name: OperationStats(Reservoir(sample_limit, random.Random(profile["seed"] + position)))
        for position, name in enumerate(sorted(set(operations)))
    }
    stop_at = time.monotonic() + duration
    started = time.monotonic()
    active_trace: list[dict[str, Any]] = []
    trace_lock = threading.Lock()

    def worker(worker_id: int) -> None:
        rng = random.Random(profile["seed"] + 10000 + worker_id)
        last_trace_second = -1
        while time.monotonic() < stop_at:
            elapsed = time.monotonic() - started
            phase, allowed = workload_phase_and_clients(read_stress, elapsed)
            second = int(elapsed)
            if worker_id == 0 and second != last_trace_second:
                with trace_lock:
                    active_trace.append(
                        {
                            "elapsed_seconds": second,
                            "phase": phase,
                            "active_clients": allowed,
                        }
                    )
                last_trace_second = second
            if worker_id >= allowed:
                time.sleep(0.02)
                continue
            operation = rng.choice(operations)
            result = execute_read_operation(operation, client, act_ids, book_ids, rng)
            with lock:
                stats[operation].record(result, READ_STRESS_EXPECTED_SUCCESS[operation])

    sampler = resource_sampler or ResourceSampler()
    owns_sampler = resource_sampler is None
    sampler.set_phase("pending_acts_read_stress")
    if owns_sampler:
        sampler.start()
    else:
        sampler.sample_now()
    with concurrent.futures.ThreadPoolExecutor(max_workers=clients) as executor:
        futures = [executor.submit(worker, worker_id) for worker_id in range(clients)]
        for future in futures:
            future.result()
    elapsed = time.monotonic() - started
    resources = sampler.finish() if owns_sampler else sampler.report()

    operation_reports = {name: value.report() for name, value in sorted(stats.items())}
    total = sum(item["requests"] for item in operation_reports.values())
    errors = sum(item["errors"] for item in operation_reports.values())
    return (
        {
            "mode": read_stress["mode"],
            "duration_seconds": elapsed,
            "configured_clients": clients,
            "active_client_trace": active_trace,
            "phases": workload_phase_report(read_stress, elapsed),
            "requests": total,
            "errors": errors,
            "error_rate": errors / total if total else 0.0,
            "throughput_per_second": total / max(elapsed, 0.000001),
            "operations": operation_reports,
        },
        resources,
    )


def evaluate_read_stress_slo(
    read_stress_report: dict[str, Any],
    slo: dict[str, Any] | None,
) -> dict[str, Any]:
    """Checks the read-stress result against `slo.capacity.json`'s *existing* envelope
    (plan §5 B2: "meet the existing `slo.capacity.json` envelope for their operation
    classes"). Only `signature_status` has a same-named threshold there; the other three
    B2 operations (`act_get`, `book_acts_list`, `dashboard`) have no counterpart in that
    file and are reported `not_configured`, per this harness's existing rule that an
    absent threshold is never silently treated as a pass (`harness.evaluate_slo`)."""

    if slo is None:
        return {
            "assessment": "not_configured",
            "checks": [],
            "message": "No SLO file supplied; measurements are evidence, not a pass.",
        }
    global_slo = slo.get("global", {})
    operation_slo = slo.get("operations", {})
    checks: list[dict[str, Any]] = []

    def check(metric: str, observed: float | None, threshold: Any, relation: str) -> None:
        if threshold is None:
            checks.append(
                {"metric": metric, "observed": observed, "threshold": None, "passed": None}
            )
            return
        passed = observed is not None and (
            observed <= threshold if relation == "max" else observed >= threshold
        )
        checks.append(
            {
                "metric": metric,
                "observed": observed,
                "threshold": threshold,
                "relation": relation,
                "passed": passed,
            }
        )

    check(
        "global.max_error_rate",
        read_stress_report.get("error_rate"),
        global_slo.get("max_error_rate"),
        "max",
    )
    check(
        "global.min_throughput_per_second",
        read_stress_report.get("throughput_per_second"),
        global_slo.get("min_throughput_per_second"),
        "min",
    )
    for name, op_report in read_stress_report.get("operations", {}).items():
        thresholds = operation_slo.get(name)
        if not isinstance(thresholds, dict):
            checks.append(
                {
                    "metric": f"operations.{name}",
                    "observed": None,
                    "threshold": None,
                    "passed": None,
                    "note": f"no slo.capacity.json envelope for {name!r}",
                }
            )
            continue
        check(f"operations.{name}.p95_ms", op_report.get("p95_ms"), thresholds.get("p95_ms"), "max")
        check(f"operations.{name}.p99_ms", op_report.get("p99_ms"), thresholds.get("p99_ms"), "max")
        check(
            f"operations.{name}.max_error_rate",
            op_report.get("error_rate"),
            thresholds.get("max_error_rate"),
            "max",
        )

    configured = [c for c in checks if c["threshold"] is not None]
    if not configured:
        assessment = "not_configured"
    elif all(c["passed"] for c in configured):
        assessment = "passed"
    else:
        assessment = "failed"
    return {"assessment": assessment, "checks": checks}


# --------------------------------------------------------------------------------------
# Boot rehydration timing -- restart the app service, then time until `readiness.py`'s
# existing container-health gate reports ready. This is deliberately a real container
# restart, not a narrower reload endpoint: the plan asks for "rehydration on boot".
# --------------------------------------------------------------------------------------


def measure_boot_rehydration(
    compose_files: list[pathlib.Path],
    profiles: list[str],
    project_name: str,
    service: str,
    expected_replicas: int,
    timeout_seconds: float,
    poll_seconds: float,
    *,
    command_runner=topology.command,
) -> dict[str, Any]:
    """Restart `service` and time until `readiness.readiness_report` reports ready.

    Precondition (left to the caller, same as `seed_pending_cmd_sessions_sqlite`): any
    store-direct seeding must already be durable on disk before this call -- this
    function only restarts and times, it never seeds."""

    compose = readiness.compose_prefix(compose_files, profiles, project_name)
    started = time.monotonic()
    command_runner([*compose, "restart", service], timeout=timeout_seconds)
    restart_issued_at = time.monotonic() - started

    def snapshot_reader(deadline: float) -> dict[str, list[dict[str, Any]]]:
        return readiness.capture_snapshot(compose, deadline, command_runner=command_runner)

    report = readiness.readiness_report(
        snapshot_reader, expected_replicas, timeout_seconds, poll_seconds
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "captured_at": utc_now(),
        "service": service,
        "restart_issued_after_seconds": round(restart_issued_at, 6),
        "ready": report["ready"],
        "outcome": report["outcome"],
        "elapsed_seconds": report["elapsed_seconds"],
        "attempts": report["attempts"],
        "diagnostics": report["diagnostics"],
        "boundary": (
            "Times a container restart plus health-gate readiness, which includes "
            "rehydrating every durable read model (`AppState::with_data_dir`, "
            "`lib.rs:1471-1480`), not only pending_signatures in isolation. Report the "
            "pending-session table size alongside this figure, never this figure alone."
        ),
    }


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=pathlib.Path, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:18081")
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--sqlite-db-path",
        type=pathlib.Path,
        help=(
            "Host-reachable SQLite CHANCELA_DATA_DIR store file, required only when "
            "profile.pending_cmd_sessions.seed_mode is store_direct_sqlite. Absent this, "
            "the pending_cmd_sessions stage is reported not_measured."
        ),
    )
    parser.add_argument(
        "--slo",
        type=pathlib.Path,
        help="Path to an SLO file (e.g. slo.capacity.json) to check the read-stress result against.",
    )
    parser.add_argument("--compose-file", action="append", type=pathlib.Path, default=[])
    parser.add_argument("--compose-profile", action="append", default=[])
    parser.add_argument("--project-name")
    parser.add_argument("--expected-replicas", type=int, default=1)
    return parser


def run_command(args: argparse.Namespace) -> int:
    profile = read_json(args.profile)
    validate_profile(profile)
    source_context = capture_source_context()

    client = ApiClient(args.base_url, float(profile["read_stress"]["request_timeout_seconds"]))
    bootstrap_owner(client, args.password)
    seed_report, entity_ids, book_ids = seed_entities_and_books(client, profile["backlog"])
    backlog_report, act_ids = seed_backlog_to_signing(client, profile["backlog"], book_ids)
    seed_report["acts"] = backlog_report

    pending_cfg = profile["pending_cmd_sessions"]
    if pending_cfg["seed_mode"] == "store_direct_sqlite" and args.sqlite_db_path is not None:
        pending_report = seed_pending_cmd_sessions_sqlite(
            args.sqlite_db_path, act_ids, pending_cfg["target_count"]
        )
    else:
        pending_report = pending_cmd_sessions_not_measured(
            pending_cfg["target_count"],
            "no host-reachable --sqlite-db-path supplied (Postgres/cluster topology, or "
            "seed_mode=unsupported); see module docstring for why this cannot be seeded "
            "over HTTP.",
        )

    read_stress_report, resources = run_read_stress(client, profile, act_ids, book_ids)
    slo = read_json(args.slo) if args.slo else None
    slo_assessment = evaluate_read_stress_slo(read_stress_report, slo)

    rehydration_report: dict[str, Any] | None = None
    if profile["rehydration"].get("measure") and args.compose_file:
        rehydration_report = measure_boot_rehydration(
            args.compose_file,
            args.compose_profile,
            args.project_name or "chancela-perf",
            profile["rehydration"]["service"],
            args.expected_replicas,
            float(profile["rehydration"].get("timeout_seconds", 600)),
            float(profile["rehydration"].get("poll_seconds", 2)),
        )

    exactness_blockers = [
        blocker
        for blocker in (
            None if seed_report["acts"]["exact"] else "backlog seed did not reach the exact requested volume",
            pending_cmd_sessions_exactness_blocker(pending_report),
        )
        if blocker
    ]

    report = {
        "schema_version": SCHEMA_VERSION,
        "captured_at": utc_now(),
        "source_context": source_context,
        "proof_eligible": False,
        "proof_blockers": proof_context_blockers(profile, source_context)
        + exactness_blockers,
        "profile": profile,
        "seed": seed_report,
        "pending_cmd_sessions": pending_report,
        "read_stress": read_stress_report,
        "resources": resources,
        "slo": slo_assessment,
        "rehydration": rehydration_report,
        "claim_boundary": (
            "This is a pending-acts read-path engineering measurement, not a capacity "
            "proof (governed capacity/slo.capacity.json are untouched by this profile). "
            "It does not by itself flip any spec-coverage claim."
        ),
    }
    write_json(args.output, report)
    print(json.dumps({"proof_blockers": report["proof_blockers"], "slo": slo_assessment}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_command(args)
    except HarnessError as error:
        print(f"pending_stress: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
