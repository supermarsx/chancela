#!/usr/bin/env python3
"""Deterministic capacity dataset generator and HTTP load harness.

The harness deliberately separates evidence from claims:

* ``generate`` streams exact-volume JSONL fixtures and records count + SHA-256.
* ``validate`` re-counts and re-hashes every fixture.
* ``run`` optionally seeds a fresh Chancela API, executes a mixed workload, samples
  Docker resources, and emits JSON + Markdown reports.
* SLO thresholds are opt-in. A report with no thresholds is ``not_configured``,
  never an invented pass.

The ``signatures`` fixture represents unsigned act subjects exercised through the
real signature-status route. It does not claim cryptographic signing/provider
capacity; that limitation is always included in the report.
"""

from __future__ import annotations

import argparse
import base64
import copy
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import http.client
import json
import math
import os
import pathlib
import random
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter, defaultdict
from typing import Any, Callable, Iterable, Iterator

from perf_io import atomic_write_text_lf


SCHEMA_VERSION = 1
DATASET_FILES = {
    "users": "users.jsonl",
    "entities": "entities.jsonl",
    "books": "books.jsonl",
    "signatures": "signatures.jsonl",
}
EXPECTED_SUCCESS = {
    "health": {200},
    "entity_list": {200},
    "entity_get": {200},
    "book_list": {200},
    "book_get": {200},
    "user_list": {200},
    "auth_login": {200, 201},
    "entity_write": {200, 201},
    "signature_status": {200},
    "search_query": {200},
    "search_status": {200},
}
MODES = {"steady", "ramp", "spike", "soak"}
WORKLOAD_PHASES = (
    "warmup_seconds",
    "ramp_seconds",
    "peak_plateau_seconds",
    "cooldown_seconds",
)
CRYPTO_SLO_FIELDS = {
    "min_completed",
    "max_error_rate",
    "min_throughput_per_second",
    "p95_ms",
    "p99_ms",
    "max_duration_seconds",
    "max_phase_memory_bytes",
    "max_phase_cpu_percent",
}
SLO_TOP_LEVEL_FIELDS = {
    "schema_version",
    "global",
    "operations",
    "resources",
    "cryptographic_signing",
}
SLO_GLOBAL_FIELDS = {"max_error_rate", "min_throughput_per_second"}
SLO_OPERATION_FIELDS = {"p95_ms", "p99_ms", "max_error_rate"}
SLO_RESOURCE_FIELDS = {
    "max_container_memory_bytes",
    "max_container_cpu_percent",
}
DURATION_BUDGET_SECONDS = {
    "dataset_generation_and_topology_start": 900,
    "exact_volume_seed": 3_600,
    "cryptographic_setup": 600,
    "cryptographic_per_signature": 0.75,
    "cleanup_and_artifact_upload": 1_800,
}
TSA_SETTINGS_READ_ATTEMPTS = 12
TSA_SETTINGS_READ_RETRY_STATUSES = {401, 429, 503}
DEFAULT_PASSWORD = "Perf-Only-Password-2026!"
USER_NAMESPACE = uuid.UUID("7b0fb943-83ff-4e56-a670-0fd19fb46ee5")
GITHUB_MAIN_REF = "refs/heads/main"
GIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class HarnessError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise HarnessError(f"{path} must contain a JSON object")
    return value


def write_json(path: pathlib.Path, value: Any) -> None:
    atomic_write_text_lf(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
    )


def validate_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError(f"profile schema_version must be {SCHEMA_VERSION}")
    if not isinstance(profile.get("proof_eligible"), bool):
        raise HarnessError("profile.proof_eligible must be a boolean")
    if profile.get("name") == "pr-smoke" and profile["proof_eligible"]:
        raise HarnessError("the pr-smoke profile must not be proof eligible")
    dataset = profile.get("dataset")
    if not isinstance(dataset, dict):
        raise HarnessError("profile.dataset must be an object")
    for name in DATASET_FILES:
        count = dataset.get(name)
        if not isinstance(count, int) or count < 1:
            raise HarnessError(f"profile.dataset.{name} must be a positive integer")
    if dataset["books"] < dataset["signatures"]:
        raise HarnessError("books must be >= signatures so each signature subject has an open book")
    workload = profile.get("workload")
    if not isinstance(workload, dict):
        raise HarnessError("profile.workload must be an object")
    if workload.get("mode") not in MODES:
        raise HarnessError(f"workload.mode must be one of {sorted(MODES)}")
    for field in ("duration_seconds", "clients", "request_timeout_seconds"):
        value = workload.get(field)
        if not isinstance(value, (int, float)) or value <= 0:
            raise HarnessError(f"workload.{field} must be positive")
    present_phases = [field for field in WORKLOAD_PHASES if field in workload]
    if present_phases:
        missing_phases = [field for field in WORKLOAD_PHASES if field not in workload]
        if missing_phases:
            raise HarnessError(
                "explicit workload phases require every phase field; missing "
                + ", ".join(missing_phases)
            )
        for field in WORKLOAD_PHASES:
            value = workload[field]
            if not isinstance(value, (int, float)) or value < 0:
                raise HarnessError(f"workload.{field} must be a non-negative number")
        if workload["peak_plateau_seconds"] <= 0:
            raise HarnessError("workload.peak_plateau_seconds must be positive")
        phase_duration = sum(float(workload[field]) for field in WORKLOAD_PHASES)
        if not math.isclose(
            phase_duration,
            float(workload["duration_seconds"]),
            rel_tol=0,
            abs_tol=0.001,
        ):
            raise HarnessError(
                "workload phase durations must sum to workload.duration_seconds "
                f"({phase_duration} != {workload['duration_seconds']})"
            )
    weights = workload.get("weights")
    if not isinstance(weights, dict) or not weights:
        raise HarnessError("workload.weights must be a non-empty object")
    unknown = set(weights) - set(EXPECTED_SUCCESS)
    if unknown:
        raise HarnessError(f"unknown workload operations: {sorted(unknown)}")
    if any(not isinstance(value, int) or value < 0 for value in weights.values()):
        raise HarnessError("workload weights must be non-negative integers")
    if sum(weights.values()) <= 0:
        raise HarnessError("at least one workload weight must be positive")


def _git_output(*arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=pathlib.Path(__file__).resolve().parents[2],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def valid_git_sha(value: Any) -> bool:
    return isinstance(value, str) and GIT_SHA_PATTERN.fullmatch(value) is not None


def capture_source_context() -> dict[str, Any]:
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        ref = os.environ.get("GITHUB_REF") or None
        commit_sha = os.environ.get("GITHUB_SHA") or None
        return {
            "kind": "github_actions",
            "proof_eligible": ref == GITHUB_MAIN_REF and valid_git_sha(commit_sha),
            "ref": ref,
            "commit_sha": commit_sha,
            "repository": os.environ.get("GITHUB_REPOSITORY") or None,
            "event_name": os.environ.get("GITHUB_EVENT_NAME") or None,
            "run_id": os.environ.get("GITHUB_RUN_ID") or None,
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT") or None,
            "working_tree_dirty": None,
            "working_tree_status_entries": None,
        }

    commit_sha = _git_output("rev-parse", "HEAD")
    ref = _git_output("rev-parse", "--abbrev-ref", "HEAD")
    status = _git_output("status", "--short")
    status_entries = None if status is None else len(status.splitlines())
    working_tree_dirty = None if status_entries is None else status_entries > 0
    return {
        "kind": "local",
        "proof_eligible": valid_git_sha(commit_sha) and working_tree_dirty is False,
        "ref": ref,
        "commit_sha": commit_sha,
        "repository": None,
        "event_name": None,
        "run_id": None,
        "run_attempt": None,
        "working_tree_dirty": working_tree_dirty,
        "working_tree_status_entries": status_entries,
    }


def proof_context_blockers(
    profile: dict[str, Any],
    source_context: dict[str, Any],
) -> list[str]:
    blockers: list[str] = []
    if profile.get("name") == "pr-smoke" or profile.get("proof_eligible") is not True:
        blockers.append(
            f"Profile {profile.get('name', '<unknown>')} is evidence-only and is not "
            "eligible for capacity proof."
        )
    if (
        source_context.get("kind") == "github_actions"
        and source_context.get("ref") != GITHUB_MAIN_REF
    ):
        blockers.append(
            "GitHub Actions capacity proof requires GITHUB_REF "
            f"{GITHUB_MAIN_REF}; observed {source_context.get('ref')!r}."
        )
    if not valid_git_sha(source_context.get("commit_sha")):
        blockers.append(
            "Capacity proof requires a recorded 40-hex Git commit SHA; observed "
            f"{source_context.get('commit_sha')!r}."
        )
    if source_context.get("kind") == "local":
        dirty = source_context.get("working_tree_dirty")
        if dirty is not False:
            blockers.append(
                "Local capacity proof requires a known-clean Git working tree; "
                f"working_tree_dirty is {dirty!r}."
            )
    elif source_context.get("kind") != "github_actions":
        blockers.append(
            "Capacity proof requires a recognized local or GitHub Actions source context."
        )
    return blockers


def add_proof_blockers(
    slo_report: dict[str, Any],
    blockers: Iterable[str],
) -> None:
    existing = slo_report.setdefault("proof_blockers", [])
    has_blockers = False
    for blocker in blockers:
        has_blockers = True
        if blocker not in existing:
            existing.append(blocker)
    if not has_blockers:
        return
    slo_report["proof_ready"] = False
    if slo_report["assessment"] == "passed":
        slo_report["assessment"] = "not_configured"
        slo_report["message"] = (
            "Measurements completed, but proof prerequisites are unavailable."
        )


def _validate_object(
    parent: dict[str, Any],
    field: str,
    allowed_fields: set[str],
) -> dict[str, Any]:
    value = parent.get(field, {})
    if not isinstance(value, dict):
        raise HarnessError(f"SLO {field} must be an object")
    unknown = set(value) - allowed_fields
    if unknown:
        raise HarnessError(f"SLO {field} has unknown fields: {sorted(unknown)}")
    return value


def _validate_numeric_threshold(path: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HarnessError(f"SLO {path} must be numeric or null")
    if not math.isfinite(float(value)) or value < 0:
        raise HarnessError(f"SLO {path} must be finite and non-negative")
    if path.endswith("error_rate") and value > 1:
        raise HarnessError(f"SLO {path} must be between 0 and 1")
    if path == "cryptographic_signing.min_completed" and not isinstance(value, int):
        raise HarnessError(f"SLO {path} must be an integer or null")


def validate_slo_schema(slo: dict[str, Any]) -> None:
    if slo.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError(f"SLO schema_version must be {SCHEMA_VERSION}")
    unknown = set(slo) - SLO_TOP_LEVEL_FIELDS
    if unknown:
        raise HarnessError(f"SLO has unknown top-level fields: {sorted(unknown)}")
    global_slo = _validate_object(slo, "global", SLO_GLOBAL_FIELDS)
    resource_slo = _validate_object(slo, "resources", SLO_RESOURCE_FIELDS)
    crypto_slo = _validate_object(
        slo,
        "cryptographic_signing",
        CRYPTO_SLO_FIELDS,
    )
    operations = slo.get("operations", {})
    if not isinstance(operations, dict):
        raise HarnessError("SLO operations must be an object")
    unknown_operations = set(operations) - set(EXPECTED_SUCCESS)
    if unknown_operations:
        raise HarnessError(
            f"SLO operations has unknown operations: {sorted(unknown_operations)}"
        )
    for operation, thresholds in operations.items():
        if not isinstance(thresholds, dict):
            raise HarnessError(f"SLO operations.{operation} must be an object")
        unknown_fields = set(thresholds) - SLO_OPERATION_FIELDS
        if unknown_fields:
            raise HarnessError(
                f"SLO operations.{operation} has unknown fields: "
                f"{sorted(unknown_fields)}"
            )
        for field, value in thresholds.items():
            _validate_numeric_threshold(f"operations.{operation}.{field}", value)
    for section_name, section in (
        ("global", global_slo),
        ("resources", resource_slo),
        ("cryptographic_signing", crypto_slo),
    ):
        for field, value in section.items():
            _validate_numeric_threshold(f"{section_name}.{field}", value)


def duration_budget_report(
    profile: dict[str, Any],
    *,
    workflow_timeout_seconds: float,
    search_readiness_timeout_seconds: float,
    cryptographic_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_profile(profile)
    if (
        isinstance(workflow_timeout_seconds, bool)
        or not isinstance(workflow_timeout_seconds, (int, float))
        or workflow_timeout_seconds <= 0
    ):
        raise HarnessError("workflow timeout must be a positive number")
    if (
        isinstance(search_readiness_timeout_seconds, bool)
        or not isinstance(search_readiness_timeout_seconds, (int, float))
        or search_readiness_timeout_seconds <= 0
    ):
        raise HarnessError("search readiness timeout must be a positive number")
    crypto_count = 0
    if cryptographic_config is not None:
        crypto_count = cryptographic_config.get("count")
        if (
            isinstance(crypto_count, bool)
            or not isinstance(crypto_count, int)
            or crypto_count < 1
        ):
            raise HarnessError(
                "duration budget cryptographic count must be a positive integer"
            )
        if crypto_count > int(profile["dataset"]["signatures"]):
            raise HarnessError(
                "duration budget cryptographic count exceeds seeded signature subjects"
            )
    components = {
        "dataset_generation_and_topology_start": DURATION_BUDGET_SECONDS[
            "dataset_generation_and_topology_start"
        ],
        "exact_volume_seed": DURATION_BUDGET_SECONDS["exact_volume_seed"],
        "search_catch_up": float(search_readiness_timeout_seconds),
        "mixed_workload": float(profile["workload"]["duration_seconds"]),
        "cryptographic_signing": (
            DURATION_BUDGET_SECONDS["cryptographic_setup"]
            + crypto_count * DURATION_BUDGET_SECONDS["cryptographic_per_signature"]
            if crypto_count
            else 0
        ),
        "cleanup_and_artifact_upload": DURATION_BUDGET_SECONDS[
            "cleanup_and_artifact_upload"
        ],
    }
    required = float(sum(components.values()))
    passed = required <= float(workflow_timeout_seconds)
    return {
        "schema_version": SCHEMA_VERSION,
        "budget_passed": passed,
        "workflow_timeout_seconds": float(workflow_timeout_seconds),
        "required_seconds": required,
        "remaining_seconds": float(workflow_timeout_seconds) - required,
        "components": components,
        "cryptographic_signatures": crypto_count,
        "method": (
            "Deterministic phase allowances include exact-volume seed, configured search "
            "timeout and workload, per-signature crypto allowance, and an explicit cleanup/"
            "artifact-upload reserve."
        ),
    }


def dataset_records(kind: str, count: int, counts: dict[str, int]) -> Iterator[dict[str, Any]]:
    if kind == "users":
        for ordinal in range(count):
            username = "perf-owner" if ordinal == 0 else f"perf-user-{ordinal:05d}"
            yield {
                "kind": "user",
                "ordinal": ordinal,
                "stable_id": str(uuid.uuid5(USER_NAMESPACE, f"user:{ordinal}")),
                "request": {
                    "username": username,
                    "display_name": f"Performance User {ordinal:05d}",
                    "email": f"{username}@example.test",
                    "send_welcome_email": False,
                },
            }
    elif kind == "entities":
        for ordinal in range(count):
            yield {
                "kind": "entity",
                "ordinal": ordinal,
                "request": {
                    "name": f"Performance Entity {ordinal:05d}, Lda",
                    "nipc": f"8{ordinal:08d}"[-9:],
                    "seat": "Lisboa",
                    "kind": "SociedadePorQuotas",
                    "allow_invalid_nipc": True,
                },
            }
    elif kind == "books":
        entity_count = counts["entities"]
        for ordinal in range(count):
            yield {
                "kind": "book",
                "ordinal": ordinal,
                "entity_ordinal": ordinal % entity_count,
                "request": {
                    "kind": "AssembleiaGeral",
                    "purpose": f"Performance capacity book {ordinal:05d}",
                    "opening_date": "2026-01-15",
                    "required_signatories": ["Administrador"],
                    "one_shot": True,
                    "actor": "perf-harness",
                },
            }
    elif kind == "signatures":
        book_count = counts["books"]
        for ordinal in range(count):
            yield {
                "kind": "signature_subject",
                "ordinal": ordinal,
                "book_ordinal": ordinal % book_count,
                "realization": "unsigned-act-signature-status",
                "request": {
                    "title": f"Performance Signature Subject {ordinal:05d}",
                    "channel": "Physical",
                    "actor": "perf-harness",
                },
            }
    else:
        raise HarnessError(f"unknown dataset kind {kind}")


def stream_jsonl(path: pathlib.Path, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    with path.open("wb") as handle:
        for record in records:
            line = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            handle.write(line)
            digest.update(line)
            count += 1
    return {"count": count, "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def generate_dataset(profile_path: pathlib.Path, output_dir: pathlib.Path) -> dict[str, Any]:
    profile = read_json(profile_path)
    validate_profile(profile)
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = profile["dataset"]
    files: dict[str, Any] = {}
    for kind, filename in DATASET_FILES.items():
        files[kind] = {
            "path": filename,
            **stream_jsonl(
                output_dir / filename,
                dataset_records(kind, counts[kind], counts),
            ),
        }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "profile": profile["name"],
        "seed": profile["seed"],
        "counts": dict(counts),
        "files": files,
        "signature_realization": {
            "kind": "unsigned-act-signature-status",
            "claim": "signature-shaped API workload only; not cryptographic/provider signing capacity",
        },
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest


def validate_dataset(output_dir: pathlib.Path) -> dict[str, Any]:
    manifest = read_json(output_dir / "manifest.json")
    failures: list[str] = []
    observed: dict[str, Any] = {}
    for kind, expected in manifest["files"].items():
        path = output_dir / expected["path"]
        digest = hashlib.sha256()
        count = 0
        bytes_seen = 0
        if not path.is_file():
            failures.append(f"missing {path}")
            continue
        with path.open("rb") as handle:
            for raw in handle:
                bytes_seen += len(raw)
                digest.update(raw)
                count += 1
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError as error:
                    failures.append(f"{path}:{count}: invalid JSON: {error}")
                    continue
                if record.get("ordinal") != count - 1:
                    failures.append(f"{path}:{count}: non-contiguous ordinal")
        observed[kind] = {
            "count": count,
            "sha256": digest.hexdigest(),
            "bytes": bytes_seen,
        }
        for field in ("count", "sha256", "bytes"):
            if observed[kind][field] != expected[field]:
                failures.append(
                    f"{kind}.{field}: expected {expected[field]!r}, observed {observed[kind][field]!r}"
                )
    for name, count in manifest["counts"].items():
        if name in observed and observed[name]["count"] != count:
            failures.append(f"{name}: manifest count {count}, file count {observed[name]['count']}")
    result = {"valid": not failures, "failures": failures, "observed": observed}
    if failures:
        raise HarnessError("dataset validation failed: " + "; ".join(failures[:10]))
    return result


def iter_jsonl(path: pathlib.Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise HarnessError(f"{path}:{line_number}: {error}") from error
            if not isinstance(value, dict):
                raise HarnessError(f"{path}:{line_number}: record is not an object")
            yield value


@dataclasses.dataclass
class HttpResult:
    status: int | None
    latency_ms: float
    body: bytes
    error: str | None = None


class ApiClient:
    def __init__(self, base_url: str, timeout: float, session_token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session_token = session_token

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        authenticated: bool = True,
    ) -> HttpResult:
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {"accept": "application/json", "user-agent": "chancela-perf-harness/1"}
        if payload is not None:
            headers["content-type"] = "application/json"
        if authenticated and self.session_token:
            headers["x-chancela-session"] = self.session_token
        request = urllib.request.Request(
            self.base_url + path,
            data=payload,
            headers=headers,
            method=method,
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return HttpResult(
                    response.status,
                    (time.perf_counter() - started) * 1000.0,
                    response.read(),
                )
        except urllib.error.HTTPError as error:
            return HttpResult(
                error.code,
                (time.perf_counter() - started) * 1000.0,
                error.read(),
                f"HTTP {error.code}",
            )
        except Exception as error:  # network failures are evidence, not harness crashes
            return HttpResult(
                None,
                (time.perf_counter() - started) * 1000.0,
                b"",
                f"{type(error).__name__}: {error}",
            )


def decode_json(result: HttpResult, context: str) -> dict[str, Any]:
    try:
        value = json.loads(result.body)
    except Exception as error:
        raise HarnessError(
            f"{context}: status={result.status}, response is not JSON: {result.body[:300]!r}"
        ) from error
    if not isinstance(value, dict):
        raise HarnessError(f"{context}: response is not an object")
    return value


def safe_retry_request(
    client: ApiClient,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    *,
    authenticated: bool = True,
    attempts: int = 8,
) -> HttpResult:
    """Retry only explicit pre-commit throttling/failover statuses.

    Ambiguous network errors and 5xx are never retried for POST because a commit
    may have happened before the connection broke.
    """
    for attempt in range(attempts):
        result = client.request(method, path, body, authenticated=authenticated)
        if result.status not in {429, 503}:
            return result
        if attempt + 1 < attempts:
            time.sleep(min(5.0, 0.1 * (2**attempt)))
    return result


def _settings_without_tsa_or_server_metadata(
    document: dict[str, Any],
) -> dict[str, Any]:
    """Normalize fields intentionally changed or re-stamped by the server.

    The performance harness uses the whole-document settings API because there
    is no narrow TSA-disable endpoint. The request must preserve every
    operator-authored field. GET/PUT may legitimately re-stamp the provider
    inventory and connector environment ceiling, so those server-owned values
    are excluded from the preservation comparison alongside the two TSA fields
    the harness deliberately clears.
    """

    normalized = copy.deepcopy(document)
    signing = normalized.get("signing")
    if isinstance(signing, dict):
        signing["tsa_url"] = "<performance-tsa-override>"
        signing["tsa_providers"] = "<performance-tsa-override>"
        signing["providers"] = "<server-owned>"
    connectors = normalized.get("connectors")
    if isinstance(connectors, dict):
        connectors["environment_ceiling"] = "<server-owned>"
    return normalized


def _decode_settings_document(result: HttpResult, context: str) -> dict[str, Any]:
    """Decode settings without copying response contents into proof evidence."""

    try:
        value = json.loads(result.body)
    except Exception as error:
        raise HarnessError(
            f"{context}: status={result.status}, response is not valid JSON"
        ) from error
    if not isinstance(value, dict):
        raise HarnessError(
            f"{context}: status={result.status}, response is not an object"
        )
    return value


def disable_external_timestamping_for_local_signing(
    client: ApiClient,
    *,
    attempts: int = TSA_SETTINGS_READ_ATTEMPTS,
) -> dict[str, Any]:
    """Disable TSA selection in the fresh disposable performance topology.

    Local-PKCS#12 capacity explicitly excludes TSA capacity. A fresh Chancela
    instance nevertheless defaults to a public TSA, so leaving settings alone
    would make every measured local signature depend on that external service.
    Read retries are bounded and idempotent because a just-created clustered
    session can briefly reach a follower before its authorization view catches
    up. The whole-document PUT is routed to the leader by the performance
    gateway and uses the existing safe pre-commit retry policy.
    """

    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1:
        raise HarnessError("TSA settings read attempts must be a positive integer")

    get_statuses: list[int | None] = []
    current_result: HttpResult | None = None
    for attempt in range(attempts):
        current_result = client.request("GET", "/v1/settings")
        get_statuses.append(current_result.status)
        if current_result.status == 200:
            break
        if current_result.status not in TSA_SETTINGS_READ_RETRY_STATUSES:
            break
        if attempt + 1 < attempts:
            time.sleep(min(1.0, 0.1 * (attempt + 1)))

    if current_result is None or current_result.status != 200:
        raise HarnessError(
            "could not read settings before local cryptographic signing; "
            f"statuses={get_statuses}"
        )

    current = _decode_settings_document(
        current_result,
        "local signing TSA settings read",
    )
    updated = copy.deepcopy(current)
    signing = updated.get("signing")
    if not isinstance(signing, dict):
        raise HarnessError(
            "settings document has no signing object; refusing local cryptographic signing"
        )
    providers = signing.get("tsa_providers")
    if not isinstance(providers, list):
        raise HarnessError(
            "settings signing.tsa_providers is not an array; "
            "refusing local cryptographic signing"
        )

    before_tsa_configured = signing.get("tsa_url") is not None or bool(providers)
    before_provider_count = len(providers)
    signing["tsa_url"] = None
    signing["tsa_providers"] = []
    request_preserved = _settings_without_tsa_or_server_metadata(
        current
    ) == _settings_without_tsa_or_server_metadata(updated)
    if not request_preserved:
        raise HarnessError(
            "local signing TSA override changed a non-TSA operator setting before PUT"
        )

    put_result = safe_retry_request(
        client,
        "PUT",
        "/v1/settings",
        updated,
    )
    if put_result.status != 200:
        raise HarnessError(
            "could not disable TSA before local cryptographic signing; "
            f"status={put_result.status}"
        )
    committed = _decode_settings_document(
        put_result,
        "local signing TSA settings write",
    )
    committed_signing = committed.get("signing")
    if not isinstance(committed_signing, dict):
        raise HarnessError(
            "settings PUT response has no signing object; "
            "refusing local cryptographic signing"
        )

    tsa_disabled = (
        committed_signing.get("tsa_url") is None
        and committed_signing.get("tsa_providers") == []
    )
    non_tsa_settings_preserved = (
        request_preserved
        and _settings_without_tsa_or_server_metadata(updated)
        == _settings_without_tsa_or_server_metadata(committed)
    )
    if not tsa_disabled or not non_tsa_settings_preserved:
        raise HarnessError(
            "settings PUT did not disable both TSA selectors while preserving "
            "non-TSA operator settings"
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "disabled_for_local_pkcs12_capacity",
        "ordering": "after_seed_and_search_before_cryptographic_signing",
        "get_attempts": len(get_statuses),
        "get_statuses": get_statuses,
        "put_status": put_result.status,
        "before_tsa_configured": before_tsa_configured,
        "before_tsa_provider_count": before_provider_count,
        "effective_tsa_configured": False,
        "effective_tsa_provider_count": 0,
        "non_tsa_settings_preserved": True,
        "comparison_excludes_server_owned_metadata": True,
        "tsa_disabled": True,
    }


@dataclasses.dataclass
class SeedStage:
    requested: int
    created: int = 0
    statuses: Counter = dataclasses.field(default_factory=Counter)
    errors: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    duration_seconds: float = 0.0

    def record(self, ordinal: int, result: HttpResult, expected: set[int]) -> None:
        self.statuses[str(result.status)] += 1
        if result.status in expected:
            self.created += 1
        elif len(self.errors) < 50:
            self.errors.append(
                {
                    "ordinal": ordinal,
                    "status": result.status,
                    "error": result.error,
                    "body": result.body[:300].decode("utf-8", "replace"),
                }
            )

    def report(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "created": self.created,
            "exact": self.requested == self.created,
            "duration_seconds": round(self.duration_seconds, 3),
            "throughput_per_second": round(
                self.created / max(self.duration_seconds, 0.000001), 3
            ),
            "statuses": dict(self.statuses),
            "errors": self.errors,
        }


def parallel_seed(
    records: Iterable[dict[str, Any]],
    requested: int,
    concurrency: int,
    create: Callable[[dict[str, Any]], tuple[int, HttpResult, str | None]],
    expected: set[int],
) -> tuple[SeedStage, list[str]]:
    stage = SeedStage(requested=requested)
    identifiers: dict[int, str] = {}
    started = time.perf_counter()
    lock = threading.Lock()

    def task(record: dict[str, Any]) -> None:
        ordinal, result, identifier = create(record)
        with lock:
            stage.record(ordinal, result, expected)
            if identifier is not None:
                identifiers[ordinal] = identifier

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(task, record) for record in records]
        for future in concurrent.futures.as_completed(futures):
            future.result()
    stage.duration_seconds = time.perf_counter() - started
    return stage, [identifiers[key] for key in sorted(identifiers)]


def seed_dataset(
    dataset_dir: pathlib.Path,
    client: ApiClient,
    profile: dict[str, Any],
    password: str,
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    manifest = read_json(dataset_dir / "manifest.json")
    concurrency = int(profile["seed_concurrency"])
    stages: dict[str, Any] = {}

    user_records = iter_jsonl(dataset_dir / DATASET_FILES["users"])
    owner_record = next(user_records)
    owner_request = dict(owner_record["request"])
    owner_request["password"] = password
    started = time.perf_counter()
    owner_result = safe_retry_request(
        client, "POST", "/v1/users", owner_request, authenticated=False
    )
    owner_stage = SeedStage(requested=1)
    owner_stage.record(0, owner_result, {200, 201})
    owner_stage.duration_seconds = time.perf_counter() - started
    if owner_stage.created != 1:
        raise HarnessError(f"bootstrap user failed: {owner_stage.report()}")
    owner = decode_json(owner_result, "bootstrap user")

    login = client.request(
        "POST",
        "/v1/session",
        {"user_id": owner["id"], "password": password},
        authenticated=False,
    )
    if login.status not in {200, 201}:
        raise HarnessError(
            f"bootstrap login failed: status={login.status}, body={login.body[:300]!r}"
        )
    client.session_token = decode_json(login, "bootstrap login")["token"]

    def create_user(record: dict[str, Any]) -> tuple[int, HttpResult, str | None]:
        request = dict(record["request"])
        request["password"] = password
        result = safe_retry_request(client, "POST", "/v1/users", request)
        identifier = None
        if result.status in {200, 201}:
            identifier = decode_json(result, f"user {record['ordinal']}").get("id")
        return record["ordinal"], result, identifier

    user_stage, user_ids_tail = parallel_seed(
        user_records,
        manifest["counts"]["users"] - 1,
        concurrency,
        create_user,
        {200, 201},
    )
    # parallel_seed uses ordinals starting at 1, so retain a compact exact list separately.
    user_ids = [owner["id"]] + [item for item in user_ids_tail if item]
    combined_users = user_stage.report()
    combined_users["requested"] += 1
    combined_users["created"] += 1
    combined_users["exact"] = combined_users["requested"] == combined_users["created"]
    combined_users["duration_seconds"] = round(
        combined_users["duration_seconds"] + owner_stage.duration_seconds, 3
    )
    stages["users"] = combined_users

    def create_entity(record: dict[str, Any]) -> tuple[int, HttpResult, str | None]:
        result = safe_retry_request(client, "POST", "/v1/entities", record["request"])
        identifier = None
        if result.status in {200, 201}:
            identifier = decode_json(result, f"entity {record['ordinal']}").get("id")
        return record["ordinal"], result, identifier

    entity_stage, entity_ids_optional = parallel_seed(
        iter_jsonl(dataset_dir / DATASET_FILES["entities"]),
        manifest["counts"]["entities"],
        concurrency,
        create_entity,
        {200, 201},
    )
    stages["entities"] = entity_stage.report()
    if not stages["entities"]["exact"]:
        raise HarnessError("entity seed was not exact; refusing dependent book seed")
    entity_ids = [str(value) for value in entity_ids_optional if value]

    def create_book(record: dict[str, Any]) -> tuple[int, HttpResult, str | None]:
        request = dict(record["request"])
        request["entity_id"] = entity_ids[record["entity_ordinal"]]
        result = safe_retry_request(client, "POST", "/v1/books", request)
        identifier = None
        if result.status in {200, 201}:
            identifier = decode_json(result, f"book {record['ordinal']}").get("id")
        return record["ordinal"], result, identifier

    book_stage, book_ids_optional = parallel_seed(
        iter_jsonl(dataset_dir / DATASET_FILES["books"]),
        manifest["counts"]["books"],
        concurrency,
        create_book,
        {200, 201},
    )
    stages["books"] = book_stage.report()
    if not stages["books"]["exact"]:
        raise HarnessError("book seed was not exact; refusing dependent signature-subject seed")
    book_ids = [str(value) for value in book_ids_optional if value]

    def create_signature_subject(
        record: dict[str, Any],
    ) -> tuple[int, HttpResult, str | None]:
        request = dict(record["request"])
        request["book_id"] = book_ids[record["book_ordinal"]]
        result = safe_retry_request(client, "POST", "/v1/acts", request)
        identifier = None
        if result.status in {200, 201}:
            identifier = decode_json(result, f"signature subject {record['ordinal']}").get("id")
        return record["ordinal"], result, identifier

    signature_stage, signature_ids_optional = parallel_seed(
        iter_jsonl(dataset_dir / DATASET_FILES["signatures"]),
        manifest["counts"]["signatures"],
        concurrency,
        create_signature_subject,
        {200, 201},
    )
    signature_report = signature_stage.report()
    signature_report["realization"] = "unsigned-act-signature-status"
    signature_report["cryptographic_signatures_created"] = 0
    stages["signatures"] = signature_report
    signature_ids = [str(value) for value in signature_ids_optional if value]

    index = {
        "users": user_ids,
        "entities": entity_ids,
        "books": book_ids,
        "signatures": signature_ids,
    }
    exact = all(stage["exact"] for stage in stages.values())
    return (
        {
            "exact": exact,
            "stages": stages,
            "coverage_gap": (
                "The signatures stage creates unsigned acts and exercises signature status. "
                "It does not create cryptographic signatures or measure QTSP, smart-card, "
                "timestamp, revocation, or validator capacity."
            ),
        },
        index,
    )


class Reservoir:
    def __init__(self, limit: int, rng: random.Random):
        self.limit = max(1, limit)
        self.rng = rng
        self.seen = 0
        self.values: list[float] = []

    def add(self, value: float) -> None:
        self.seen += 1
        if len(self.values) < self.limit:
            self.values.append(value)
            return
        replacement = self.rng.randrange(self.seen)
        if replacement < self.limit:
            self.values[replacement] = value


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * quantile
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    fraction = rank - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


@dataclasses.dataclass
class OperationStats:
    reservoir: Reservoir
    requests: int = 0
    errors: int = 0
    status_counts: Counter = dataclasses.field(default_factory=Counter)
    error_samples: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    def record(self, result: HttpResult, expected: set[int]) -> None:
        self.requests += 1
        self.reservoir.add(result.latency_ms)
        self.status_counts[str(result.status)] += 1
        if result.status not in expected:
            self.errors += 1
            if len(self.error_samples) < 20:
                self.error_samples.append(
                    {
                        "status": result.status,
                        "error": result.error,
                        "body": result.body[:200].decode("utf-8", "replace"),
                    }
                )

    def report(self) -> dict[str, Any]:
        values = self.reservoir.values
        return {
            "requests": self.requests,
            "errors": self.errors,
            "error_rate": self.errors / self.requests if self.requests else 0.0,
            "p50_ms": percentile(values, 0.50),
            "p95_ms": percentile(values, 0.95),
            "p99_ms": percentile(values, 0.99),
            "max_ms": max(values) if values else None,
            "latency_samples": len(values),
            "latency_population": self.reservoir.seen,
            "latency_sampling": "exact" if len(values) == self.reservoir.seen else "reservoir",
            "statuses": dict(self.status_counts),
            "error_samples": self.error_samples,
        }


def active_clients(mode: str, elapsed: float, duration: float, clients: int) -> int:
    if mode in {"steady", "soak"}:
        return clients
    progress = min(1.0, max(0.0, elapsed / max(duration, 0.001)))
    if mode == "ramp":
        return max(1, min(clients, 1 + int(progress * clients)))
    if mode == "spike":
        baseline = max(1, clients // 4)
        return clients if 0.40 <= progress <= 0.60 else baseline
    raise HarnessError(f"unknown mode {mode}")


def workload_phase_and_clients(
    workload: dict[str, Any], elapsed: float
) -> tuple[str, int]:
    clients = int(workload["clients"])
    if not all(field in workload for field in WORKLOAD_PHASES):
        return (
            f"legacy_{workload['mode']}",
            active_clients(
                workload["mode"],
                elapsed,
                float(workload["duration_seconds"]),
                clients,
            ),
        )

    warmup = float(workload["warmup_seconds"])
    ramp = float(workload["ramp_seconds"])
    plateau = float(workload["peak_plateau_seconds"])
    cooldown = float(workload["cooldown_seconds"])
    baseline = max(1, clients // 4)
    if elapsed < warmup:
        return "warmup", baseline
    elapsed -= warmup
    if elapsed < ramp:
        progress = elapsed / max(ramp, 0.001)
        active = baseline + int(progress * (clients - baseline))
        return "ramp", max(baseline, min(clients, active))
    elapsed -= ramp
    if elapsed < plateau:
        return "peak_plateau", clients
    elapsed -= plateau
    if elapsed < cooldown:
        progress = elapsed / max(cooldown, 0.001)
        active = clients - int(progress * (clients - baseline))
        return "cooldown", max(baseline, min(clients, active))
    return "complete", baseline


def workload_phase_report(workload: dict[str, Any], elapsed: float) -> dict[str, Any]:
    if not all(field in workload for field in WORKLOAD_PHASES):
        return {
            "model": "legacy",
            "peak_plateau_complete": False,
            "proof_boundary": (
                "Legacy mode has no explicit sustained peak plateau and is evidence only."
            ),
        }
    configured = {field: float(workload[field]) for field in WORKLOAD_PHASES}
    plateau_start = configured["warmup_seconds"] + configured["ramp_seconds"]
    plateau_end = plateau_start + configured["peak_plateau_seconds"]
    observed_plateau = max(0.0, min(elapsed, plateau_end) - plateau_start)
    complete = observed_plateau + 0.001 >= configured["peak_plateau_seconds"]
    return {
        "model": "explicit",
        "configured": configured,
        "peak_plateau_observed_seconds": observed_plateau,
        "peak_plateau_complete": complete,
        "proof_boundary": (
            "Closed-loop concurrency was sustained for the recorded plateau; "
            "this does not establish an open-loop arrival-rate ceiling."
        ),
    }


def weighted_operations(weights: dict[str, int]) -> list[str]:
    operations: list[str] = []
    for name, weight in sorted(weights.items()):
        operations.extend([name] * weight)
    return operations


def parse_size_bytes(value: str) -> float:
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?i?B)\s*", value)
    if not match:
        raise ValueError(f"unsupported size {value!r}")
    number = float(match.group(1))
    units = {
        "B": 1,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
        "TiB": 1024**4,
    }
    return number * units[match.group(2)]


def docker_snapshot(project_name: str) -> list[dict[str, Any]]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project_name):
        return []
    try:
        discovered = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--format",
                "{{.ID}}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        identifiers = [
            identifier.strip()
            for identifier in discovered.stdout.splitlines()
            if identifier.strip()
        ]
        if discovered.returncode != 0 or not identifiers:
            return []
        completed = subprocess.run(
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{json .}}",
                *identifiers,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    samples: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = row.get("Name") or row.get("Container")
        if not name:
            continue
        try:
            cpu = float(str(row.get("CPUPerc", "0")).rstrip("%"))
            memory_text = str(row.get("MemUsage", "0B / 0B")).split("/", 1)[0].strip()
            memory = parse_size_bytes(memory_text)
        except (ValueError, TypeError):
            continue
        samples.append(
            {
                "container": name,
                "cpu_percent": cpu,
                "memory_bytes": memory,
                "at": utc_now(),
            }
        )
    return samples


class ResourceSampler:
    def __init__(
        self,
        interval_seconds: float = 5.0,
        project_name: str | None = None,
    ):
        self.interval_seconds = interval_seconds
        self.project_name = project_name or os.environ.get(
            "CHANCELA_PERF_PROJECT_NAME",
            "chancela-perf",
        )
        self.stop = threading.Event()
        self.samples: list[dict[str, Any]] = []
        self.thread: threading.Thread | None = None
        self.phase = "startup"
        self.lock = threading.Lock()

    def set_phase(self, phase: str) -> None:
        with self.lock:
            self.phase = phase

    def sample_now(self) -> None:
        snapshots = docker_snapshot(self.project_name)
        with self.lock:
            phase = self.phase
            for sample in snapshots:
                self.samples.append({**sample, "phase": phase})

    def start(self) -> None:
        def loop() -> None:
            while not self.stop.is_set():
                self.sample_now()
                self.stop.wait(self.interval_seconds)

        self.thread = threading.Thread(target=loop, name="resource-sampler", daemon=True)
        self.thread.start()

    @staticmethod
    def summarize(samples: list[dict[str, Any]]) -> dict[str, Any]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for sample in samples:
            grouped[sample["container"]].append(sample)
        containers = {}
        for name, container_samples in grouped.items():
            containers[name] = {
                "samples": len(container_samples),
                "max_cpu_percent": max(item["cpu_percent"] for item in container_samples),
                "avg_cpu_percent": sum(
                    item["cpu_percent"] for item in container_samples
                )
                / len(container_samples),
                "max_memory_bytes": max(
                    item["memory_bytes"] for item in container_samples
                ),
            }
        return containers

    def report(self) -> dict[str, Any]:
        with self.lock:
            samples = list(self.samples)
        by_phase: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for sample in samples:
            by_phase[str(sample.get("phase", "unknown"))].append(sample)
        return {
            "sampler": "docker stats",
            "compose_project": self.project_name,
            "available": bool(samples),
            "interval_seconds": self.interval_seconds,
            "sample_count": len(samples),
            "containers": self.summarize(samples),
            "phases": {
                phase: {
                    "sample_count": len(phase_samples),
                    "containers": self.summarize(phase_samples),
                }
                for phase, phase_samples in sorted(by_phase.items())
            },
        }

    def finish(self) -> dict[str, Any]:
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=self.interval_seconds + 2)
        return self.report()


def phase_resource_maxima(
    resources: dict[str, Any], phase: str
) -> tuple[float | None, float | None]:
    containers = (
        resources.get("phases", {}).get(phase, {}).get("containers", {}).values()
    )
    containers = list(containers)
    max_memory = max(
        (item.get("max_memory_bytes") for item in containers),
        default=None,
    )
    max_cpu = max(
        (item.get("max_cpu_percent") for item in containers),
        default=None,
    )
    return max_memory, max_cpu


def cryptographic_exactness_blocker(
    cryptographic_signing: dict[str, Any],
) -> str | None:
    if not cryptographic_signing.get("enabled"):
        return None
    requested = cryptographic_signing.get("requested")
    signed = cryptographic_signing.get("signed")
    if (
        cryptographic_signing.get("exact") is True
        and isinstance(requested, int)
        and not isinstance(requested, bool)
        and isinstance(signed, int)
        and not isinstance(signed, bool)
        and signed == requested
    ):
        return None
    return (
        "Cryptographic signing did not complete the exact requested volume "
        f"(requested={requested!r}, signed={signed!r}, "
        f"exact={cryptographic_signing.get('exact')!r})."
    )


def capture_final_topology(
    initial: dict[str, Any],
    output: pathlib.Path,
) -> dict[str, Any]:
    summary = initial.get("summary")
    if not isinstance(summary, dict):
        raise HarnessError("initial topology evidence has no summary object")
    compose_files = summary.get("compose_files")
    profiles = summary.get("profiles")
    project_name = summary.get("project_name")
    expected_replicas = summary.get("expected_app_replicas")
    if (
        not isinstance(compose_files, list)
        or not compose_files
        or any(not isinstance(item, str) or not item for item in compose_files)
    ):
        raise HarnessError("initial topology evidence has no valid compose-file list")
    if not isinstance(profiles, list) or any(
        not isinstance(item, str) or not item for item in profiles
    ):
        raise HarnessError("initial topology evidence has no valid profile list")
    if not isinstance(project_name, str) or not project_name:
        raise HarnessError("initial topology evidence has no Compose project name")
    if (
        isinstance(expected_replicas, bool)
        or not isinstance(expected_replicas, int)
        or not 1 <= expected_replicas <= 9
    ):
        raise HarnessError("initial topology evidence has invalid expected replicas")
    try:
        import topology as topology_capture

        final = topology_capture.capture(
            [pathlib.Path(item) for item in compose_files],
            profiles,
            expected_replicas,
            project_name,
        )
        topology_capture.write_json(output, final)
    except Exception as error:
        if isinstance(error, HarnessError):
            raise
        raise HarnessError(f"final topology capture failed: {error}") from error
    return final


def _topology_container_ids(
    snapshot: dict[str, Any],
    service: str,
) -> set[str]:
    containers = snapshot.get("containers", {})
    if not isinstance(containers, dict):
        return set()
    service_containers = containers.get(service, [])
    if not isinstance(service_containers, list):
        return set()
    return {
        str(container.get("id"))
        for container in service_containers
        if isinstance(container, dict) and container.get("id")
    }


def combine_topology_evidence(
    initial: dict[str, Any],
    final: dict[str, Any],
) -> dict[str, Any]:
    failures: list[str] = []
    if initial.get("preflight_passed") is not True:
        failures.extend(
            f"initial: {failure}"
            for failure in initial.get("failures", ["topology preflight did not pass"])
        )
    if final.get("preflight_passed") is not True:
        failures.extend(
            f"final: {failure}"
            for failure in final.get("failures", ["topology final check did not pass"])
        )
    for service in (
        "chancela-cluster",
        "search-projector-postgres",
        "postgres",
        "redis",
        "perf-gateway",
    ):
        initial_ids = _topology_container_ids(initial, service)
        final_ids = _topology_container_ids(final, service)
        if initial_ids != final_ids:
            failures.append(
                f"{service} container set changed during the run "
                f"(initial={sorted(initial_ids)}, final={sorted(final_ids)})"
            )
    return {
        "preflight_passed": not failures,
        "stable": not failures,
        "failures": failures,
        "initial": initial,
        "final": final,
        "summary": {
            "project_name": initial.get("summary", {}).get("project_name"),
            "initial_app_replicas": initial.get("summary", {}).get("app_replicas"),
            "final_app_replicas": final.get("summary", {}).get("app_replicas"),
            "expected_app_replicas": initial.get("summary", {}).get(
                "expected_app_replicas"
            ),
            "aggregate_resource_envelope": initial.get("summary", {}).get(
                "aggregate_resource_envelope"
            ),
        },
    }


def search_path(params: dict[str, Any]) -> str:
    return "/v1/search?" + urllib.parse.urlencode(
        {key: value for key, value in params.items() if value is not None}
    )


def known_search_probes(index: dict[str, list[str]]) -> list[dict[str, Any]]:
    required = {"entities": "entity", "books": "book", "signatures": "act"}
    missing = [family for family in required if not index.get(family)]
    if missing:
        raise HarnessError(
            "search readiness requires seeded identifiers for " + ", ".join(missing)
        )
    return [
        {
            "family": "entities",
            "kind": "entity",
            "query": "Performance Entity 00000",
            "relation_key": "entity_id",
            "expected_id": index["entities"][0],
        },
        {
            "family": "books",
            "kind": "book",
            "query": index["books"][0],
            "relation_key": "book_id",
            "expected_id": index["books"][0],
        },
        {
            "family": "signatures",
            "kind": "act",
            "query": "Performance Signature Subject 00000",
            "relation_key": "act_id",
            "expected_id": index["signatures"][0],
        },
    ]


def search_probe(client: ApiClient, probe: dict[str, Any]) -> dict[str, Any]:
    result = client.request(
        "GET",
        search_path({"q": probe["query"], "kind": probe["kind"], "limit": 10}),
    )
    report: dict[str, Any] = {
        "kind": probe["kind"],
        "query": probe["query"],
        "expected_id": probe["expected_id"],
        "status": result.status,
        "latency_ms": result.latency_ms,
        "matched": False,
    }
    if result.status != 200:
        report["error"] = result.error
        report["body"] = result.body[:300].decode("utf-8", "replace")
        return report
    response = decode_json(result, f"search readiness {probe['kind']}")
    page = response.get("page") if isinstance(response.get("page"), dict) else {}
    hits = page.get("hits") if isinstance(page.get("hits"), list) else []
    matching = [
        hit
        for hit in hits
        if isinstance(hit, dict)
        and hit.get(probe["relation_key"]) == probe["expected_id"]
    ]
    report.update(
        {
            "matched": bool(matching),
            "total": page.get("total"),
            "returned": len(hits),
            "facets_truncated": page.get("facets_truncated"),
            "pagination_truncated": response.get("pagination_truncated"),
            "next_cursor": response.get("next_cursor"),
            "generation": (
                response.get("index", {}).get("generation")
                if isinstance(response.get("index"), dict)
                else None
            ),
        }
    )
    return report


def search_pagination_probe(
    client: ApiClient,
    expected_generation: int,
) -> dict[str, Any]:
    first = client.request(
        "GET",
        search_path({"q": "Performance", "kind": "entity,book,act", "limit": 1}),
    )
    if first.status != 200:
        return {
            "status": first.status,
            "error": first.error,
            "body": first.body[:300].decode("utf-8", "replace"),
            "cursor_exercised": False,
        }
    first_response = decode_json(first, "search pagination first page")
    first_page = (
        first_response.get("page")
        if isinstance(first_response.get("page"), dict)
        else {}
    )
    cursor = first_response.get("next_cursor")
    first_hits = (
        first_page.get("hits") if isinstance(first_page.get("hits"), list) else []
    )
    first_generation = (
        first_response.get("index", {}).get("generation")
        if isinstance(first_response.get("index"), dict)
        else None
    )
    report: dict[str, Any] = {
        "status": first.status,
        "latency_ms": first.latency_ms,
        "total": first_page.get("total"),
        "offset": first_page.get("offset"),
        "limit": first_page.get("limit"),
        "has_more": first_page.get("has_more"),
        "returned": len(first_hits),
        "generation": first_generation,
        "facets_truncated": first_page.get("facets_truncated"),
        "pagination_truncated": first_response.get("pagination_truncated"),
        "next_cursor": cursor,
        "cursor_exercised": False,
    }
    first_total = first_page.get("total")
    first_offset = first_page.get("offset")
    first_limit = first_page.get("limit")
    first_has_more = first_page.get("has_more")
    if not first_hits:
        report["error"] = "broad seeded search returned an empty first page"
        return report
    if (
        isinstance(first_total, bool)
        or not isinstance(first_total, int)
        or first_total < 2
        or first_total < len(first_hits)
    ):
        report["error"] = "broad seeded search returned an incoherent first-page total"
        return report
    if first_offset != 0 or first_limit != 1:
        report["error"] = "broad seeded search returned incoherent first-page bounds"
        return report
    if first_has_more is not True or not isinstance(cursor, str) or not cursor:
        report["error"] = (
            "broad seeded search must report has_more=true with a nonempty cursor"
        )
        return report
    if first_generation != expected_generation:
        report["error"] = (
            "broad seeded search generation changed before the cursor probe "
            f"({first_generation!r} != {expected_generation!r})"
        )
        return report
    second = client.request(
        "GET",
        search_path(
            {
                "q": "Performance",
                "kind": "entity,book,act",
                "limit": 1,
                "cursor": cursor,
            }
        ),
    )
    report["second_status"] = second.status
    report["second_latency_ms"] = second.latency_ms
    if second.status == 200:
        second_response = decode_json(second, "search pagination second page")
        second_page = (
            second_response.get("page")
            if isinstance(second_response.get("page"), dict)
            else {}
        )
        second_hits = (
            second_page.get("hits")
            if isinstance(second_page.get("hits"), list)
            else []
        )
        second_cursor = second_response.get("next_cursor")
        second_generation = (
            second_response.get("index", {}).get("generation")
            if isinstance(second_response.get("index"), dict)
            else None
        )
        report["second_offset"] = second_page.get("offset")
        report["second_total"] = second_page.get("total")
        report["second_limit"] = second_page.get("limit")
        report["second_has_more"] = second_page.get("has_more")
        report["second_returned"] = len(second_hits)
        report["second_next_cursor"] = second_cursor
        report["second_generation"] = second_generation
        if not second_hits:
            report["error"] = "cursor search returned an empty second page"
            return report
        if second_page.get("offset") != len(first_hits) or second_page.get("limit") != 1:
            report["error"] = "cursor search returned incoherent second-page bounds"
            return report
        if second_page.get("total") != first_total:
            report["error"] = "cursor search changed total between pages"
            return report
        if second_generation != first_generation:
            report["error"] = "cursor search changed generation between pages"
            return report
        if json.dumps(first_hits[0], sort_keys=True) == json.dumps(
            second_hits[0],
            sort_keys=True,
        ):
            report["error"] = "cursor search repeated the first hit on the second page"
            return report
        expected_has_more = (
            second_page["offset"] + len(second_hits) < second_page["total"]
        )
        if second_page.get("has_more") is not expected_has_more:
            report["error"] = "cursor search returned incoherent second-page has_more"
            return report
        if expected_has_more:
            if (
                not isinstance(second_cursor, str)
                or not second_cursor
                or second_cursor == cursor
            ):
                report["error"] = (
                    "cursor search must advance to a distinct nonempty next cursor"
                )
                return report
        elif second_cursor is not None:
            report["error"] = "cursor search returned a cursor when has_more=false"
            return report
        report["cursor_exercised"] = True
    else:
        report["error"] = second.error
        report["body"] = second.body[:300].decode("utf-8", "replace")
    return report


def wait_for_search_ready(
    client: ApiClient,
    index: dict[str, list[str]],
    expected_minimum_documents: int,
    *,
    timeout_seconds: float,
    poll_seconds: float = 2.0,
) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + timeout_seconds
    attempts = 0
    last_status: dict[str, Any] | None = None
    last_probes: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        attempts += 1
        result = client.request("GET", "/v1/search/status")
        if result.status == 200:
            last_status = decode_json(result, "search readiness status")
            ready = (
                last_status.get("enabled") is True
                and last_status.get("phase") == "idle"
                and last_status.get("partial") is False
                and last_status.get("stale") is False
                and isinstance(last_status.get("generation"), int)
                and last_status["generation"] > 0
                and isinstance(last_status.get("document_count"), int)
                and last_status["document_count"] >= expected_minimum_documents
            )
            if ready:
                last_probes = [
                    search_probe(client, probe) for probe in known_search_probes(index)
                ]
                generation = last_status["generation"]
                if all(
                    probe["matched"] and probe.get("generation") == generation
                    for probe in last_probes
                ):
                    pagination = search_pagination_probe(client, generation)
                    if pagination.get("cursor_exercised"):
                        return {
                            "ready": True,
                            "attempts": attempts,
                            "duration_seconds": time.monotonic() - started,
                            "expected_minimum_documents": expected_minimum_documents,
                            "status": last_status,
                            "known_record_probes": last_probes,
                            "pagination_probe": pagination,
                        }
        time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))
    raise HarnessError(
        "search readiness timed out after "
        f"{timeout_seconds}s; expected at least {expected_minimum_documents} documents, "
        f"last_status={last_status!r}, last_probes={last_probes!r}"
    )


def execute_operation(
    name: str,
    client: ApiClient,
    index: dict[str, list[str]],
    rng: random.Random,
    password: str,
    write_ordinal: int,
) -> HttpResult:
    if name == "health":
        return client.request("GET", "/health", authenticated=False)
    if name == "entity_list":
        return client.request("GET", "/v1/entities")
    if name == "entity_get":
        return client.request("GET", f"/v1/entities/{rng.choice(index['entities'])}")
    if name == "book_list":
        return client.request("GET", "/v1/books")
    if name == "book_get":
        return client.request("GET", f"/v1/books/{rng.choice(index['books'])}")
    if name == "user_list":
        return client.request("GET", "/v1/users")
    if name == "auth_login":
        return client.request(
            "POST",
            "/v1/session",
            {"username": "perf-owner", "password": password},
            authenticated=False,
        )
    if name == "entity_write":
        return client.request(
            "POST",
            "/v1/entities",
            {
                "name": f"Performance Workload Entity {write_ordinal}",
                "nipc": f"7{write_ordinal % 100000000:08d}",
                "seat": "Porto",
                "kind": "SociedadePorQuotas",
                "allow_invalid_nipc": True,
            },
        )
    if name == "signature_status":
        return client.request(
            "GET", f"/v1/acts/{rng.choice(index['signatures'])}/signature"
        )
    if name == "search_status":
        return client.request("GET", "/v1/search/status")
    if name == "search_query":
        family = rng.choice(("entities", "books", "signatures"))
        ordinal = rng.randrange(len(index[family]))
        if family == "entities":
            query, kind = f"Performance Entity {ordinal:05d}", "entity"
        elif family == "books":
            query, kind = index["books"][ordinal], "book"
        else:
            query, kind = f"Performance Signature Subject {ordinal:05d}", "act"
        return client.request(
            "GET",
            search_path({"q": query, "kind": kind, "limit": 10}),
        )
    raise HarnessError(f"unimplemented operation {name}")


def run_workload(
    client: ApiClient,
    profile: dict[str, Any],
    index: dict[str, list[str]],
    password: str,
    resource_sampler: ResourceSampler | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    workload = profile["workload"]
    mode = workload["mode"]
    duration = float(workload["duration_seconds"])
    clients = int(workload["clients"])
    sample_limit = int(workload.get("max_latency_samples_per_operation", 200000))
    operations = weighted_operations(workload["weights"])
    operation_indexes = {
        "entity_get": "entities",
        "book_get": "books",
        "signature_status": "signatures",
        "search_query": "entities",
    }
    missing = [
        name
        for name in workload["weights"]
        if workload["weights"][name] > 0
        and name in operation_indexes
        and not index[operation_indexes[name]]
    ]
    if missing:
        raise HarnessError(f"workload cannot run; missing seeded identifiers for {missing}")

    lock = threading.Lock()
    stats: dict[str, OperationStats] = {
        name: OperationStats(Reservoir(sample_limit, random.Random(profile["seed"] + position)))
        for position, name in enumerate(sorted(set(operations)))
    }
    stop_at = time.monotonic() + duration
    started = time.monotonic()
    write_counter = 0
    active_trace: list[dict[str, Any]] = []
    phase_request_counts: Counter = Counter()
    trace_lock = threading.Lock()

    def worker(worker_id: int) -> None:
        nonlocal write_counter
        rng = random.Random(profile["seed"] + 10000 + worker_id)
        last_trace_second = -1
        while time.monotonic() < stop_at:
            elapsed = time.monotonic() - started
            phase, allowed = workload_phase_and_clients(workload, elapsed)
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
            with lock:
                write_counter += 1
                ordinal = write_counter
            result = execute_operation(operation, client, index, rng, password, ordinal)
            with lock:
                stats[operation].record(result, EXPECTED_SUCCESS[operation])
                phase_request_counts[phase] += 1

    sampler = resource_sampler or ResourceSampler()
    owns_sampler = resource_sampler is None
    sampler.set_phase("mixed_workload")
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
            "mode": mode,
            "duration_seconds": elapsed,
            "configured_clients": clients,
            "active_client_trace": active_trace,
            "phase_requests": dict(phase_request_counts),
            "phases": workload_phase_report(workload, elapsed),
            "requests": total,
            "errors": errors,
            "error_rate": errors / total if total else 0.0,
            "throughput_per_second": total / max(elapsed, 0.000001),
            "operations": operation_reports,
        },
        resources,
    )


def evaluate_slo(
    workload: dict[str, Any],
    resources: dict[str, Any],
    slo: dict[str, Any] | None,
    cryptographic_signing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if slo is None:
        return {
            "assessment": "not_configured",
            "configured_thresholds": 0,
            "checks": [],
            "proof_ready": False,
            "proof_blockers": ["No reviewed SLO file was supplied."],
            "message": "No SLO file supplied; measurements are evidence, not a pass.",
        }
    validate_slo_schema(slo)
    checks: list[dict[str, Any]] = []
    proof_blockers: list[str] = []

    def check(path: str, observed: float | None, threshold: Any, relation: str) -> None:
        if threshold is None:
            return
        if not isinstance(threshold, (int, float)):
            raise HarnessError(f"SLO {path} must be numeric or null")
        passed = observed is not None and (
            observed <= threshold if relation == "max" else observed >= threshold
        )
        checks.append(
            {
                "metric": path,
                "observed": observed,
                "threshold": threshold,
                "relation": relation,
                "passed": passed,
            }
        )

    global_slo = slo.get("global", {})
    resource_slo = slo.get("resources", {})
    operation_slo = slo.get("operations", {})
    missing_capacity_thresholds = sorted(
        path
        for path, threshold in (
            ("global.max_error_rate", global_slo.get("max_error_rate")),
            (
                "global.min_throughput_per_second",
                global_slo.get("min_throughput_per_second"),
            ),
            (
                "resources.max_container_memory_bytes",
                resource_slo.get("max_container_memory_bytes"),
            ),
            (
                "resources.max_container_cpu_percent",
                resource_slo.get("max_container_cpu_percent"),
            ),
        )
        if threshold is None
    )
    measured_operations = workload.get("operations", {})
    if not isinstance(measured_operations, dict) or not measured_operations:
        proof_blockers.append(
            "Capacity proof requires measured operations and a complete reviewed "
            "latency/error policy for them."
        )
    else:
        for operation in sorted(measured_operations):
            thresholds = operation_slo.get(operation, {})
            for field in sorted(SLO_OPERATION_FIELDS):
                if thresholds.get(field) is None:
                    missing_capacity_thresholds.append(
                        f"operations.{operation}.{field}"
                    )
    if missing_capacity_thresholds:
        proof_blockers.append(
            "Capacity proof requires a complete reviewed non-null "
            "latency/throughput/error/resource policy; missing: "
            + ", ".join(missing_capacity_thresholds)
        )

    check("global.error_rate", workload.get("error_rate"), global_slo.get("max_error_rate"), "max")
    check(
        "global.throughput_per_second",
        workload.get("throughput_per_second"),
        global_slo.get("min_throughput_per_second"),
        "min",
    )
    for operation, thresholds in operation_slo.items():
        observed = workload.get("operations", {}).get(operation, {})
        check(f"{operation}.p95_ms", observed.get("p95_ms"), thresholds.get("p95_ms"), "max")
        check(f"{operation}.p99_ms", observed.get("p99_ms"), thresholds.get("p99_ms"), "max")
        check(
            f"{operation}.error_rate",
            observed.get("error_rate"),
            thresholds.get("max_error_rate"),
            "max",
        )
    all_containers = resources.get("containers", {}).values()
    max_memory = max(
        (item["max_memory_bytes"] for item in all_containers), default=None
    )
    all_containers = resources.get("containers", {}).values()
    max_cpu = max((item["max_cpu_percent"] for item in all_containers), default=None)
    check(
        "resources.max_container_memory_bytes",
        max_memory,
        resource_slo.get("max_container_memory_bytes"),
        "max",
    )
    check(
        "resources.max_container_cpu_percent",
        max_cpu,
        resource_slo.get("max_container_cpu_percent"),
        "max",
    )
    cryptographic_signing = cryptographic_signing or {"enabled": False}
    if cryptographic_signing.get("enabled"):
        crypto_slo = slo.get("cryptographic_signing", {})
        if not isinstance(crypto_slo, dict):
            raise HarnessError("SLO cryptographic_signing must be an object")
        missing_crypto_thresholds = sorted(
            field for field in CRYPTO_SLO_FIELDS if crypto_slo.get(field) is None
        )
        if missing_crypto_thresholds:
            proof_blockers.append(
                "Cryptographic signing was requested but reviewed thresholds are missing: "
                + ", ".join(missing_crypto_thresholds)
            )
        exactness_blocker = cryptographic_exactness_blocker(cryptographic_signing)
        if exactness_blocker:
            proof_blockers.append(exactness_blocker)
        operation = cryptographic_signing.get("sign_operation", {})
        crypto_memory, crypto_cpu = phase_resource_maxima(
            resources, "cryptographic_signing"
        )
        check(
            "cryptographic_signing.completed",
            cryptographic_signing.get("signed"),
            crypto_slo.get("min_completed"),
            "min",
        )
        check(
            "cryptographic_signing.error_rate",
            operation.get("error_rate"),
            crypto_slo.get("max_error_rate"),
            "max",
        )
        check(
            "cryptographic_signing.throughput_per_second",
            cryptographic_signing.get("throughput_per_second"),
            crypto_slo.get("min_throughput_per_second"),
            "min",
        )
        check(
            "cryptographic_signing.p95_ms",
            operation.get("p95_ms"),
            crypto_slo.get("p95_ms"),
            "max",
        )
        check(
            "cryptographic_signing.p99_ms",
            operation.get("p99_ms"),
            crypto_slo.get("p99_ms"),
            "max",
        )
        check(
            "cryptographic_signing.duration_seconds",
            cryptographic_signing.get("duration_seconds"),
            crypto_slo.get("max_duration_seconds"),
            "max",
        )
        check(
            "cryptographic_signing.resources.max_memory_bytes",
            crypto_memory,
            crypto_slo.get("max_phase_memory_bytes"),
            "max",
        )
        check(
            "cryptographic_signing.resources.max_cpu_percent",
            crypto_cpu,
            crypto_slo.get("max_phase_cpu_percent"),
            "max",
        )

    resource_available = resources.get(
        "available", bool(resources.get("containers"))
    )
    if not resource_available:
        proof_blockers.append(
            "Docker resource sampling was unavailable; the run has no bounded resource evidence."
        )
    else:
        required_resource_phases = {"seed", "search_catch_up", "mixed_workload"}
        if cryptographic_signing.get("enabled"):
            required_resource_phases.add("cryptographic_signing")
        missing_resource_phases = sorted(
            phase
            for phase in required_resource_phases
            if not resources.get("phases", {})
            .get(phase, {})
            .get("containers")
        )
        if missing_resource_phases:
            proof_blockers.append(
                "Resource samples are missing for phases: "
                + ", ".join(missing_resource_phases)
            )
    phase_report = workload.get("phases", {})
    if phase_report.get("model") == "explicit":
        if not phase_report.get("peak_plateau_complete"):
            proof_blockers.append("The configured peak concurrency plateau did not complete.")
    else:
        proof_blockers.append(
            "The workload used legacy concurrency semantics without a sustained peak plateau."
        )

    failed_checks = [item for item in checks if not item["passed"]]
    if failed_checks:
        assessment = "failed"
        message = "At least one explicitly configured threshold failed."
    elif proof_blockers:
        assessment = "not_configured"
        message = (
            "Measurements completed, but proof prerequisites remain "
            "unconfigured or unavailable."
        )
    elif not checks:
        assessment = "not_configured"
        message = "SLO file contained only null thresholds; measurements are not a pass."
    else:
        assessment = "passed"
        message = "Every explicitly configured threshold passed."
    return {
        "assessment": assessment,
        "configured_thresholds": len(checks),
        "checks": checks,
        "proof_ready": assessment == "passed",
        "proof_blockers": proof_blockers,
        "message": message,
    }


def markdown_report(report: dict[str, Any]) -> str:
    dataset = report["dataset"]
    seed = report["seed"]
    workload = report["workload"]
    search_readiness = report["search_readiness"]
    cryptographic = report["cryptographic_signing"]
    timestamping = cryptographic.get("timestamping", {})
    resources = report["resources"]
    topology = report["topology"]
    duration_budget = report["duration_budget"]
    source = report["source"]
    lines = [
        "# Chancela performance evidence",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Profile: `{report['profile']}`",
        f"- Profile proof eligible: `{report['profile_proof_eligible']}`",
        f"- Source kind: `{source.get('kind')}`",
        f"- Source ref: `{source.get('ref')}`",
        f"- Source commit: `{source.get('commit_sha')}`",
        f"- Source proof eligible: `{source.get('proof_eligible')}`",
        f"- Local working tree dirty: `{source.get('working_tree_dirty')}`",
        f"- Workload mode: `{workload['mode']}`",
        f"- SLO assessment: `{report['slo']['assessment']}`",
        f"- Proof ready: `{report['slo'].get('proof_ready', False)}`",
        f"- Exact seed: `{seed['exact']}`",
        f"- Search ready: `{search_readiness['ready']}`",
        f"- Requests: `{workload['requests']}`",
        f"- Error rate: `{workload['error_rate']:.6f}`",
        f"- Throughput: `{workload['throughput_per_second']:.3f} req/s`",
        "",
        "## Exact-volume dataset",
        "",
        "| Kind | Count | SHA-256 | Seed realization |",
        "| --- | ---: | --- | --- |",
    ]
    for kind in DATASET_FILES:
        realization = (
            "unsigned act + signature-status route"
            if kind == "signatures"
            else "real API create"
        )
        lines.append(
            f"| {kind} | {dataset['counts'][kind]} | `{dataset['files'][kind]['sha256']}` | {realization} |"
        )
    lines.extend(
        [
            "",
            "## Workload measurements",
            "",
            "| Operation | Requests | Errors | Error rate | p50 ms | p95 ms | p99 ms | Samples |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, operation in workload["operations"].items():
        value = lambda key: (
            "n/a" if operation[key] is None else f"{operation[key]:.3f}"
        )
        lines.append(
            f"| {name} | {operation['requests']} | {operation['errors']} | "
            f"{operation['error_rate']:.6f} | {value('p50_ms')} | {value('p95_ms')} | "
            f"{value('p99_ms')} | {operation['latency_samples']} ({operation['latency_sampling']}) |"
        )
    status = search_readiness["status"]
    lines.extend(
        [
            "",
            "## Search projection",
            "",
            f"- Generation: `{status.get('generation')}`",
            f"- Documents: `{status.get('document_count')}`",
            f"- Indexed characters: `{status.get('indexed_content_chars')}`",
            f"- Content truncated: `{status.get('content_truncated')}`",
            f"- Truncated documents: `{status.get('truncated_document_count')}`",
            f"- Readiness duration: `{search_readiness['duration_seconds']:.3f}s`",
            f"- Cursor exercised: `{search_readiness['pagination_probe']['cursor_exercised']}`",
            f"- Facets truncated: `{search_readiness['pagination_probe'].get('facets_truncated')}`",
            "",
            "## Cryptographic signing",
            "",
            f"- Enabled: `{cryptographic.get('enabled', False)}`",
            f"- Requested: `{cryptographic.get('requested', 0)}`",
            f"- Signed: `{cryptographic.get('signed', 0)}`",
            f"- Exact: `{cryptographic.get('exact', False)}`",
            f"- Throughput: `{cryptographic.get('throughput_per_second', 0):.3f} signatures/s`",
            f"- External TSA disabled for local phase: `{timestamping.get('tsa_disabled', False)}`",
            f"- Non-TSA operator settings preserved: `{timestamping.get('non_tsa_settings_preserved', False)}`",
            "",
            "## Resource and topology evidence",
            "",
            f"- Resource samples available: `{resources.get('available', False)}`",
            f"- Resource phases: `{', '.join(sorted(resources.get('phases', {})))}`",
            f"- Initial/final topology stable: `{topology.get('stable', False)}`",
            f"- Initial app replicas: `{topology.get('summary', {}).get('initial_app_replicas')}`",
            f"- Final app replicas: `{topology.get('summary', {}).get('final_app_replicas')}`",
            f"- Aggregate host envelope: `{topology.get('summary', {}).get('aggregate_resource_envelope', {}).get('within_envelope')}`",
            f"- Duration budget passed: `{duration_budget.get('budget_passed', False)}`",
            f"- Duration budget: `{duration_budget.get('required_seconds')}` / "
            f"`{duration_budget.get('workflow_timeout_seconds')}` seconds",
            f"- Peak plateau complete: `{workload.get('phases', {}).get('peak_plateau_complete')}`",
        ]
    )
    blockers = report["slo"].get("proof_blockers", [])
    if blockers:
        lines.extend(["", "## Proof blockers", ""])
        lines.extend(f"- {blocker}" for blocker in blockers)
    lines.extend(
        [
            "",
            "## Honest boundary",
            "",
            seed["coverage_gap"],
            "",
            "A `not_configured` SLO assessment is not a pass. Capacity is proven only when "
            "an operator supplies reviewed thresholds and the resulting report says `passed`.",
            "",
        ]
    )
    return "\n".join(lines)


def run_cryptographic_signing(
    client: ApiClient,
    signature_ids: list[str],
    config: dict[str, Any],
) -> dict[str, Any]:
    provider = config.get("provider")
    if provider != "local-pkcs12":
        raise HarnessError("cryptographic provider must be 'local-pkcs12'")
    count = config.get("count")
    concurrency = config.get("concurrency", 2)
    if not isinstance(count, int) or count < 1:
        raise HarnessError("cryptographic count must be a positive integer")
    if count > len(signature_ids):
        raise HarnessError(
            f"cryptographic count {count} exceeds {len(signature_ids)} seeded signature subjects"
        )
    if not isinstance(concurrency, int) or not 1 <= concurrency <= 32:
        raise HarnessError("cryptographic concurrency must be between 1 and 32")
    pfx_path = pathlib.Path(str(config.get("pkcs12_path", "")))
    if not pfx_path.is_file():
        raise HarnessError(f"cryptographic pkcs12_path does not exist: {pfx_path}")
    passphrase_env = str(config.get("passphrase_env", "CHANCELA_PERF_PKCS12_PASSPHRASE"))
    passphrase = os.environ.get(passphrase_env)
    if not passphrase:
        raise HarnessError(f"cryptographic passphrase env {passphrase_env} is unset")
    pfx_base64 = base64.b64encode(pfx_path.read_bytes()).decode("ascii")
    friendly_name = str(config.get("friendly_name", "Chancela performance test identity"))
    timestamping = disable_external_timestamping_for_local_signing(client)
    stats = OperationStats(Reservoir(max(count, 1), random.Random(99117)))
    setup_statuses: Counter = Counter()
    setup_errors: list[dict[str, Any]] = []
    lock = threading.Lock()
    started = time.perf_counter()

    def prepare_and_sign(position: int, act_id: str) -> None:
        setup_requests = [
            (
                "PATCH",
                f"/v1/acts/{act_id}",
                {
                    "meeting_date": "2026-03-30",
                    "meeting_time": "10:00",
                    "place": "Sede social",
                    "mesa": {
                        "presidente": "Performance President",
                        "secretarios": ["Performance Secretary"],
                    },
                    "agenda": [{"number": 1, "text": "Performance capacity evidence"}],
                    "attendance_reference": "Synthetic performance fixture",
                    "deliberations": "Synthetic performance fixture approved.",
                },
            )
        ]
        setup_requests.extend(
            (
                "POST",
                f"/v1/acts/{act_id}/advance",
                {"to": state},
            )
            for state in ("Review", "Convened", "Deliberated", "TextApproved", "Signing")
        )
        for method, path, body in setup_requests:
            result = safe_retry_request(client, method, path, body)
            with lock:
                setup_statuses[str(result.status)] += 1
            if result.status != 200:
                with lock:
                    if len(setup_errors) < 50:
                        setup_errors.append(
                            {
                                "ordinal": position,
                                "stage": path,
                                "status": result.status,
                                "body": result.body[:300].decode("utf-8", "replace"),
                            }
                        )
                    stats.record(result, {200})
                return
        result = client.request(
            "POST",
            f"/v1/acts/{act_id}/signature/local/pkcs12/sign",
            {
                "pkcs12_base64": pfx_base64,
                "passphrase": passphrase,
                "friendly_name": friendly_name,
                "capacity": "Administrador",
                "actor": "perf-harness",
            },
        )
        with lock:
            stats.record(result, {200})

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(prepare_and_sign, position, act_id)
            for position, act_id in enumerate(signature_ids[:count])
        ]
        for future in concurrent.futures.as_completed(futures):
            future.result()
    elapsed = time.perf_counter() - started
    result = stats.report()
    return {
        "enabled": True,
        "provider": provider,
        "evidence_class": "advanced-local-technical-evidence",
        "requested": count,
        "signed": result["requests"] - result["errors"],
        "exact": result["requests"] == count and result["errors"] == 0,
        "duration_seconds": elapsed,
        "throughput_per_second": (
            (result["requests"] - result["errors"]) / max(elapsed, 0.000001)
        ),
        "sign_operation": result,
        "setup_statuses": dict(setup_statuses),
        "setup_errors": setup_errors,
        "timestamping": timestamping,
        "claim_boundary": (
            "Exercises real local RSA/PKCS#12 PDF signing with an ephemeral test certificate. "
            "It does not measure CMD/CSC/QTSP, smart-card, TSA, revocation, or external-validator capacity."
        ),
    }


def write_failure_report(
    args: argparse.Namespace,
    profile: dict[str, Any],
    manifest: dict[str, Any],
    validation: dict[str, Any],
    error: Exception,
    *,
    resources: dict[str, Any] | None = None,
    topology: dict[str, Any] | None = None,
    duration_budget: dict[str, Any] | None = None,
    source_context: dict[str, Any] | None = None,
) -> None:
    source_context = source_context or capture_source_context()
    proof_blockers = proof_context_blockers(profile, source_context)
    proof_blockers.append("Harness stopped before workload completion.")
    failure = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "profile": profile["name"],
        "profile_proof_eligible": profile["proof_eligible"],
        "source": source_context,
        "base_url": args.base_url,
        "dataset": manifest,
        "dataset_validation": validation,
        "seed": {"exact": False, "fatal_error": f"{type(error).__name__}: {error}"},
        "search_readiness": {"ready": False, "status": "not_completed"},
        "cryptographic_signing": {"enabled": False, "status": "not_reached"},
        "workload": {"status": "not_run"},
        "resources": resources
        or {"available": False, "status": "not_sampled"},
        "topology": topology or {"preflight_passed": False, "status": "not_supplied"},
        "duration_budget": duration_budget
        or {"budget_passed": False, "status": "not_supplied"},
        "slo": {
            "assessment": "not_evaluated",
            "configured_thresholds": 0,
            "checks": [],
            "proof_ready": False,
            "proof_blockers": proof_blockers,
            "message": "Harness stopped before workload completion.",
        },
    }
    write_json(args.report_dir / "report.json", failure)
    atomic_write_text_lf(
        args.report_dir / "report.md",
        "# Chancela performance evidence\n\n"
        f"- Profile: `{profile['name']}`\n"
        f"- Profile proof eligible: `{profile['proof_eligible']}`\n"
        f"- Source kind: `{source_context.get('kind')}`\n"
        f"- Source ref: `{source_context.get('ref')}`\n"
        "- Result: `INCOMPLETE`\n"
        f"- Fatal error: `{type(error).__name__}: {error}`\n\n"
        "An incomplete run is not capacity proof.\n",
    )


def budget_command(args: argparse.Namespace) -> int:
    profile = read_json(args.profile)
    cryptographic_config = (
        read_json(args.cryptographic_config) if args.cryptographic_config else None
    )
    report = duration_budget_report(
        profile,
        workflow_timeout_seconds=args.workflow_timeout_seconds,
        search_readiness_timeout_seconds=args.search_readiness_timeout_seconds,
        cryptographic_config=cryptographic_config,
    )
    write_json(args.output, report)
    print(json.dumps(report, sort_keys=True))
    if not report["budget_passed"]:
        raise HarnessError(
            "deterministic run budget exceeds workflow timeout "
            f"({report['required_seconds']} > {report['workflow_timeout_seconds']} seconds)"
        )
    return 0


def run_command(args: argparse.Namespace) -> int:
    profile = read_json(args.profile)
    validate_profile(profile)
    source_context = capture_source_context()
    validation = validate_dataset(args.dataset_dir)
    manifest = read_json(args.dataset_dir / "manifest.json")
    password = os.environ.get("CHANCELA_PERF_PASSWORD", DEFAULT_PASSWORD)
    client = ApiClient(
        args.base_url,
        float(profile["workload"]["request_timeout_seconds"]),
    )
    topology_initial = (
        read_json(args.topology_evidence)
        if args.topology_evidence
        else {"preflight_passed": False, "status": "not_supplied"}
    )
    topology: dict[str, Any] = {
        "preflight_passed": False,
        "stable": False,
        "status": "final_not_captured",
        "initial": topology_initial,
    }
    duration_budget = (
        read_json(args.duration_budget_evidence)
        if args.duration_budget_evidence
        else {"budget_passed": False, "status": "not_supplied"}
    )
    project_name = (
        topology_initial.get("summary", {}).get("project_name")
        if isinstance(topology_initial.get("summary"), dict)
        else None
    )
    sampler = ResourceSampler(project_name=project_name)
    sampler.set_phase("seed")
    sampler.start()
    resources: dict[str, Any] | None = None
    try:
        slo = read_json(args.slo) if args.slo else None
        if slo is not None:
            validate_slo_schema(slo)
        if args.search_readiness_timeout_seconds <= 0:
            raise HarnessError("search readiness timeout must be positive")
        if (
            args.duration_budget_evidence
            and duration_budget.get("budget_passed") is not True
        ):
            raise HarnessError(
                "duration-budget preflight does not fit inside the workflow timeout"
            )
        if (
            args.topology_evidence
            and topology_initial.get("preflight_passed") is not True
        ):
            raise HarnessError(
                "topology evidence did not pass strict replica/resource preflight"
            )
        if args.topology_evidence and not args.final_topology_evidence:
            raise HarnessError(
                "final topology evidence path is required with initial topology evidence"
            )
        seed_report, index = seed_dataset(args.dataset_dir, client, profile, password)
        write_json(args.report_dir / "runtime-index.json", index)
        sampler.set_phase("search_catch_up")
        sampler.sample_now()
        search_readiness = wait_for_search_ready(
            client,
            index,
            (
                int(manifest["counts"]["entities"])
                + int(manifest["counts"]["books"])
                + int(manifest["counts"]["signatures"])
            ),
            timeout_seconds=args.search_readiness_timeout_seconds,
        )
        sampler.set_phase("cryptographic_signing")
        sampler.sample_now()
        cryptographic_report = (
            run_cryptographic_signing(
                client,
                index["signatures"],
                read_json(args.cryptographic_config),
            )
            if args.cryptographic_config
            else {
                "enabled": False,
                "status": "not_requested",
                "claim_boundary": (
                    "No cryptographic workload was requested; unsigned signature-status subjects "
                    "must not be reported as completed signatures."
                ),
            }
        )
        workload_report, _ = run_workload(
            client,
            profile,
            index,
            password,
            resource_sampler=sampler,
        )
        resources = sampler.finish()
        topology_final = (
            capture_final_topology(
                topology_initial,
                args.final_topology_evidence,
            )
            if args.topology_evidence
            else {"preflight_passed": False, "status": "not_supplied"}
        )
        topology = combine_topology_evidence(topology_initial, topology_final)
    except Exception as error:
        resources = sampler.finish()
        write_failure_report(
            args,
            profile,
            manifest,
            validation,
            error,
            resources=resources,
            topology=topology,
            duration_budget=duration_budget,
            source_context=source_context,
        )
        if isinstance(error, HarnessError):
            raise
        raise HarnessError(str(error)) from error
    slo_report = evaluate_slo(
        workload_report,
        resources,
        slo,
        cryptographic_report,
    )
    proof_blockers = proof_context_blockers(profile, source_context)
    if topology.get("preflight_passed") is not True:
        failures = topology.get("failures", [])
        detail = "; ".join(str(item) for item in failures[:8])
        proof_blockers.append(
            "Initial/final topology evidence was not stable and healthy"
            + (f": {detail}" if detail else ".")
        )
    if duration_budget.get("budget_passed") is not True:
        proof_blockers.append(
            "A passing deterministic duration-budget preflight was not supplied."
        )
    if seed_report.get("exact") is not True:
        proof_blockers.append("The exact requested seed volume did not complete.")
    exactness_blocker = cryptographic_exactness_blocker(cryptographic_report)
    if exactness_blocker:
        proof_blockers.append(exactness_blocker)
    add_proof_blockers(slo_report, proof_blockers)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "profile": profile["name"],
        "profile_proof_eligible": profile["proof_eligible"],
        "source": source_context,
        "base_url": args.base_url,
        "dataset": manifest,
        "dataset_validation": validation,
        "seed": seed_report,
        "search_readiness": search_readiness,
        "cryptographic_signing": cryptographic_report,
        "workload": workload_report,
        "resources": resources,
        "topology": topology,
        "duration_budget": duration_budget,
        "slo": slo_report,
        "environment": {
            "python": sys.version,
            "platform": sys.platform,
            "git_sha": source_context.get("commit_sha"),
            "runner": os.environ.get("RUNNER_ENVIRONMENT"),
        },
    }
    write_json(args.report_dir / "report.json", report)
    atomic_write_text_lf(
        args.report_dir / "report.md",
        markdown_report(report),
    )
    print(json.dumps({"report": str(args.report_dir / "report.json"), "slo": slo_report}))
    if not seed_report["exact"]:
        return 2
    if cryptographic_report.get("enabled") and not cryptographic_report.get("exact"):
        return 4
    if topology.get("preflight_passed") is not True:
        return 5
    if slo_report["assessment"] == "failed":
        return 3
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    generate = subcommands.add_parser("generate", help="generate exact-volume JSONL dataset")
    generate.add_argument("--profile", type=pathlib.Path, required=True)
    generate.add_argument("--output-dir", type=pathlib.Path, required=True)

    validate = subcommands.add_parser("validate", help="validate counts and SHA-256 digests")
    validate.add_argument("--dataset-dir", type=pathlib.Path, required=True)

    budget = subcommands.add_parser(
        "budget",
        help="preflight the whole-run wall-clock budget against the workflow timeout",
    )
    budget.add_argument("--profile", type=pathlib.Path, required=True)
    budget.add_argument("--output", type=pathlib.Path, required=True)
    budget.add_argument("--workflow-timeout-seconds", type=float, required=True)
    budget.add_argument(
        "--search-readiness-timeout-seconds",
        type=float,
        required=True,
    )
    budget.add_argument("--cryptographic-config", type=pathlib.Path)

    run = subcommands.add_parser("run", help="seed target and run mixed workload")
    run.add_argument("--profile", type=pathlib.Path, required=True)
    run.add_argument("--dataset-dir", type=pathlib.Path, required=True)
    run.add_argument("--report-dir", type=pathlib.Path, required=True)
    run.add_argument("--base-url", default="http://127.0.0.1:18081")
    run.add_argument("--slo", type=pathlib.Path)
    run.add_argument(
        "--search-readiness-timeout-seconds",
        type=float,
        default=float(
            os.environ.get(
                "CHANCELA_PERF_SEARCH_READY_TIMEOUT_SECONDS",
                "900",
            )
        ),
    )
    run.add_argument(
        "--topology-evidence",
        type=pathlib.Path,
        help="strict topology preflight JSON captured after Compose startup",
    )
    run.add_argument(
        "--final-topology-evidence",
        type=pathlib.Path,
        help="output path for the mandatory post-workload topology capture",
    )
    run.add_argument(
        "--duration-budget-evidence",
        type=pathlib.Path,
        help="passing deterministic duration-budget preflight JSON",
    )
    run.add_argument(
        "--cryptographic-config",
        type=pathlib.Path,
        help="opt-in local PKCS#12 signing workload; never enabled by a profile alone",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            manifest = generate_dataset(args.profile, args.output_dir)
            print(json.dumps(manifest, sort_keys=True))
            return 0
        if args.command == "validate":
            result = validate_dataset(args.dataset_dir)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "budget":
            return budget_command(args)
        if args.command == "run":
            return run_command(args)
        raise HarnessError(f"unknown command {args.command}")
    except HarnessError as error:
        print(f"performance harness error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
