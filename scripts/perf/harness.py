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
}
MODES = {"steady", "ramp", "spike", "soak"}
DEFAULT_PASSWORD = "Perf-Only-Password-2026!"
USER_NAMESPACE = uuid.UUID("7b0fb943-83ff-4e56-a670-0fd19fb46ee5")


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
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(path)


def validate_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError(f"profile schema_version must be {SCHEMA_VERSION}")
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


def docker_snapshot() -> list[dict[str, Any]]:
    try:
        completed = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
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
        if not name or "chancela" not in name:
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
    def __init__(self, interval_seconds: float = 5.0):
        self.interval_seconds = interval_seconds
        self.stop = threading.Event()
        self.samples: list[dict[str, Any]] = []
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        def loop() -> None:
            while not self.stop.is_set():
                self.samples.extend(docker_snapshot())
                self.stop.wait(self.interval_seconds)

        self.thread = threading.Thread(target=loop, name="resource-sampler", daemon=True)
        self.thread.start()

    def finish(self) -> dict[str, Any]:
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=self.interval_seconds + 2)
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for sample in self.samples:
            grouped[sample["container"]].append(sample)
        containers = {}
        for name, samples in grouped.items():
            containers[name] = {
                "samples": len(samples),
                "max_cpu_percent": max(item["cpu_percent"] for item in samples),
                "avg_cpu_percent": sum(item["cpu_percent"] for item in samples) / len(samples),
                "max_memory_bytes": max(item["memory_bytes"] for item in samples),
            }
        return {
            "sampler": "docker stats",
            "available": bool(self.samples),
            "interval_seconds": self.interval_seconds,
            "containers": containers,
        }


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
    raise HarnessError(f"unimplemented operation {name}")


def run_workload(
    client: ApiClient,
    profile: dict[str, Any],
    index: dict[str, list[str]],
    password: str,
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
    trace_lock = threading.Lock()

    def worker(worker_id: int) -> None:
        nonlocal write_counter
        rng = random.Random(profile["seed"] + 10000 + worker_id)
        last_trace_second = -1
        while time.monotonic() < stop_at:
            elapsed = time.monotonic() - started
            allowed = active_clients(mode, elapsed, duration, clients)
            second = int(elapsed)
            if worker_id == 0 and second != last_trace_second:
                with trace_lock:
                    active_trace.append(
                        {"elapsed_seconds": second, "active_clients": allowed}
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

    sampler = ResourceSampler()
    sampler.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=clients) as executor:
        futures = [executor.submit(worker, worker_id) for worker_id in range(clients)]
        for future in futures:
            future.result()
    elapsed = time.monotonic() - started
    resources = sampler.finish()

    operation_reports = {name: value.report() for name, value in sorted(stats.items())}
    total = sum(item["requests"] for item in operation_reports.values())
    errors = sum(item["errors"] for item in operation_reports.values())
    return (
        {
            "mode": mode,
            "duration_seconds": elapsed,
            "configured_clients": clients,
            "active_client_trace": active_trace,
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
) -> dict[str, Any]:
    if not slo:
        return {
            "assessment": "not_configured",
            "configured_thresholds": 0,
            "checks": [],
            "message": "No SLO file supplied; measurements are evidence, not a pass.",
        }
    checks: list[dict[str, Any]] = []

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
    check("global.error_rate", workload.get("error_rate"), global_slo.get("max_error_rate"), "max")
    check(
        "global.throughput_per_second",
        workload.get("throughput_per_second"),
        global_slo.get("min_throughput_per_second"),
        "min",
    )
    for operation, thresholds in slo.get("operations", {}).items():
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
    resource_slo = slo.get("resources", {})
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
    if not checks:
        assessment = "not_configured"
        message = "SLO file contained only null thresholds; measurements are not a pass."
    elif all(item["passed"] for item in checks):
        assessment = "passed"
        message = "Every explicitly configured threshold passed."
    else:
        assessment = "failed"
        message = "At least one explicitly configured threshold failed."
    return {
        "assessment": assessment,
        "configured_thresholds": len(checks),
        "checks": checks,
        "message": message,
    }


def markdown_report(report: dict[str, Any]) -> str:
    dataset = report["dataset"]
    seed = report["seed"]
    workload = report["workload"]
    lines = [
        "# Chancela performance evidence",
        "",
        f"- Generated: `{report['generated_at']}`",
        f"- Profile: `{report['profile']}`",
        f"- Workload mode: `{workload['mode']}`",
        f"- SLO assessment: `{report['slo']['assessment']}`",
        f"- Exact seed: `{seed['exact']}`",
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
) -> None:
    failure = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "profile": profile["name"],
        "base_url": args.base_url,
        "dataset": manifest,
        "dataset_validation": validation,
        "seed": {"exact": False, "fatal_error": f"{type(error).__name__}: {error}"},
        "cryptographic_signing": {"enabled": False, "status": "not_reached"},
        "workload": {"status": "not_run"},
        "resources": {"available": False, "status": "not_sampled"},
        "slo": {
            "assessment": "not_evaluated",
            "configured_thresholds": 0,
            "checks": [],
            "message": "Harness stopped before workload completion.",
        },
    }
    write_json(args.report_dir / "report.json", failure)
    (args.report_dir / "report.md").write_text(
        "# Chancela performance evidence\n\n"
        f"- Profile: `{profile['name']}`\n"
        "- Result: `INCOMPLETE`\n"
        f"- Fatal error: `{type(error).__name__}: {error}`\n\n"
        "An incomplete run is not capacity proof.\n",
        encoding="utf-8",
        newline="\n",
    )


def run_command(args: argparse.Namespace) -> int:
    profile = read_json(args.profile)
    validate_profile(profile)
    validation = validate_dataset(args.dataset_dir)
    manifest = read_json(args.dataset_dir / "manifest.json")
    password = os.environ.get("CHANCELA_PERF_PASSWORD", DEFAULT_PASSWORD)
    client = ApiClient(
        args.base_url,
        float(profile["workload"]["request_timeout_seconds"]),
    )
    try:
        seed_report, index = seed_dataset(args.dataset_dir, client, profile, password)
        write_json(args.report_dir / "runtime-index.json", index)
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
        workload_report, resources = run_workload(client, profile, index, password)
    except Exception as error:
        write_failure_report(args, profile, manifest, validation, error)
        if isinstance(error, HarnessError):
            raise
        raise HarnessError(str(error)) from error
    slo = read_json(args.slo) if args.slo else None
    slo_report = evaluate_slo(workload_report, resources, slo)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "profile": profile["name"],
        "base_url": args.base_url,
        "dataset": manifest,
        "dataset_validation": validation,
        "seed": seed_report,
        "cryptographic_signing": cryptographic_report,
        "workload": workload_report,
        "resources": resources,
        "slo": slo_report,
        "environment": {
            "python": sys.version,
            "platform": sys.platform,
            "git_sha": os.environ.get("GITHUB_SHA"),
            "runner": os.environ.get("RUNNER_ENVIRONMENT"),
        },
    }
    write_json(args.report_dir / "report.json", report)
    (args.report_dir / "report.md").write_text(
        markdown_report(report), encoding="utf-8", newline="\n"
    )
    print(json.dumps({"report": str(args.report_dir / "report.json"), "slo": slo_report}))
    if not seed_report["exact"]:
        return 2
    if cryptographic_report.get("enabled") and not cryptographic_report.get("exact"):
        return 4
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

    run = subcommands.add_parser("run", help="seed target and run mixed workload")
    run.add_argument("--profile", type=pathlib.Path, required=True)
    run.add_argument("--dataset-dir", type=pathlib.Path, required=True)
    run.add_argument("--report-dir", type=pathlib.Path, required=True)
    run.add_argument("--base-url", default="http://127.0.0.1:18081")
    run.add_argument("--slo", type=pathlib.Path)
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
        if args.command == "run":
            return run_command(args)
        raise HarnessError(f"unknown command {args.command}")
    except HarnessError as error:
        print(f"performance harness error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
