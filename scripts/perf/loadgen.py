#!/usr/bin/env python3
"""Open-loop, connection-pooled, multi-process HTTP load generator.

Why this exists, stated plainly so no figure it produces can be misread:

* The existing ``harness.py`` workload is **closed-loop** — a fixed pool of
  clients that each block on a response. A closed-loop harness cannot express
  an *arrival rate*, and "10 000 requests per second" is an arrival rate.
* ``harness.py`` also opens a new TCP connection per request. On this Windows
  host the ephemeral range is 16 384 ports and ``TIME_WAIT`` is ~120 s, which
  caps *new connections* at roughly 136/s. That is a property of the load
  generator and the OS, not of the server.

This generator fixes both: a schedule of intended send times computed **before**
the run, dispatched over a fixed set of persistent keep-alive connections spread
across worker processes so protocol work is not serialized by one GIL.

Honesty rules encoded here, not merely documented:

* **"Client saturated" is a first-class bottleneck outcome.** Client-side causes
  are tested *before* server-side ones. When the generator is the limiter, the
  result is marked ``server_capacity_interpretable: false`` and carries an
  explicit blocker sentence. A client ceiling is never reported as a server
  ceiling.
* **The container CPU quota and the generator's CPU allocation are required
  fields on every figure.** Rendering a figure that is missing one raises.
  They cannot be demoted to a footnote.
* **The quota is observed, not assumed.** The declared stage quota is checked
  against ``docker inspect``; a mismatch is a blocker.
* **Pass criteria are constants.** ``slo.throughput.json`` is verified against
  them, so a threshold cannot be quietly softened to make a run pass.
* **Running is gated.** ``run`` refuses to execute without an explicit release
  flag *and* environment variable. Being build-complete is not authorization to
  generate load.

Latency is reported twice and both are labelled: ``service`` (response minus
actual send) and ``corrected`` (response minus *intended* send). The corrected
figure is the one that governs; it is what removes coordinated omission.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import multiprocessing
import os
import pathlib
import queue
import random
import re
import socket
import subprocess
import sys
import threading
import time
import http.client
from collections import Counter
from typing import Any, Iterable, Sequence

from perf_io import atomic_write_text_lf


SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Pass criteria — t57 plan §5 B3. Fixed before the run and NOT softened because
# the container CPU quota was raised. Raising the quota buys a fair measurement,
# not a lower bar.
# ---------------------------------------------------------------------------
B3_TARGET_RATE_PER_SECOND = 10_000.0
B3_MIN_SUSTAINED_SECONDS = 60.0
B3_MAX_ERROR_RATE = 0.005
B3_MAX_P99_MS = 1000.0

LOOPBACK_DISCLOSURE = (
    "loopback on a single Windows 11 host via the Docker Desktop port proxy; "
    "load generator and server share the machine"
)
DIRECT_DISCLOSURE = (
    "loopback on a single Windows 11 host, load generator inside the Docker "
    "network addressing app replicas directly; load generator and server share "
    "the machine"
)

# ---------------------------------------------------------------------------
# Bottleneck outcomes. A closed set — a run is never described with an ad-hoc
# phrase.
# ---------------------------------------------------------------------------
OUTCOME_TARGET_MET = "target_rate_met"
OUTCOME_CLIENT_CPU = "client_cpu_saturated"
OUTCOME_CLIENT_DISPATCH_LAG = "client_dispatch_lag"
OUTCOME_CLIENT_CONNECTION_STARVED = "client_connection_starved"
OUTCOME_CLIENT_PORT_PRESSURE = "client_ephemeral_port_pressure"
OUTCOME_SERVER_ERRORS = "server_error_rate"
OUTCOME_SERVER_LATENCY = "server_latency"
OUTCOME_INDETERMINATE = "indeterminate"

CLIENT_BOTTLENECKS = frozenset(
    {
        OUTCOME_CLIENT_CPU,
        OUTCOME_CLIENT_DISPATCH_LAG,
        OUTCOME_CLIENT_CONNECTION_STARVED,
        OUTCOME_CLIENT_PORT_PRESSURE,
    }
)
ALL_OUTCOMES = frozenset(
    CLIENT_BOTTLENECKS
    | {
        OUTCOME_TARGET_MET,
        OUTCOME_SERVER_ERRORS,
        OUTCOME_SERVER_LATENCY,
        OUTCOME_INDETERMINATE,
    }
)

CLIENT_BOTTLENECK_BLOCKER = {
    OUTCOME_CLIENT_CPU: (
        "The load generator was CPU saturated. This figure measures the "
        "generator, not the server, and must not be reported as server capacity."
    ),
    OUTCOME_CLIENT_DISPATCH_LAG: (
        "The load generator could not issue requests on schedule. The offered "
        "rate was never actually offered, so this figure is a generator "
        "measurement, not a server capacity measurement."
    ),
    OUTCOME_CLIENT_CONNECTION_STARVED: (
        "The load generator ran out of free pooled connections and dropped "
        "scheduled sends. This is a generator limit, not a server limit."
    ),
    OUTCOME_CLIENT_PORT_PRESSURE: (
        "Connection reuse broke down and the generator churned TCP connections, "
        "so the host ephemeral-port range and TIME_WAIT depth bounded the run. "
        "This is a generator/OS limit, not a server limit."
    ),
}

# ---------------------------------------------------------------------------
# Required fields. Every reported figure carries the CPU quota it ran under and
# the generator's CPU allocation (t57 plan D2 / R9). Rendering refuses to emit a
# figure missing any of them.
# ---------------------------------------------------------------------------
REQUIRED_ENVIRONMENT_FIELDS = (
    "stage",
    "step",
    "proof_eligible",
    "container_cpu_quota_per_app_node",
    "container_cpu_quota_app_total",
    "container_cpu_quota_source",
    "generator_worker_processes",
    "generator_cpu_allocation",
    "generator_cpu_pinning",
    "docker_vm_logical_cpus",
    "host_logical_cpus",
    "transport_path",
    "transport_disclosure",
    "offered_rate_per_second",
    "bottleneck",
    "server_capacity_interpretable",
)
# These may be absent only when the step produced nothing to measure, and only
# alongside an explicit `measurement_void_reason`. A step where every request
# failed must still yield a reportable figure — discovering that mid-window as a
# crash would waste the exclusive window.
REQUIRED_MEASUREMENT_FIELDS = (
    "generator_cpu_utilization_of_allocation",
    "issued_rate_per_second",
    "achieved_rate_per_second",
    "error_rate",
    "corrected_p99_ms",
    "longest_sustained_seconds_at_target",
)
REQUIRED_FIGURE_FIELDS = REQUIRED_ENVIRONMENT_FIELDS + REQUIRED_MEASUREMENT_FIELDS

# Endpoint mix. Named endpoints with stated payloads; a throughput number
# against an unnamed mix is not a result (§5 B3).
ENDPOINTS: dict[str, dict[str, Any]] = {
    "health": {
        "method": "GET",
        "template": "/health",
        "identifiers": None,
        "authenticated": False,
        "expect": (200,),
        "payload": "none",
    },
    "entity_get": {
        "method": "GET",
        "template": "/v1/entities/{id}",
        "identifiers": "entities",
        "authenticated": True,
        "expect": (200,),
        "payload": "none",
    },
    "book_get": {
        "method": "GET",
        "template": "/v1/books/{id}",
        "identifiers": "books",
        "authenticated": True,
        "expect": (200,),
        "payload": "none",
    },
    "signature_status": {
        "method": "GET",
        "template": "/v1/acts/{id}/signature",
        "identifiers": "signatures",
        "authenticated": True,
        "expect": (200,),
        "payload": "none",
    },
    "entity_list": {
        "method": "GET",
        "template": "/v1/entities",
        "identifiers": None,
        "authenticated": True,
        "expect": (200,),
        "payload": "none",
    },
}
IDENTIFIER_FAMILIES = ("entities", "books", "signatures")

RELEASE_ENV = "CHANCELA_PERF_LOADGEN_RELEASE"
APP_CPUS_ENV = "CHANCELA_PERF_APP_CPUS"
PROJECTOR_CPUS_ENV = "CHANCELA_PERF_SEARCH_PROJECTOR_CPUS"
APP_SERVICE = "chancela-cluster"
# A Windows affinity mask addresses one processor group only.
WINDOWS_AFFINITY_MASK_LIMIT = 64

DEFAULT_THRESHOLDS: dict[str, float] = {
    # Fraction of its own CPU allocation above which the generator is called
    # saturated. Below 1.0 on purpose: a generator at 85% of budget is already
    # distorting the measurement.
    "generator_cpu_saturation_fraction": 0.85,
    # Fraction of scheduled sends that may be issued late-or-not-at-all.
    "max_dispatch_deficit_fraction": 0.01,
    "max_dispatch_blocked_fraction": 0.01,
    # p99 of (actual send - intended send).
    "max_dispatch_lag_p99_ms": 50.0,
    # Persistent connections must carry essentially all requests.
    "min_connection_reuse_ratio": 0.95,
    # Host sockets in TIME_WAIT at step end, as a fraction of the ephemeral range.
    "max_time_wait_fraction_of_ephemeral_range": 0.50,
    # Achieved must track offered for the rate to have been genuinely offered.
    "min_achieved_fraction_of_offered": 0.99,
}


class LoadGenError(RuntimeError):
    pass


def utc_now() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise LoadGenError(f"{path} must contain a JSON object")
    return value


def write_json(path: pathlib.Path, value: Any) -> None:
    atomic_write_text_lf(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Profile / SLO validation
# ---------------------------------------------------------------------------


def validate_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema_version") != SCHEMA_VERSION:
        raise LoadGenError(f"profile schema_version must be {SCHEMA_VERSION}")
    if not isinstance(profile.get("name"), str) or not profile["name"]:
        raise LoadGenError("profile.name must be a non-empty string")
    if profile.get("proof_eligible") is not False:
        raise LoadGenError(
            "throughput profiles must declare proof_eligible: false; a raised-CPU "
            "profile can never support a coverage claim"
        )
    generator = profile.get("generator")
    if not isinstance(generator, dict):
        raise LoadGenError("profile.generator must be an object")
    for field in ("worker_processes", "connections_per_worker", "cpu_allocation"):
        value = generator.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise LoadGenError(f"profile.generator.{field} must be a positive integer")
    base = generator.get("cpu_index_base", 0)
    if isinstance(base, bool) or not isinstance(base, int) or base < 0:
        raise LoadGenError("profile.generator.cpu_index_base must be a non-negative integer")
    timeout = generator.get("request_timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise LoadGenError("profile.generator.request_timeout_seconds must be positive")

    stages = profile.get("stages")
    if not isinstance(stages, list) or not stages:
        raise LoadGenError("profile.stages must be a non-empty array")
    names = set()
    for stage in stages:
        validate_stage(stage)
        if stage["name"] in names:
            raise LoadGenError(f"duplicate stage name {stage['name']!r}")
        names.add(stage["name"])

    thresholds = profile.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise LoadGenError("profile.thresholds must be an object")
    unknown = set(thresholds) - set(DEFAULT_THRESHOLDS)
    if unknown:
        raise LoadGenError(f"profile.thresholds has unknown fields: {sorted(unknown)}")
    for field, value in thresholds.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise LoadGenError(f"profile.thresholds.{field} must be numeric")
        if not math.isfinite(float(value)) or value < 0:
            raise LoadGenError(f"profile.thresholds.{field} must be finite and non-negative")


def validate_stage(stage: Any) -> None:
    if not isinstance(stage, dict):
        raise LoadGenError("each stage must be an object")
    if not isinstance(stage.get("name"), str) or not stage["name"]:
        raise LoadGenError("stage.name must be a non-empty string")
    cpus = stage.get("app_cpus")
    if isinstance(cpus, bool) or not isinstance(cpus, (int, float)) or cpus <= 0:
        raise LoadGenError(f"stage {stage.get('name')!r}: app_cpus must be positive")
    projector = stage.get("search_projector_cpus")
    if (
        isinstance(projector, bool)
        or not isinstance(projector, (int, float))
        or projector <= 0
    ):
        raise LoadGenError(
            f"stage {stage.get('name')!r}: search_projector_cpus must be positive"
        )
    replicas = stage.get("app_replicas")
    if isinstance(replicas, bool) or not isinstance(replicas, int) or replicas < 1:
        raise LoadGenError(f"stage {stage.get('name')!r}: app_replicas must be a positive integer")
    weights = stage.get("weights")
    if not isinstance(weights, dict) or not weights:
        raise LoadGenError(f"stage {stage.get('name')!r}: weights must be a non-empty object")
    unknown = set(weights) - set(ENDPOINTS)
    if unknown:
        raise LoadGenError(
            f"stage {stage.get('name')!r}: unknown endpoints {sorted(unknown)}"
        )
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in weights.values()):
        raise LoadGenError(f"stage {stage.get('name')!r}: weights must be non-negative integers")
    if sum(weights.values()) <= 0:
        raise LoadGenError(f"stage {stage.get('name')!r}: at least one weight must be positive")
    steps = stage.get("steps")
    if not isinstance(steps, list) or not steps:
        raise LoadGenError(f"stage {stage.get('name')!r}: steps must be a non-empty array")
    for step in steps:
        if not isinstance(step, dict):
            raise LoadGenError(f"stage {stage.get('name')!r}: each step must be an object")
        if not isinstance(step.get("name"), str) or not step["name"]:
            raise LoadGenError(f"stage {stage.get('name')!r}: step.name must be a non-empty string")
        rate = step.get("target_rate_per_second")
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate <= 0:
            raise LoadGenError(
                f"stage {stage['name']!r} step {step.get('name')!r}: "
                "target_rate_per_second must be positive"
            )
        for field in ("duration_seconds", "warmup_seconds"):
            value = step.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise LoadGenError(
                    f"stage {stage['name']!r} step {step.get('name')!r}: "
                    f"{field} must be a non-negative number"
                )
        if float(step["duration_seconds"]) <= float(step["warmup_seconds"]):
            raise LoadGenError(
                f"stage {stage['name']!r} step {step.get('name')!r}: "
                "duration_seconds must exceed warmup_seconds"
            )


def validate_slo(slo: dict[str, Any]) -> None:
    """Validate the throughput SLO and refuse any softening of §5 B3."""

    if slo.get("schema_version") != SCHEMA_VERSION:
        raise LoadGenError(f"SLO schema_version must be {SCHEMA_VERSION}")
    allowed = {"schema_version", "kind", "pass_criteria", "notes"}
    unknown = set(slo) - allowed
    if unknown:
        raise LoadGenError(f"SLO has unknown top-level fields: {sorted(unknown)}")
    if slo.get("kind") != "throughput":
        raise LoadGenError("SLO kind must be 'throughput'")
    criteria = slo.get("pass_criteria")
    if not isinstance(criteria, dict):
        raise LoadGenError("SLO pass_criteria must be an object")
    expected = {
        "target_rate_per_second": B3_TARGET_RATE_PER_SECOND,
        "min_sustained_seconds": B3_MIN_SUSTAINED_SECONDS,
        "max_error_rate": B3_MAX_ERROR_RATE,
        "max_p99_ms": B3_MAX_P99_MS,
    }
    missing = sorted(set(expected) - set(criteria))
    if missing:
        raise LoadGenError(f"SLO pass_criteria is missing {missing}")
    extra = sorted(set(criteria) - set(expected))
    if extra:
        raise LoadGenError(f"SLO pass_criteria has unknown fields: {extra}")
    for field, required in expected.items():
        value = criteria[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise LoadGenError(f"SLO pass_criteria.{field} must be numeric")
        if not math.isclose(float(value), required, rel_tol=0.0, abs_tol=1e-9):
            raise LoadGenError(
                f"SLO pass_criteria.{field} is {value!r} but the fixed t57 §5 B3 "
                f"criterion is {required!r}; pass criteria are set before the run "
                "and are not softened because the CPU quota was raised"
            )


# ---------------------------------------------------------------------------
# Environment capture — host, Docker VM, and the *observed* container quota.
# ---------------------------------------------------------------------------


def _run_capture(command: Sequence[str], timeout: float = 20.0) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, f"{type(error).__name__}: {error}"
    return completed.returncode, completed.stdout


def host_logical_cpus() -> int | None:
    return os.cpu_count()


def docker_vm_logical_cpus() -> int | None:
    code, output = _run_capture(["docker", "info", "--format", "{{.NCPU}}"])
    if code != 0:
        return None
    try:
        return int(output.strip())
    except ValueError:
        return None


def observe_app_cpu_quota(project_name: str, service: str = APP_SERVICE) -> dict[str, Any]:
    """Read the CPU quota Docker is actually enforcing on the app containers.

    The declared quota is an intention; this is the fact. Every figure records
    which of the two it carries.
    """

    unknown = {
        "available": False,
        "containers": [],
        "per_container_cpus": None,
        "consistent": False,
        "source": "unavailable",
    }
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project_name or ""):
        return unknown
    code, output = _run_capture(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--filter",
            f"label=com.docker.compose.service={service}",
            "--format",
            "{{.ID}}",
        ]
    )
    identifiers = [line.strip() for line in output.splitlines() if line.strip()]
    if code != 0 or not identifiers:
        return unknown
    code, output = _run_capture(
        ["docker", "inspect", "--format", "{{.Name}} {{.HostConfig.NanoCpus}}", *identifiers]
    )
    if code != 0:
        return unknown
    containers: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        try:
            nano = int(parts[1])
        except ValueError:
            continue
        containers.append(
            {
                "container": parts[0].lstrip("/"),
                "nano_cpus": nano,
                "cpus": (nano / 1_000_000_000.0) if nano > 0 else None,
            }
        )
    if not containers:
        return unknown
    values = {item["cpus"] for item in containers}
    consistent = len(values) == 1
    per_container = containers[0]["cpus"] if consistent else None
    return {
        "available": True,
        "containers": containers,
        "per_container_cpus": per_container,
        "consistent": consistent,
        "source": "observed",
    }


def quota_blockers(stage: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    """Refuse to attribute a figure to a quota that was not actually in force."""

    blockers: list[str] = []
    declared = float(stage["app_cpus"])
    if not observed.get("available"):
        blockers.append(
            "The container CPU quota could not be observed from Docker; the "
            f"declared stage quota of {declared} CPUs per app node is unverified."
        )
        return blockers
    if not observed.get("consistent"):
        blockers.append(
            "App containers are running under different CPU quotas: "
            f"{observed.get('containers')!r}."
        )
        return blockers
    actual = observed.get("per_container_cpus")
    if actual is None:
        blockers.append(
            "App containers are running with no CPU quota at all, but stage "
            f"{stage['name']!r} declares {declared}."
        )
        return blockers
    if not math.isclose(float(actual), declared, rel_tol=0.0, abs_tol=0.01):
        blockers.append(
            f"Stage {stage['name']!r} declares {declared} CPUs per app node but "
            f"Docker is enforcing {actual}. Relaunch the stack with "
            f"{APP_CPUS_ENV}={declared} before measuring."
        )
    expected_replicas = int(stage["app_replicas"])
    actual_replicas = len(observed.get("containers") or [])
    if actual_replicas != expected_replicas:
        blockers.append(
            f"Stage {stage['name']!r} declares {expected_replicas} app replicas "
            f"but {actual_replicas} are running."
        )
    return blockers


def sample_socket_state() -> dict[str, Any]:
    """Sample host TCP socket state — TIME_WAIT depth is a first-class metric (R6)."""

    if sys.platform == "win32":
        code, output = _run_capture(["netstat", "-an", "-p", "tcp"], timeout=60.0)
        if code != 0:
            return {"available": False, "sampler": "netstat"}
        time_wait = 0
        established = 0
        for line in output.splitlines():
            if "TIME_WAIT" in line:
                time_wait += 1
            elif "ESTABLISHED" in line:
                established += 1
        return {
            "available": True,
            "sampler": "netstat -an -p tcp",
            "time_wait": time_wait,
            "established": established,
        }
    code, output = _run_capture(["ss", "-tan"], timeout=60.0)
    if code != 0:
        return {"available": False, "sampler": "ss"}
    time_wait = sum(1 for line in output.splitlines() if "TIME-WAIT" in line)
    established = sum(1 for line in output.splitlines() if "ESTAB" in line)
    return {
        "available": True,
        "sampler": "ss -tan",
        "time_wait": time_wait,
        "established": established,
    }


def ephemeral_port_range() -> dict[str, Any]:
    if sys.platform == "win32":
        code, output = _run_capture(["netsh", "int", "ipv4", "show", "dynamicport", "tcp"])
        if code != 0:
            return {"available": False}
        start = None
        count = None
        for line in output.splitlines():
            match = re.search(r"Start Port\s*:\s*(\d+)", line)
            if match:
                start = int(match.group(1))
            match = re.search(r"Number of Ports\s*:\s*(\d+)", line)
            if match:
                count = int(match.group(1))
        if start is None or count is None:
            return {"available": False}
        return {"available": True, "start_port": start, "port_count": count}
    try:
        text = pathlib.Path("/proc/sys/net/ipv4/ip_local_port_range").read_text()
        low, high = (int(part) for part in text.split())
        return {"available": True, "start_port": low, "port_count": high - low + 1}
    except Exception:
        return {"available": False}


def try_set_process_affinity(cpu_indices: Sequence[int]) -> dict[str, Any]:
    """Best-effort CPU partitioning between generator and containers (R9).

    Never assumed to have worked: the result is recorded either way. On Windows a
    single affinity mask only addresses the current processor group (<= 64 CPUs),
    so indices beyond that are reported as unpinned rather than silently dropped.
    """

    indices = sorted(set(int(index) for index in cpu_indices))
    if not indices:
        return {"requested": [], "applied": False, "reason": "no cpus requested"}
    if hasattr(os, "sched_setaffinity"):
        try:
            os.sched_setaffinity(0, set(indices))
            return {"requested": indices, "applied": True, "mechanism": "sched_setaffinity"}
        except Exception as error:
            return {
                "requested": indices,
                "applied": False,
                "reason": f"{type(error).__name__}: {error}",
            }
    if sys.platform == "win32":
        if any(index >= WINDOWS_AFFINITY_MASK_LIMIT for index in indices):
            return {
                "requested": indices,
                "applied": False,
                "reason": "affinity mask cannot address CPUs outside one processor group",
            }
        mask = 0
        for index in indices:
            mask |= 1 << index
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.GetCurrentProcess()
            ok = kernel32.SetProcessAffinityMask(handle, ctypes.c_size_t(mask))
            if not ok:
                return {
                    "requested": indices,
                    "applied": False,
                    "reason": f"SetProcessAffinityMask failed ({ctypes.get_last_error()})",
                }
            return {
                "requested": indices,
                "applied": True,
                "mechanism": "SetProcessAffinityMask",
            }
        except Exception as error:
            return {
                "requested": indices,
                "applied": False,
                "reason": f"{type(error).__name__}: {error}",
            }
    return {"requested": indices, "applied": False, "reason": "unsupported platform"}


def generator_cpu_slices(
    worker_count: int,
    cpu_allocation: int,
    cpu_index_base: int,
    host_cpus: int,
) -> list[list[int]]:
    """Deal the generator's CPU budget round-robin across its worker processes.

    The budget deliberately starts above index 0 so the OS and the Docker VM's
    own threads are not fought over the first cores. On Windows it is additionally
    clamped to a single processor group, because pinning there goes through one
    affinity mask and a mask cannot address more than one group; where pinning
    goes through sched_setaffinity there is no mask and no such ceiling, so the
    clamp would only strand CPUs. The ceiling therefore tracks the mechanism
    try_set_process_affinity will actually use, not the platform in the abstract.

    This is a soft partition: the WSL2 VM's vCPUs are scheduled by the hypervisor
    and cannot be excluded from these cores. The run records whether pinning was
    actually applied rather than assuming it.
    """

    if worker_count < 1 or cpu_allocation < 1:
        raise LoadGenError("worker_count and cpu_allocation must be positive")
    ceiling = min(host_cpus, WINDOWS_AFFINITY_MASK_LIMIT if sys.platform == "win32" else host_cpus)
    base = min(cpu_index_base, max(0, ceiling - cpu_allocation))
    indices = list(range(base, min(base + cpu_allocation, ceiling)))
    if not indices:
        return [[] for _ in range(worker_count)]
    return [indices[index::worker_count] for index in range(worker_count)]


def summarize_affinity(results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    applied = [bool((item.get("affinity") or {}).get("applied")) for item in results]
    reasons = sorted(
        {
            str((item.get("affinity") or {}).get("reason"))
            for item in results
            if not (item.get("affinity") or {}).get("applied")
            and (item.get("affinity") or {}).get("reason")
        }
    )
    return {
        "workers": len(applied),
        "pinned_workers": sum(1 for value in applied if value),
        "applied": bool(applied) and all(applied),
        "reasons": reasons,
        "caveat": (
            "A soft partition only: the Docker Desktop WSL2 VM's vCPUs are "
            "hypervisor-scheduled and cannot be excluded from these host CPUs."
        ),
    }


def _begin_high_resolution_timer() -> bool:
    """Ask Windows for a 1 ms timer period so sub-millisecond pacing is possible."""

    if sys.platform != "win32":
        return False
    try:
        ctypes.WinDLL("winmm").timeBeginPeriod(1)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Latency histogram — merges exactly across processes, never understates.
# ---------------------------------------------------------------------------

_HISTOGRAM_LAYOUT = (
    # (upper bound ms, resolution ms, first bucket index)
    (100.0, 0.1, 0),
    (1_000.0, 1.0, 1000),
    (10_000.0, 10.0, 1900),
    (120_000.0, 100.0, 2800),
)
HISTOGRAM_BUCKETS = 3901
HISTOGRAM_OVERFLOW_INDEX = 3900


def histogram_index(milliseconds: float) -> int:
    value = max(0.0, float(milliseconds))
    lower = 0.0
    for upper, resolution, base in _HISTOGRAM_LAYOUT:
        if value < upper:
            return base + int((value - lower) / resolution)
        lower = upper
    return HISTOGRAM_OVERFLOW_INDEX


def histogram_upper_bound(index: int) -> float:
    """Upper edge of a bucket. Percentiles report this, so latency is never understated."""

    if index >= HISTOGRAM_OVERFLOW_INDEX:
        return float("inf")
    lower = 0.0
    for upper, resolution, base in _HISTOGRAM_LAYOUT:
        span = int(round((upper - lower) / resolution))
        if index < base + span:
            return lower + (index - base + 1) * resolution
        lower = upper
    return float("inf")


def new_histogram() -> list[int]:
    return [0] * HISTOGRAM_BUCKETS


def merge_histograms(histograms: Iterable[Sequence[int]]) -> list[int]:
    merged = new_histogram()
    for histogram in histograms:
        for index, count in enumerate(histogram):
            if count:
                merged[index] += count
    return merged


def histogram_percentile(histogram: Sequence[int], quantile: float) -> float | None:
    total = sum(histogram)
    if total == 0:
        return None
    if not 0.0 < quantile <= 1.0:
        raise LoadGenError("quantile must be in (0, 1]")
    threshold = quantile * total
    cumulative = 0
    for index, count in enumerate(histogram):
        cumulative += count
        if cumulative >= threshold:
            bound = histogram_upper_bound(index)
            return None if math.isinf(bound) else bound
    return None


def histogram_report(histogram: Sequence[int]) -> dict[str, Any]:
    return {
        "samples": sum(histogram),
        "p50_ms": histogram_percentile(histogram, 0.50),
        "p95_ms": histogram_percentile(histogram, 0.95),
        "p99_ms": histogram_percentile(histogram, 0.99),
        "overflow_samples": histogram[HISTOGRAM_OVERFLOW_INDEX],
        "resolution": "0.1 ms below 100 ms, 1 ms below 1 s, 10 ms below 10 s, 100 ms below 120 s",
        "accounting": "each percentile is the bucket upper bound; latency is never understated",
    }


# ---------------------------------------------------------------------------
# Open-loop schedule
# ---------------------------------------------------------------------------


def intended_offsets(
    rate_per_second: float,
    duration_seconds: float,
    worker_index: int,
    worker_count: int,
) -> list[float]:
    """Intended send offsets for one worker, computed before the run starts.

    The schedule is fixed in advance and does not depend on responses — that is
    what makes this open loop. Workers interleave by a fixed phase so the
    aggregate arrival process is evenly spaced rather than bursty.
    """

    if rate_per_second <= 0:
        raise LoadGenError("rate_per_second must be positive")
    if worker_count < 1 or not 0 <= worker_index < worker_count:
        raise LoadGenError("worker_index must be within worker_count")
    interval = worker_count / float(rate_per_second)
    phase = worker_index / float(rate_per_second)
    total = int(math.floor((duration_seconds - phase) / interval)) + 1
    if total <= 0:
        return []
    return [phase + position * interval for position in range(total)]


def longest_sustained_seconds(per_second_counts: dict[int, int], target_rate: float) -> int:
    """Longest run of consecutive whole seconds meeting the target rate.

    "Sustained" means continuous, not an average and not a peak (§5 B3).
    """

    if not per_second_counts:
        return 0
    best = 0
    current = 0
    for second in range(min(per_second_counts), max(per_second_counts) + 1):
        if per_second_counts.get(second, 0) >= target_rate:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


# ---------------------------------------------------------------------------
# Bottleneck classification — the core of R9.
# ---------------------------------------------------------------------------


def classify_bottleneck(
    metrics: dict[str, Any],
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Name the limiter. Client-side causes are tested first, always.

    A CPU-starved generator under-reports server capacity and looks exactly like
    a server ceiling. Testing client causes first is what stops that mistake
    being made silently.
    """

    limits = dict(DEFAULT_THRESHOLDS)
    limits.update(thresholds or {})
    evidence: list[str] = []
    outcome = OUTCOME_INDETERMINATE

    cpu_fraction = metrics.get("generator_cpu_utilization_of_allocation")
    dispatch_deficit = metrics.get("dispatch_deficit_fraction")
    dispatch_blocked = metrics.get("dispatch_blocked_fraction")
    dispatch_lag_p99 = metrics.get("dispatch_lag_p99_ms")
    reuse_ratio = metrics.get("connection_reuse_ratio")
    time_wait_fraction = metrics.get("time_wait_fraction_of_ephemeral_range")
    error_rate = metrics.get("error_rate")
    p99 = metrics.get("corrected_p99_ms")
    offered = metrics.get("offered_rate_per_second")
    achieved = metrics.get("achieved_rate_per_second")
    sustained = metrics.get("longest_sustained_seconds_at_target")
    target = metrics.get("target_rate_per_second")

    # --- client-side, in order of how decisively each invalidates the figure ---
    if isinstance(cpu_fraction, (int, float)) and cpu_fraction >= limits[
        "generator_cpu_saturation_fraction"
    ]:
        outcome = OUTCOME_CLIENT_CPU
        evidence.append(
            f"generator consumed {cpu_fraction:.1%} of its CPU allocation "
            f"(saturation threshold {limits['generator_cpu_saturation_fraction']:.0%})"
        )
    elif isinstance(dispatch_deficit, (int, float)) and dispatch_deficit > limits[
        "max_dispatch_deficit_fraction"
    ]:
        outcome = OUTCOME_CLIENT_DISPATCH_LAG
        evidence.append(
            f"{dispatch_deficit:.2%} of scheduled sends were never issued "
            f"(limit {limits['max_dispatch_deficit_fraction']:.2%})"
        )
    elif isinstance(dispatch_lag_p99, (int, float)) and dispatch_lag_p99 > limits[
        "max_dispatch_lag_p99_ms"
    ]:
        outcome = OUTCOME_CLIENT_DISPATCH_LAG
        evidence.append(
            f"p99 dispatch lag {dispatch_lag_p99:.1f} ms exceeds "
            f"{limits['max_dispatch_lag_p99_ms']:.1f} ms; the offered rate was not actually offered"
        )
    elif isinstance(dispatch_blocked, (int, float)) and dispatch_blocked > limits[
        "max_dispatch_blocked_fraction"
    ]:
        outcome = OUTCOME_CLIENT_CONNECTION_STARVED
        evidence.append(
            f"{dispatch_blocked:.2%} of sends found no free pooled connection "
            f"(limit {limits['max_dispatch_blocked_fraction']:.2%})"
        )
    elif isinstance(reuse_ratio, (int, float)) and reuse_ratio < limits[
        "min_connection_reuse_ratio"
    ]:
        outcome = OUTCOME_CLIENT_PORT_PRESSURE
        evidence.append(
            f"connection reuse ratio {reuse_ratio:.3f} below "
            f"{limits['min_connection_reuse_ratio']:.3f}; the generator churned TCP connections"
        )
    elif isinstance(time_wait_fraction, (int, float)) and time_wait_fraction > limits[
        "max_time_wait_fraction_of_ephemeral_range"
    ]:
        outcome = OUTCOME_CLIENT_PORT_PRESSURE
        evidence.append(
            f"TIME_WAIT depth reached {time_wait_fraction:.1%} of the host ephemeral "
            f"port range (limit {limits['max_time_wait_fraction_of_ephemeral_range']:.0%})"
        )
    # --- server-side, only once the client is exonerated ---
    elif isinstance(error_rate, (int, float)) and error_rate > B3_MAX_ERROR_RATE:
        outcome = OUTCOME_SERVER_ERRORS
        evidence.append(
            f"error rate {error_rate:.3%} exceeds the fixed {B3_MAX_ERROR_RATE:.1%} criterion"
        )
    elif isinstance(p99, (int, float)) and p99 > B3_MAX_P99_MS:
        outcome = OUTCOME_SERVER_LATENCY
        evidence.append(
            f"coordinated-omission-corrected p99 {p99:.0f} ms exceeds the fixed "
            f"{B3_MAX_P99_MS:.0f} ms criterion"
        )
    elif (
        isinstance(offered, (int, float))
        and isinstance(achieved, (int, float))
        and offered > 0
        and achieved / offered >= limits["min_achieved_fraction_of_offered"]
        and isinstance(sustained, (int, float))
        and isinstance(target, (int, float))
        and sustained >= B3_MIN_SUSTAINED_SECONDS
    ):
        outcome = OUTCOME_TARGET_MET
        evidence.append(
            f"achieved {achieved:.0f}/s against an offered {offered:.0f}/s, sustained "
            f"{sustained:.0f} s at or above {target:.0f}/s"
        )
    else:
        evidence.append(
            "no single limiter met its threshold; the step neither met the target "
            "nor breached a named ceiling"
        )
        if (
            isinstance(offered, (int, float))
            and isinstance(achieved, (int, float))
            and offered > 0
        ):
            evidence.append(f"achieved/offered = {achieved / offered:.3f}")

    interpretable = outcome not in CLIENT_BOTTLENECKS
    return {
        "bottleneck": outcome,
        "bottleneck_evidence": evidence,
        "client_saturated": outcome in CLIENT_BOTTLENECKS,
        "server_capacity_interpretable": interpretable,
        "server_capacity_blocker": CLIENT_BOTTLENECK_BLOCKER.get(outcome),
        "thresholds_applied": limits,
    }


def evaluate_pass_criteria(figure: dict[str, Any]) -> dict[str, Any]:
    """Apply §5 B3 verbatim. A shortfall is a measured shortfall, never a pass."""

    reasons: list[str] = []
    sustained = figure.get("longest_sustained_seconds_at_target")
    error_rate = figure.get("error_rate")
    p99 = figure.get("corrected_p99_ms")
    target = figure.get("target_rate_per_second")
    offered = figure.get("offered_rate_per_second")
    achieved = figure.get("achieved_rate_per_second")

    if not figure.get("server_capacity_interpretable"):
        reasons.append(
            "the load generator was the limiter, so this is not a server capacity result"
        )
    if not isinstance(target, (int, float)) or float(target) < B3_TARGET_RATE_PER_SECOND:
        reasons.append(
            f"step target {target!r}/s is below the {B3_TARGET_RATE_PER_SECOND:.0f}/s criterion"
        )
    if not isinstance(sustained, (int, float)) or sustained < B3_MIN_SUSTAINED_SECONDS:
        reasons.append(
            f"sustained {sustained!r} s at target, below the "
            f"{B3_MIN_SUSTAINED_SECONDS:.0f} s continuous criterion"
        )
    if not isinstance(error_rate, (int, float)) or error_rate > B3_MAX_ERROR_RATE:
        reasons.append(f"error rate {error_rate!r} exceeds {B3_MAX_ERROR_RATE}")
    if not isinstance(p99, (int, float)) or p99 > B3_MAX_P99_MS:
        reasons.append(f"corrected p99 {p99!r} ms exceeds {B3_MAX_P99_MS:.0f} ms")
    if (
        not isinstance(offered, (int, float))
        or not isinstance(achieved, (int, float))
        or offered < achieved
    ):
        reasons.append("offered rate must be >= achieved rate for an open-loop result")

    return {
        "criteria": {
            "target_rate_per_second": B3_TARGET_RATE_PER_SECOND,
            "min_sustained_seconds": B3_MIN_SUSTAINED_SECONDS,
            "max_error_rate": B3_MAX_ERROR_RATE,
            "max_p99_ms": B3_MAX_P99_MS,
        },
        "assessment": "passed" if not reasons else "shortfall",
        "shortfall_reasons": reasons,
        "coverage_claim_eligible": False,
        "coverage_boundary": (
            "This is engineering measurement on a non-proof profile. It flips no "
            "SPEC-COVERAGE claim and is not progress toward the unclaimed "
            "'10 000 real cryptographic signatures'."
        ),
    }


def missing_required_fields(figure: dict[str, Any]) -> list[str]:
    """Fields whose absence makes the figure unreportable.

    A void measurement excuses the metric fields but never the environment ones:
    a figure always names the CPU quota it ran under, even when it measured
    nothing.
    """

    missing = [field for field in REQUIRED_ENVIRONMENT_FIELDS if figure.get(field) is None]
    void_reason = figure.get("measurement_void_reason")
    if not (isinstance(void_reason, str) and void_reason):
        missing.extend(
            field for field in REQUIRED_MEASUREMENT_FIELDS if figure.get(field) is None
        )
    return missing


def require_complete_figure(figure: dict[str, Any]) -> None:
    missing = missing_required_fields(figure)
    if missing:
        raise LoadGenError(
            "refusing to report a figure without its environment: missing "
            + ", ".join(missing)
            + ". The container CPU quota and generator CPU allocation are required "
            "fields, not footnotes."
        )


# ---------------------------------------------------------------------------
# Worker process
# ---------------------------------------------------------------------------


class _Job:
    __slots__ = ("intended_ns", "endpoint", "path", "authenticated")

    def __init__(self, intended_ns: int, endpoint: str, path: str, authenticated: bool):
        self.intended_ns = intended_ns
        self.endpoint = endpoint
        self.path = path
        self.authenticated = authenticated


def _build_paths(
    weights: dict[str, int],
    identifiers: dict[str, list[str]],
    rng: random.Random,
    count: int,
) -> list[tuple[str, str, bool]]:
    """Materialize the request plan up front so the dispatcher does no work per send."""

    pool: list[str] = []
    for name, weight in sorted(weights.items()):
        pool.extend([name] * int(weight))
    if not pool:
        raise LoadGenError("no endpoint has a positive weight")
    plan: list[tuple[str, str, bool]] = []
    for _ in range(count):
        name = pool[rng.randrange(len(pool))]
        spec = ENDPOINTS[name]
        family = spec["identifiers"]
        if family is None:
            path = spec["template"]
        else:
            values = identifiers.get(family) or []
            if not values:
                raise LoadGenError(
                    f"endpoint {name!r} needs seeded {family} identifiers; supply "
                    "--identifiers or use an identifier-free endpoint mix"
                )
            path = spec["template"].format(id=values[rng.randrange(len(values))])
        plan.append((name, path, bool(spec["authenticated"])))
    return plan


def _worker_main(config: dict[str, Any], result_queue: Any) -> None:  # pragma: no cover - process entry
    try:
        result_queue.put(_worker_run(config))
    except Exception as error:  # a worker crash is evidence, not a silent hole
        result_queue.put(
            {
                "worker_index": config.get("worker_index"),
                "failed": True,
                "error": f"{type(error).__name__}: {error}",
            }
        )


def _worker_run(config: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - needs sockets
    worker_index = int(config["worker_index"])
    affinity = try_set_process_affinity(config.get("cpu_indices") or [])
    high_resolution_timer = _begin_high_resolution_timer()

    offsets = intended_offsets(
        float(config["target_rate_per_second"]),
        float(config["duration_seconds"]),
        worker_index,
        int(config["worker_count"]),
    )
    rng = random.Random(int(config["seed"]) + worker_index)
    plan = _build_paths(config["weights"], config["identifiers"], rng, len(offsets))

    targets: list[tuple[str, int]] = [tuple(item) for item in config["targets"]]  # type: ignore[misc]
    connections_per_worker = int(config["connections_per_worker"])
    timeout = float(config["request_timeout_seconds"])
    session_token = config.get("session_token")
    warmup_seconds = float(config["warmup_seconds"])

    jobs: "queue.Queue[Any]" = queue.Queue(maxsize=connections_per_worker)

    service_histogram = new_histogram()
    corrected_histogram = new_histogram()
    lag_histogram = new_histogram()
    per_second: Counter = Counter()
    statuses: Counter = Counter()
    error_samples: list[dict[str, Any]] = []
    counters = {
        "responses": 0,
        "errors": 0,
        "connections_opened": 0,
        "requests_on_reused_connection": 0,
    }
    max_service_ms = 0.0
    lock = threading.Lock()
    start_ns = 0

    def consumer(slot: int) -> None:
        nonlocal max_service_ms
        host, port = targets[slot % len(targets)]
        connection: Any = None
        opened = 0
        reused = 0
        while True:
            job = jobs.get()
            if job is None:
                break
            sent_ns = time.perf_counter_ns()
            status: int | None = None
            error: str | None = None
            fresh = False
            try:
                if connection is None:
                    connection = http.client.HTTPConnection(host, port, timeout=timeout)
                    connection.connect()
                    opened += 1
                    fresh = True
                headers = {
                    "accept": "application/json",
                    "user-agent": "chancela-perf-loadgen/1",
                    "connection": "keep-alive",
                }
                if job.authenticated and session_token:
                    headers["x-chancela-session"] = session_token
                connection.request(ENDPOINTS[job.endpoint]["method"], job.path, headers=headers)
                response = connection.getresponse()
                response.read()
                status = response.status
                if response.will_close:
                    connection.close()
                    connection = None
            except Exception as failure:
                error = f"{type(failure).__name__}: {failure}"
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass
                    connection = None
            done_ns = time.perf_counter_ns()
            service_ms = (done_ns - sent_ns) / 1e6
            corrected_ms = (done_ns - job.intended_ns) / 1e6
            lag_ms = (sent_ns - job.intended_ns) / 1e6
            expected = ENDPOINTS[job.endpoint]["expect"]
            in_window = (done_ns - start_ns) / 1e9 >= warmup_seconds
            with lock:
                if not fresh:
                    reused += 1
                if in_window:
                    service_histogram[histogram_index(service_ms)] += 1
                    corrected_histogram[histogram_index(corrected_ms)] += 1
                    lag_histogram[histogram_index(max(0.0, lag_ms))] += 1
                    per_second[int((done_ns - start_ns) / 1_000_000_000)] += 1
                    statuses[str(status)] += 1
                    counters["responses"] += 1
                    if status not in expected:
                        counters["errors"] += 1
                        if len(error_samples) < 20:
                            error_samples.append({"status": status, "error": error})
                    max_service_ms = max(max_service_ms, service_ms)
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        with lock:
            counters["connections_opened"] += opened
            counters["requests_on_reused_connection"] += reused

    threads = [
        threading.Thread(target=consumer, args=(slot,), name=f"loadgen-{worker_index}-{slot}")
        for slot in range(connections_per_worker)
    ]
    for thread in threads:
        thread.start()

    barrier_ns = int(config["start_at_perf_ns"])
    while time.perf_counter_ns() < barrier_ns:
        time.sleep(0.0005)
    start_ns = barrier_ns

    issued = 0
    blocked = 0
    position = 0
    total = len(offsets)
    while position < total:
        intended_ns = start_ns + int(offsets[position] * 1e9)
        now = time.perf_counter_ns()
        if now < intended_ns:
            # Micro-batched pacing: sleep only in short ticks so that Windows timer
            # coarseness shows up as measured dispatch lag rather than silent drift.
            time.sleep(min(0.001, (intended_ns - now) / 1e9))
            continue
        endpoint, path, authenticated = plan[position]
        try:
            jobs.put_nowait(_Job(intended_ns, endpoint, path, authenticated))
            issued += 1
        except Exception:
            blocked += 1
        position += 1

    for _ in threads:
        jobs.put(None)
    for thread in threads:
        thread.join(timeout=timeout + 30.0)

    wall_seconds = (time.perf_counter_ns() - start_ns) / 1e9
    return {
        "worker_index": worker_index,
        "failed": False,
        "scheduled": total,
        "issued": issued,
        "dispatch_blocked": blocked,
        "responses": counters["responses"],
        "errors": counters["errors"],
        "connections_opened": counters["connections_opened"],
        "requests_on_reused_connection": counters["requests_on_reused_connection"],
        "service_histogram": service_histogram,
        "corrected_histogram": corrected_histogram,
        "lag_histogram": lag_histogram,
        "per_second": dict(per_second),
        "statuses": dict(statuses),
        "error_samples": error_samples,
        "max_service_ms": max_service_ms,
        "cpu_seconds": time.process_time(),
        "wall_seconds": wall_seconds,
        "affinity": affinity,
        "high_resolution_timer": high_resolution_timer,
    }


def _measurement_void_reason(
    results: Sequence[dict[str, Any]], issued: int, responses: int
) -> str | None:
    if not results:
        return "no worker process reported a result"
    if responses:
        return None
    if not issued:
        return "no request was issued"
    return f"all {issued} issued requests failed; no response was received"


def aggregate_worker_results(
    results: Sequence[dict[str, Any]],
    *,
    measured_seconds: float,
    total_seconds: float,
    generator_cpu_allocation: int,
    ephemeral_ports: int | None,
    time_wait_peak: int | None,
) -> dict[str, Any]:
    """Merge worker summaries into the metrics classification consumes.

    Pure: no sockets, no processes. This is what the unit tests exercise.
    """

    failures = [item for item in results if item.get("failed")]
    scheduled = sum(int(item.get("scheduled", 0)) for item in results)
    issued = sum(int(item.get("issued", 0)) for item in results)
    blocked = sum(int(item.get("dispatch_blocked", 0)) for item in results)
    responses = sum(int(item.get("responses", 0)) for item in results)
    errors = sum(int(item.get("errors", 0)) for item in results)
    opened = sum(int(item.get("connections_opened", 0)) for item in results)
    reused = sum(int(item.get("requests_on_reused_connection", 0)) for item in results)
    cpu_seconds = sum(float(item.get("cpu_seconds", 0.0)) for item in results)
    wall_seconds = max(
        [float(item.get("wall_seconds", 0.0)) for item in results] or [0.0]
    )

    service = merge_histograms(
        item["service_histogram"] for item in results if "service_histogram" in item
    )
    corrected = merge_histograms(
        item["corrected_histogram"] for item in results if "corrected_histogram" in item
    )
    lag = merge_histograms(item["lag_histogram"] for item in results if "lag_histogram" in item)

    per_second: Counter = Counter()
    statuses: Counter = Counter()
    for item in results:
        for second, count in (item.get("per_second") or {}).items():
            per_second[int(second)] += int(count)
        for status, count in (item.get("statuses") or {}).items():
            statuses[str(status)] += int(count)

    # Achieved rate is measured over the post-warmup window; sends are scheduled
    # across the whole step, so issued rate uses the full duration. Mixing the two
    # would inflate the offered rate by the warmup fraction.
    window = max(measured_seconds, 1e-9)
    whole = max(total_seconds, 1e-9)
    denominator = max(1, opened + reused)
    reuse_ratio = reused / denominator
    time_wait_fraction = None
    if isinstance(time_wait_peak, int) and isinstance(ephemeral_ports, int) and ephemeral_ports:
        time_wait_fraction = time_wait_peak / float(ephemeral_ports)

    cpu_utilization = None
    if generator_cpu_allocation > 0 and wall_seconds > 0:
        cpu_utilization = cpu_seconds / (wall_seconds * generator_cpu_allocation)

    return {
        "worker_failures": [
            {"worker_index": item.get("worker_index"), "error": item.get("error")}
            for item in failures
        ],
        "scheduled_sends": scheduled,
        "issued_sends": issued,
        "dispatch_blocked": blocked,
        "dispatch_deficit_fraction": (scheduled - issued) / scheduled if scheduled else None,
        "dispatch_blocked_fraction": blocked / scheduled if scheduled else None,
        "dispatch_lag_p99_ms": histogram_percentile(lag, 0.99),
        "dispatch_lag_p50_ms": histogram_percentile(lag, 0.50),
        "responses": responses,
        "errors": errors,
        # No responses with requests issued is a 100% failure, not an absence of
        # data. Only a step that issued nothing has no error rate.
        "error_rate": (errors / responses) if responses else (1.0 if issued else None),
        "measurement_void_reason": _measurement_void_reason(results, issued, responses),
        "statuses": dict(sorted(statuses.items())),
        "connections_opened": opened,
        "requests_on_reused_connection": reused,
        "connection_reuse_ratio": reuse_ratio,
        "time_wait_peak": time_wait_peak,
        "time_wait_fraction_of_ephemeral_range": time_wait_fraction,
        "generator_cpu_seconds": cpu_seconds,
        "generator_wall_seconds": wall_seconds,
        "generator_cpu_utilization_of_allocation": cpu_utilization,
        "generator_cpu_pinning": summarize_affinity(results),
        "issued_rate_per_second": issued / whole,
        "achieved_rate_per_second": responses / window,
        "successful_rate_per_second": (responses - errors) / window,
        "service_latency": histogram_report(service),
        "corrected_latency": histogram_report(corrected),
        "dispatch_lag_latency": histogram_report(lag),
        "corrected_p99_ms": histogram_percentile(corrected, 0.99),
        "corrected_p95_ms": histogram_percentile(corrected, 0.95),
        "corrected_p50_ms": histogram_percentile(corrected, 0.50),
        "service_p99_ms": histogram_percentile(service, 0.99),
        "per_second_completions": dict(sorted(per_second.items())),
        "latency_accounting": (
            "corrected_* subtracts the INTENDED send time, removing coordinated "
            "omission; service_* subtracts the actual send time and understates "
            "queueing delay"
        ),
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _format_number(value: Any, digits: int = 2) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:,.{digits}f}"
    return str(value)


def _format_percent(value: Any) -> str:
    return "n/a" if not isinstance(value, (int, float)) else f"{value:.1%}"


def render_figure_markdown(figure: dict[str, Any]) -> str:
    """Render one step. Refuses to render without the environment fields."""

    require_complete_figure(figure)
    lines: list[str] = []
    lines.append(f"### {figure['stage']} / {figure['step']}")
    lines.append("")
    if figure.get("measurement_void_reason"):
        lines.append(
            f"> ⚠️ **Nothing was measured: {figure['measurement_void_reason']}.** "
            "The environment below is recorded anyway so the void is attributable."
        )
        lines.append("")
    lines.append(
        f"**Container CPU quota: {figure['container_cpu_quota_per_app_node']} CPUs per app "
        f"node x {figure.get('container_cpu_quota_app_replicas', '?')} replicas = "
        f"{figure['container_cpu_quota_app_total']} CPUs "
        f"({figure['container_cpu_quota_source']}). "
        f"Generator CPU allocation: {figure['generator_cpu_allocation']} logical CPUs "
        f"across {figure['generator_worker_processes']} processes, "
        f"{_format_percent(figure['generator_cpu_utilization_of_allocation'])} utilized. "
        f"Docker VM: {figure['docker_vm_logical_cpus']} logical CPUs of "
        f"{figure['host_logical_cpus']} on the host.**"
    )
    lines.append("")
    pinning = figure["generator_cpu_pinning"]
    lines.append(
        f"Generator CPU pinning: {pinning.get('pinned_workers')}/{pinning.get('workers')} "
        f"worker processes pinned. {pinning.get('caveat', '')}"
    )
    lines.append("")
    lines.append(f"Transport: {figure['transport_path']} — {figure['transport_disclosure']}.")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Offered rate | {_format_number(figure['offered_rate_per_second'], 0)} req/s |")
    lines.append(f"| Issued rate | {_format_number(figure['issued_rate_per_second'], 0)} req/s |")
    lines.append(f"| Achieved rate | {_format_number(figure['achieved_rate_per_second'], 0)} req/s |")
    lines.append(
        f"| Longest sustained window at target | "
        f"{_format_number(figure['longest_sustained_seconds_at_target'], 0)} s |"
    )
    error_rate = figure["error_rate"]
    lines.append(
        "| Error rate | "
        + (_format_number(100.0 * float(error_rate), 3) + " %" if error_rate is not None else "n/a")
        + " |"
    )
    lines.append(f"| p99 (coordinated-omission corrected) | {_format_number(figure['corrected_p99_ms'], 1)} ms |")
    lines.append(f"| p99 (service time only) | {_format_number(figure.get('service_p99_ms'), 1)} ms |")
    lines.append(f"| Connection reuse ratio | {_format_number(figure.get('connection_reuse_ratio'), 4)} |")
    lines.append(f"| TIME_WAIT peak | {_format_number(figure.get('time_wait_peak'), 0)} |")
    lines.append(f"| **Bottleneck** | **{figure['bottleneck']}** |")
    lines.append("")
    for item in figure.get("bottleneck_evidence") or []:
        lines.append(f"- {item}")
    lines.append("")
    if not figure["server_capacity_interpretable"]:
        lines.append(
            f"> 🔴 **CLIENT SATURATED — NOT A SERVER RESULT.** "
            f"{figure.get('server_capacity_blocker')}"
        )
        lines.append("")
    assessment = figure.get("pass_criteria") or {}
    lines.append(f"Assessment: **{assessment.get('assessment', 'unknown')}**")
    for reason in assessment.get("shortfall_reasons") or []:
        lines.append(f"- shortfall: {reason}")
    lines.append("")
    lines.append(
        f"Profile proof eligibility: `{figure['proof_eligible']}`. "
        f"{assessment.get('coverage_boundary', '')}"
    )
    lines.append("")
    return "\n".join(lines)


def render_report_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# t57 B3 — open-loop API throughput",
        "",
        f"Generated {report.get('generated_at')}.",
        "",
        "**Every figure below records the container CPU quota it ran under and the "
        "load generator's CPU allocation. A figure produced at a raised quota is not "
        "a figure produced under production-shaped limits, and the two are not "
        "interchangeable.**",
        "",
        f"Mandatory disclosure: {report.get('transport_disclosure')}. This is not a "
        "networked benchmark and must not be written up as one.",
        "",
    ]
    for figure in report.get("figures") or []:
        lines.append(render_figure_markdown(figure))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


def resolve_targets(base_urls: Sequence[str]) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []
    for url in base_urls:
        match = re.fullmatch(r"http://([^/:]+)(?::(\d+))?/?", url.strip())
        if not match:
            raise LoadGenError(f"unsupported base url {url!r}; expected http://host[:port]")
        host = match.group(1)
        port = int(match.group(2) or 80)
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as error:
            raise LoadGenError(f"cannot resolve {url!r}: {error}") from error
        for address in sorted({info[4][0] for info in infos}):
            if (address, port) not in targets:
                targets.append((address, port))
    if not targets:
        raise LoadGenError("no reachable targets resolved")
    return targets


def login_once(host: str, port: int, user_id: str, password: str, timeout: float) -> str:
    """One request. Used to obtain a session token; not part of any measurement."""

    body = json.dumps({"user_id": user_id, "password": password}).encode("utf-8")
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(
            "POST",
            "/v1/session",
            body=body,
            headers={"content-type": "application/json", "accept": "application/json"},
        )
        response = connection.getresponse()
        payload = response.read()
        if response.status not in (200, 201):
            raise LoadGenError(f"login failed: status={response.status} body={payload[:200]!r}")
        token = json.loads(payload).get("token")
        if not isinstance(token, str) or not token:
            raise LoadGenError("login response carried no token")
        return token
    finally:
        connection.close()


def environment_snapshot(project_name: str, stage: dict[str, Any]) -> dict[str, Any]:
    observed = observe_app_cpu_quota(project_name)
    return {
        "captured_at": utc_now(),
        "stage": stage["name"],
        "host_logical_cpus": host_logical_cpus(),
        "docker_vm_logical_cpus": docker_vm_logical_cpus(),
        "ephemeral_port_range": ephemeral_port_range(),
        "socket_state_before": sample_socket_state(),
        "observed_app_cpu_quota": observed,
        "declared_app_cpus": float(stage["app_cpus"]),
        "declared_app_replicas": int(stage["app_replicas"]),
        "declared_search_projector_cpus": float(stage["search_projector_cpus"]),
        "quota_blockers": quota_blockers(stage, observed),
    }


def load_environment_snapshot(path: pathlib.Path, stage: dict[str, Any]) -> dict[str, Any]:
    """Reuse a host-captured environment for a run made from inside the container network.

    The direct-to-replica transport has to run inside the Docker network, where
    there is no Docker CLI to observe the container CPU quota. Capturing the
    snapshot on the host with ``preflight`` and passing it in keeps the observed
    quota on the figure instead of downgrading it to a declared one. The snapshot
    must name the same stage — pairing a 2.0-CPU snapshot with a raised-quota run
    is exactly the confusion this lane exists to prevent.
    """

    snapshot = read_json(path)
    if snapshot.get("stage") != stage["name"]:
        raise LoadGenError(
            f"environment snapshot was captured for stage {snapshot.get('stage')!r} but "
            f"the run is stage {stage['name']!r}; a quota observed under one stage "
            "must never be attached to another"
        )
    declared = snapshot.get("declared_app_cpus")
    if not isinstance(declared, (int, float)) or not math.isclose(
        float(declared), float(stage["app_cpus"]), rel_tol=0.0, abs_tol=0.01
    ):
        raise LoadGenError(
            f"environment snapshot declares {declared!r} app CPUs but the stage "
            f"declares {stage['app_cpus']!r}"
        )
    for field in ("host_logical_cpus", "docker_vm_logical_cpus", "observed_app_cpu_quota"):
        if field not in snapshot:
            raise LoadGenError(f"environment snapshot is missing {field}")
    snapshot["quota_blockers"] = quota_blockers(stage, snapshot["observed_app_cpu_quota"])
    snapshot["reused_from"] = str(path)
    return snapshot


def build_figure(
    *,
    stage: dict[str, Any],
    step: dict[str, Any],
    metrics: dict[str, Any],
    environment: dict[str, Any],
    generator: dict[str, Any],
    transport_path: str,
    thresholds: dict[str, float],
) -> dict[str, Any]:
    observed = environment.get("observed_app_cpu_quota") or {}
    quota_verified = observed.get("consistent") and observed.get("per_container_cpus") is not None
    per_node = (
        float(observed["per_container_cpus"]) if quota_verified else float(stage["app_cpus"])
    )
    replicas = int(stage["app_replicas"])
    measured_seconds = float(step["duration_seconds"]) - float(step["warmup_seconds"])
    target = float(step["target_rate_per_second"])

    figure: dict[str, Any] = {
        "stage": stage["name"],
        "step": step["name"],
        "proof_eligible": False,
        "container_cpu_quota_per_app_node": per_node,
        "container_cpu_quota_app_replicas": replicas,
        "container_cpu_quota_app_total": per_node * replicas,
        "container_cpu_quota_source": "observed" if quota_verified else "declared-unverified",
        "container_cpu_quota_blockers": environment.get("quota_blockers") or [],
        "search_projector_cpu_quota": float(stage["search_projector_cpus"]),
        "generator_worker_processes": int(generator["worker_processes"]),
        "generator_cpu_allocation": int(generator["cpu_allocation"]),
        "generator_connections_total": int(generator["worker_processes"])
        * int(generator["connections_per_worker"]),
        "docker_vm_logical_cpus": environment.get("docker_vm_logical_cpus"),
        "host_logical_cpus": environment.get("host_logical_cpus"),
        "transport_path": transport_path,
        "transport_disclosure": (
            LOOPBACK_DISCLOSURE if transport_path == "docker-desktop-port-proxy" else DIRECT_DISCLOSURE
        ),
        "endpoint_mix": dict(sorted(stage["weights"].items())),
        "endpoint_payloads": {
            name: ENDPOINTS[name]["payload"] for name in sorted(stage["weights"]) if stage["weights"][name]
        },
        "target_rate_per_second": target,
        # The offered rate is the schedule, which is fixed before the step starts
        # and does not depend on responses. That is what makes this open loop.
        "offered_rate_per_second": target,
        "measured_window_seconds": measured_seconds,
        "warmup_seconds": float(step["warmup_seconds"]),
        "longest_sustained_seconds_at_target": longest_sustained_seconds(
            metrics.get("per_second_completions") or {}, target
        ),
    }
    figure.update(
        {
            key: metrics.get(key)
            for key in (
                "issued_rate_per_second",
                "achieved_rate_per_second",
                "successful_rate_per_second",
                "error_rate",
                "errors",
                "responses",
                "statuses",
                "scheduled_sends",
                "issued_sends",
                "dispatch_blocked",
                "dispatch_deficit_fraction",
                "dispatch_blocked_fraction",
                "dispatch_lag_p99_ms",
                "dispatch_lag_p50_ms",
                "connections_opened",
                "connection_reuse_ratio",
                "time_wait_peak",
                "time_wait_fraction_of_ephemeral_range",
                "generator_cpu_seconds",
                "generator_cpu_utilization_of_allocation",
                "generator_cpu_pinning",
                "corrected_p99_ms",
                "corrected_p95_ms",
                "corrected_p50_ms",
                "service_p99_ms",
                "service_latency",
                "corrected_latency",
                "dispatch_lag_latency",
                "latency_accounting",
                "worker_failures",
                "measurement_void_reason",
            )
        }
    )
    classification_input = dict(figure)
    classification_input["offered_rate_per_second"] = figure["offered_rate_per_second"]
    figure.update(classify_bottleneck(classification_input, thresholds))
    figure["pass_criteria"] = evaluate_pass_criteria(figure)
    require_complete_figure(figure)
    return figure


def run_step(
    *,
    stage: dict[str, Any],
    step: dict[str, Any],
    profile: dict[str, Any],
    targets: Sequence[tuple[str, int]],
    identifiers: dict[str, list[str]],
    session_token: str | None,
    environment: dict[str, Any],
    transport_path: str,
) -> dict[str, Any]:  # pragma: no cover - drives real sockets
    generator = profile["generator"]
    worker_count = int(generator["worker_processes"])
    cpu_allocation = int(generator["cpu_allocation"])
    cpu_slices = generator_cpu_slices(
        worker_count,
        cpu_allocation,
        int(generator.get("cpu_index_base", 0)),
        host_logical_cpus() or cpu_allocation,
    )

    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    start_at = time.perf_counter_ns() + int(3e9)
    processes = []
    for worker_index in range(worker_count):
        config = {
            "worker_index": worker_index,
            "worker_count": worker_count,
            "cpu_indices": cpu_slices[worker_index],
            "target_rate_per_second": float(step["target_rate_per_second"]),
            "duration_seconds": float(step["duration_seconds"]),
            "warmup_seconds": float(step["warmup_seconds"]),
            "connections_per_worker": int(generator["connections_per_worker"]),
            "request_timeout_seconds": float(generator["request_timeout_seconds"]),
            "weights": stage["weights"],
            "identifiers": identifiers,
            "targets": [list(item) for item in targets],
            "session_token": session_token,
            "seed": int(profile.get("seed", 20260727)),
            "start_at_perf_ns": start_at,
        }
        process = context.Process(target=_worker_main, args=(config, result_queue), daemon=False)
        process.start()
        processes.append(process)

    results: list[dict[str, Any]] = []
    deadline = time.monotonic() + float(step["duration_seconds"]) + 180.0
    while len(results) < worker_count and time.monotonic() < deadline:
        try:
            results.append(result_queue.get(timeout=5.0))
        except Exception:
            continue
    for process in processes:
        process.join(timeout=30.0)
        if process.is_alive():
            process.terminate()

    socket_after = sample_socket_state()
    ports = (environment.get("ephemeral_port_range") or {}).get("port_count")
    time_wait_peak = None
    before = (environment.get("socket_state_before") or {}).get("time_wait")
    after = socket_after.get("time_wait")
    candidates = [value for value in (before, after) if isinstance(value, int)]
    if candidates:
        time_wait_peak = max(candidates)

    metrics = aggregate_worker_results(
        results,
        measured_seconds=float(step["duration_seconds"]) - float(step["warmup_seconds"]),
        total_seconds=float(step["duration_seconds"]),
        generator_cpu_allocation=cpu_allocation,
        ephemeral_ports=ports if isinstance(ports, int) else None,
        time_wait_peak=time_wait_peak,
    )
    metrics["socket_state_after"] = socket_after
    if len(results) < worker_count:
        metrics.setdefault("worker_failures", []).append(
            {"worker_index": None, "error": f"only {len(results)}/{worker_count} workers reported"}
        )
    return build_figure(
        stage=stage,
        step=step,
        metrics=metrics,
        environment=environment,
        generator=generator,
        transport_path=transport_path,
        thresholds=profile.get("thresholds") or {},
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def find_stage(profile: dict[str, Any], name: str) -> dict[str, Any]:
    for stage in profile["stages"]:
        if stage["name"] == name:
            return stage
    known = ", ".join(stage["name"] for stage in profile["stages"])
    raise LoadGenError(f"unknown stage {name!r}; profile defines: {known}")


def load_identifiers(path: pathlib.Path | None) -> dict[str, list[str]]:
    if path is None:
        return {family: [] for family in IDENTIFIER_FAMILIES}
    document = read_json(path)
    identifiers: dict[str, list[str]] = {}
    for family in IDENTIFIER_FAMILIES:
        values = document.get(family) or []
        if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
            raise LoadGenError(f"identifiers.{family} must be an array of strings")
        identifiers[family] = values
    return identifiers


def stage_environment_exports(stage: dict[str, Any]) -> list[str]:
    return [
        f"{APP_CPUS_ENV}={stage['app_cpus']}",
        f"{PROJECTOR_CPUS_ENV}={stage['search_projector_cpus']}",
        f"CHANCELA_CLUSTER_REPLICAS={stage['app_replicas']}",
    ]


def command_plan(args: argparse.Namespace) -> int:
    profile = read_json(pathlib.Path(args.profile))
    validate_profile(profile)
    plan: dict[str, Any] = {
        "profile": profile["name"],
        "proof_eligible": profile["proof_eligible"],
        "host_logical_cpus": host_logical_cpus(),
        "docker_vm_logical_cpus": docker_vm_logical_cpus(),
        "generator": profile["generator"],
        "persistent_connections": int(profile["generator"]["worker_processes"])
        * int(profile["generator"]["connections_per_worker"]),
        "stages": [],
    }
    for stage in profile["stages"]:
        plan["stages"].append(
            {
                "name": stage["name"],
                "app_cpus": stage["app_cpus"],
                "app_replicas": stage["app_replicas"],
                "app_cpu_total": float(stage["app_cpus"]) * int(stage["app_replicas"]),
                "search_projector_cpus": stage["search_projector_cpus"],
                "environment": stage_environment_exports(stage),
                "steps": [
                    {
                        "name": step["name"],
                        "target_rate_per_second": step["target_rate_per_second"],
                        "duration_seconds": step["duration_seconds"],
                        "warmup_seconds": step["warmup_seconds"],
                        "scheduled_requests": int(
                            float(step["target_rate_per_second"]) * float(step["duration_seconds"])
                        ),
                    }
                    for step in stage["steps"]
                ],
            }
        )
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


def command_env(args: argparse.Namespace) -> int:
    profile = read_json(pathlib.Path(args.profile))
    validate_profile(profile)
    stage = find_stage(profile, args.stage)
    for line in stage_environment_exports(stage):
        print(line)
    return 0


def command_preflight(args: argparse.Namespace) -> int:
    profile = read_json(pathlib.Path(args.profile))
    validate_profile(profile)
    stage = find_stage(profile, args.stage)
    environment = environment_snapshot(args.project_name, stage)
    targets = resolve_targets(args.base_url)
    environment["targets"] = [f"{host}:{port}" for host, port in targets]
    blockers = list(environment["quota_blockers"])
    identifiers = load_identifiers(
        pathlib.Path(args.identifiers) if args.identifiers else None
    )
    for name, weight in stage["weights"].items():
        family = ENDPOINTS[name]["identifiers"]
        if weight and family and not identifiers.get(family):
            blockers.append(
                f"stage {stage['name']!r} weights {name!r} but no seeded {family} "
                "identifiers were supplied"
            )
    environment["preflight_blockers"] = blockers
    print(json.dumps(environment, indent=2, sort_keys=True))
    return 0 if not blockers else 1


def command_verify_slo(args: argparse.Namespace) -> int:
    slo = read_json(pathlib.Path(args.slo))
    validate_slo(slo)
    print(
        json.dumps(
            {
                "slo": str(args.slo),
                "assessment": "matches the fixed t57 §5 B3 pass criteria",
                "criteria": slo["pass_criteria"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def run_release_blockers(args: argparse.Namespace) -> list[str]:
    """Being build-complete is not authorization to generate load."""

    blockers = []
    if os.environ.get(RELEASE_ENV) != "1":
        blockers.append(
            f"{RELEASE_ENV}=1 is not set. The benchmark window is scheduled and "
            "exclusive; this generator refuses to produce load without it."
        )
    if not getattr(args, "exclusive_window_released", False):
        blockers.append(
            "--exclusive-window-released was not passed. Runs happen only in the "
            "coordinator-released window, with no other lane active."
        )
    return blockers


def command_run(args: argparse.Namespace) -> int:  # pragma: no cover - drives real sockets
    blockers = run_release_blockers(args)
    if blockers:
        for blocker in blockers:
            print(f"REFUSED: {blocker}", file=sys.stderr)
        return 3

    profile = read_json(pathlib.Path(args.profile))
    validate_profile(profile)
    if args.slo:
        validate_slo(read_json(pathlib.Path(args.slo)))
    stage = find_stage(profile, args.stage)
    if args.environment_file:
        environment = load_environment_snapshot(pathlib.Path(args.environment_file), stage)
    else:
        environment = environment_snapshot(args.project_name, stage)
    if environment["quota_blockers"] and not args.allow_quota_mismatch:
        for blocker in environment["quota_blockers"]:
            print(f"REFUSED: {blocker}", file=sys.stderr)
        return 4

    identifiers = load_identifiers(
        pathlib.Path(args.identifiers) if args.identifiers else None
    )
    targets = resolve_targets(args.base_url)
    session_token = args.session_token
    if session_token is None and args.login_user_id:
        session_token = login_once(
            targets[0][0],
            targets[0][1],
            args.login_user_id,
            args.login_password,
            float(profile["generator"]["request_timeout_seconds"]),
        )

    figures = []
    for step in stage["steps"]:
        figure = run_step(
            stage=stage,
            step=step,
            profile=profile,
            targets=targets,
            identifiers=identifiers,
            session_token=session_token,
            environment=environment,
            transport_path=args.transport_path,
        )
        figures.append(figure)
        print(
            f"[{stage['name']}/{step['name']}] target="
            f"{step['target_rate_per_second']}/s achieved="
            f"{figure['achieved_rate_per_second']:.0f}/s bottleneck={figure['bottleneck']}"
        )

    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "profile": profile["name"],
        "proof_eligible": False,
        "stage": stage["name"],
        "environment": environment,
        "transport_path": args.transport_path,
        "transport_disclosure": (
            LOOPBACK_DISCLOSURE
            if args.transport_path == "docker-desktop-port-proxy"
            else DIRECT_DISCLOSURE
        ),
        "figures": figures,
        "coverage_boundary": (
            "Non-proof profile at a raised container CPU quota. Flips no "
            "SPEC-COVERAGE claim under any outcome."
        ),
    }
    report_dir = pathlib.Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    write_json(report_dir / f"loadgen-{stage['name']}.json", report)
    atomic_write_text_lf(
        report_dir / f"loadgen-{stage['name']}.md", render_report_markdown(report)
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="print the rate ladder and CPU budget; no load")
    plan.add_argument("--profile", required=True)
    plan.set_defaults(handler=command_plan)

    env = subparsers.add_parser(
        "env", help="print the container CPU quota environment for one stage"
    )
    env.add_argument("--profile", required=True)
    env.add_argument("--stage", required=True)
    env.set_defaults(handler=command_env)

    preflight = subparsers.add_parser(
        "preflight", help="verify the observed CPU quota and targets; generates no load"
    )
    preflight.add_argument("--profile", required=True)
    preflight.add_argument("--stage", required=True)
    preflight.add_argument("--base-url", action="append", required=True)
    preflight.add_argument("--project-name", default=os.environ.get("CHANCELA_PERF_PROJECT_NAME", "chancela-perf"))
    preflight.add_argument("--identifiers")
    preflight.set_defaults(handler=command_preflight)

    verify = subparsers.add_parser(
        "verify-slo", help="assert the SLO still encodes the fixed pass criteria"
    )
    verify.add_argument("--slo", required=True)
    verify.set_defaults(handler=command_verify_slo)

    run = subparsers.add_parser("run", help="execute the rate ladder (gated)")
    run.add_argument("--profile", required=True)
    run.add_argument("--stage", required=True)
    run.add_argument("--base-url", action="append", required=True)
    run.add_argument("--report-dir", required=True)
    run.add_argument("--slo")
    run.add_argument("--identifiers")
    run.add_argument("--project-name", default=os.environ.get("CHANCELA_PERF_PROJECT_NAME", "chancela-perf"))
    run.add_argument("--session-token")
    run.add_argument("--login-user-id")
    run.add_argument("--login-password", default="Perf-Only-Password-2026!")
    run.add_argument(
        "--transport-path",
        choices=("docker-desktop-port-proxy", "direct-container-network"),
        required=True,
    )
    run.add_argument("--allow-quota-mismatch", action="store_true")
    run.add_argument(
        "--environment-file",
        help=(
            "host-captured preflight snapshot, for runs made from inside the "
            "container network where the Docker CLI is unavailable"
        ),
    )
    run.add_argument(
        "--exclusive-window-released",
        action="store_true",
        help="assert the coordinator released the exclusive benchmark window",
    )
    run.set_defaults(handler=command_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except LoadGenError as error:
        print(f"loadgen error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
