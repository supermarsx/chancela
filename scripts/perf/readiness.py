#!/usr/bin/env python3
"""Bounded preflight wait for the exact performance container topology."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

import topology


READY = "ready"
RETRYABLE = "retryable"
TERMINAL = "terminal"
MAX_TIMEOUT_SECONDS = 900.0
MAX_POLL_SECONDS = 30.0
MAX_COMMAND_SECONDS = 5.0


class ReadinessDeadlineExceeded(topology.TopologyError):
    def __init__(
        self,
        message: str,
        snapshot: dict[str, list[dict[str, Any]]],
    ) -> None:
        super().__init__(message)
        self.snapshot = snapshot


def expected_counts(expected_replicas: int) -> dict[str, int]:
    return {
        "chancela-cluster": expected_replicas,
        **topology.SERVICE_REPLICA_COUNTS,
    }


def classify_snapshot(
    containers: dict[str, list[dict[str, Any]]],
    expected_replicas: int,
) -> tuple[str, list[str]]:
    """Only a running, never-restarted `starting` health is retryable."""
    failures: list[str] = []
    waiting: list[str] = []
    for service, expected in expected_counts(expected_replicas).items():
        observed = containers.get(service)
        if not isinstance(observed, list) or len(observed) != expected:
            actual = len(observed) if isinstance(observed, list) else "malformed"
            failures.append(
                f"{service} expected {expected} containers, observed {actual}"
            )
            continue
        for container in observed:
            label = container.get("name") or container.get("id") or "unknown"
            prefix = f"{service}/{label}"
            if container.get("oom_killed") is True:
                failures.append(f"{prefix} was OOM-killed")
                continue
            restart_count = container.get("restart_count")
            try:
                restarts = int(restart_count or 0)
            except (TypeError, ValueError):
                failures.append(
                    f"{prefix} has malformed restart count {restart_count!r}"
                )
                continue
            if restarts != 0:
                failures.append(f"{prefix} restarted {restarts} times")
                continue
            if container.get("running") is not True:
                failures.append(
                    f"{prefix} is not running (status={container.get('status')!r})"
                )
                continue
            health = container.get("health")
            if health == "healthy":
                continue
            if health == "starting":
                waiting.append(f"{prefix} health is starting")
                continue
            failures.append(f"{prefix} health is {health!r}")
    for service in topology.FORBIDDEN_CLUSTER_SERVICES:
        observed = containers.get(service, [])
        if not isinstance(observed, list):
            failures.append(f"{service} container snapshot is malformed")
            continue
        for container in observed:
            if container.get("running") is True:
                label = container.get("name") or container.get("id") or "unknown"
                failures.append(
                    f"forbidden standalone service {service}/{label} is running"
                )
    if failures:
        return TERMINAL, failures
    if waiting:
        return RETRYABLE, waiting
    return READY, []


def compose_prefix(
    compose_files: list[pathlib.Path],
    profiles: list[str],
    project_name: str | None,
) -> list[str]:
    command = ["docker", "compose"]
    if project_name:
        command.extend(["--project-name", project_name])
    for compose_file in compose_files:
        command.extend(["-f", str(compose_file)])
    for profile in profiles:
        command.extend(["--profile", profile])
    return command


def capture_snapshot(
    compose: list[str],
    deadline: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    command_runner: Callable[..., str] = topology.command,
) -> dict[str, list[dict[str, Any]]]:
    containers: dict[str, list[dict[str, Any]]] = {
        service: [] for service in topology.CAPTURED_SERVICES
    }

    def bounded_command(args: list[str]) -> str:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ReadinessDeadlineExceeded(
                "container readiness snapshot exhausted its deadline before "
                f"command: {' '.join(args)}",
                containers,
            )
        command_timeout = max(
            0.001,
            min(MAX_COMMAND_SECONDS, remaining),
        )
        try:
            return command_runner(args, timeout=command_timeout)
        except subprocess.TimeoutExpired as error:
            raise ReadinessDeadlineExceeded(
                "container readiness command timed out after "
                f"{command_timeout:.3f}s: {' '.join(args)}",
                containers,
            ) from error

    for service in topology.CAPTURED_SERVICES:
        identifiers = [
            item
            for item in bounded_command(
                [*compose, "ps", "--all", "-q", service]
            ).splitlines()
            if item
        ]
        if identifiers:
            inspected = json.loads(
                bounded_command(["docker", "inspect", *identifiers])
            )
            containers[service] = [
                topology.inspect_summary(item) for item in inspected
            ]
    return containers


def readiness_report(
    snapshot_reader: Callable[[float], dict[str, list[dict[str, Any]]]],
    expected_replicas: int,
    timeout_seconds: float,
    poll_seconds: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    started = monotonic()
    deadline = started + timeout_seconds
    next_poll = started
    attempts = 0
    last_snapshot: dict[str, list[dict[str, Any]]] = {}
    last_diagnostics: list[str] = []
    while True:
        before_snapshot = monotonic()
        remaining = deadline - before_snapshot
        if remaining <= 0:
            outcome = "timeout"
            elapsed = max(0.0, before_snapshot - started)
            break
        attempts += 1
        try:
            last_snapshot = snapshot_reader(deadline)
        except ReadinessDeadlineExceeded as error:
            last_snapshot = error.snapshot
            last_diagnostics = [str(error)]
            outcome = "timeout"
            elapsed = max(0.0, monotonic() - started)
            break
        except subprocess.TimeoutExpired as error:
            last_diagnostics = [
                "container readiness command timed out: "
                + " ".join(str(item) for item in error.cmd)
            ]
            outcome = "timeout"
            elapsed = max(0.0, monotonic() - started)
            break
        state, last_diagnostics = classify_snapshot(
            last_snapshot, expected_replicas
        )
        observed = monotonic()
        elapsed = max(0.0, observed - started)
        if state == READY:
            outcome = READY
            break
        if state == TERMINAL:
            outcome = TERMINAL
            break
        if observed >= deadline:
            outcome = "timeout"
            break
        next_poll += poll_seconds
        sleeper(max(0.0, min(next_poll, deadline) - observed))
    return {
        "schema_version": 1,
        "captured_at": topology.utc_now(),
        "outcome": outcome,
        "ready": outcome == READY,
        "attempts": attempts,
        "elapsed_seconds": round(elapsed, 6),
        "timeout_seconds": timeout_seconds,
        "poll_seconds": poll_seconds,
        "diagnostics": last_diagnostics,
        "last_snapshot": last_snapshot,
    }


def validate_bounds(timeout_seconds: float, poll_seconds: float) -> None:
    if not 1.0 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise topology.TopologyError(
            f"readiness timeout must be between 1 and {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    if not 0.1 <= poll_seconds <= MAX_POLL_SECONDS:
        raise topology.TopologyError(
            f"readiness poll must be between 0.1 and {MAX_POLL_SECONDS:g} seconds"
        )
    if poll_seconds > timeout_seconds:
        raise topology.TopologyError(
            "readiness poll interval cannot exceed readiness timeout"
        )


def failure_report(error: Exception) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "captured_at": topology.utc_now(),
        "outcome": TERMINAL,
        "ready": False,
        "attempts": 0,
        "elapsed_seconds": 0,
        "diagnostics": [f"{type(error).__name__}: {error}"],
        "last_snapshot": {},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compose-file",
        action="append",
        type=pathlib.Path,
        required=True,
    )
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--project-name")
    parser.add_argument("--expected-replicas", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--poll-seconds", type=float, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.expected_replicas <= 9:
            raise topology.TopologyError("expected replicas must be between 1 and 9")
        validate_bounds(args.timeout_seconds, args.poll_seconds)
        compose = compose_prefix(
            args.compose_file,
            args.profile,
            args.project_name,
        )
        report = readiness_report(
            lambda deadline: capture_snapshot(compose, deadline),
            args.expected_replicas,
            args.timeout_seconds,
            args.poll_seconds,
        )
    except (
        topology.TopologyError,
        json.JSONDecodeError,
        OSError,
        ValueError,
    ) as error:
        report = failure_report(error)
    topology.write_json(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
