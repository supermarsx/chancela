#!/usr/bin/env python3
"""Capture and strictly validate the bounded Compose performance topology."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
from typing import Any


REQUIRED_SERVICES = (
    "chancela-cluster",
    "search-projector-postgres",
    "postgres",
    "redis",
    "perf-gateway",
)
FORBIDDEN_CLUSTER_SERVICES = (
    "server-postgres",
    "server-sqlite",
    "search-projector-sqlite",
)
CAPTURED_SERVICES = REQUIRED_SERVICES + FORBIDDEN_CLUSTER_SERVICES
SERVICE_REPLICA_COUNTS = {
    "search-projector-postgres": 1,
    "postgres": 1,
    "redis": 1,
    "perf-gateway": 1,
}


class TopologyError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def command(args: list[str], *, timeout: int = 60) -> str:
    completed = subprocess.run(
        args,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise TopologyError(
            f"{' '.join(args)} failed ({completed.returncode}): "
            f"{completed.stderr.strip()[:500]}"
        )
    return completed.stdout.strip()


def parse_memory_bytes(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return 0
    match = re.fullmatch(
        r"\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgt](?:i?b)?|b)?\s*",
        value,
        re.I,
    )
    if not match:
        return 0
    number = float(match.group(1))
    unit = (match.group(2) or "b").lower()
    factors = {
        "b": 1,
        "k": 1000,
        "kb": 1000,
        "m": 1000**2,
        "mb": 1000**2,
        "g": 1000**3,
        "gb": 1000**3,
        "t": 1000**4,
        "tb": 1000**4,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
    }
    return int(number * factors[unit])


def service_limits(config: dict[str, Any], service: str) -> dict[str, Any]:
    limits = (
        config.get("services", {})
        .get(service, {})
        .get("deploy", {})
        .get("resources", {})
        .get("limits", {})
    )
    cpus_raw = limits.get("cpus")
    try:
        cpus = float(cpus_raw)
    except (TypeError, ValueError):
        cpus = 0.0
    memory_bytes = parse_memory_bytes(limits.get("memory"))
    return {
        "cpus": cpus,
        "memory_bytes": memory_bytes,
        "raw": limits,
    }


def validate_rendered_config(config: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    failures: list[str] = []
    limits: dict[str, Any] = {}
    services = config.get("services")
    if not isinstance(services, dict):
        return ["rendered Compose config has no services object"], limits
    for service in REQUIRED_SERVICES:
        if service not in services:
            failures.append(f"rendered Compose config is missing service {service}")
            continue
        observed = service_limits(config, service)
        limits[service] = observed
        if observed["cpus"] <= 0:
            failures.append(f"{service} has no positive CPU limit")
        if observed["memory_bytes"] <= 0:
            failures.append(f"{service} has no positive memory limit")
    return failures, limits


def inspect_summary(raw: dict[str, Any]) -> dict[str, Any]:
    state = raw.get("State") if isinstance(raw.get("State"), dict) else {}
    health = state.get("Health") if isinstance(state.get("Health"), dict) else {}
    config = raw.get("Config") if isinstance(raw.get("Config"), dict) else {}
    return {
        "id": raw.get("Id"),
        "name": str(raw.get("Name", "")).lstrip("/"),
        "image_reference": config.get("Image"),
        "image_id": raw.get("Image"),
        "running": state.get("Running"),
        "status": state.get("Status"),
        "health": health.get("Status"),
        "restart_count": raw.get("RestartCount"),
        "oom_killed": state.get("OOMKilled"),
        "started_at": state.get("StartedAt"),
    }


def validate_containers(
    containers: dict[str, list[dict[str, Any]]], expected_replicas: int
) -> list[str]:
    failures: list[str] = []
    expected_counts = {
        "chancela-cluster": expected_replicas,
        "search-projector-postgres": 1,
        "postgres": 1,
        "redis": 1,
        "perf-gateway": 1,
    }
    for service, expected in expected_counts.items():
        observed = containers.get(service, [])
        if len(observed) != expected:
            failures.append(
                f"{service} expected {expected} containers, observed {len(observed)}"
            )
        for container in observed:
            label = container.get("name") or container.get("id")
            if container.get("running") is not True:
                failures.append(f"{service}/{label} is not running")
            if container.get("oom_killed") is True:
                failures.append(f"{service}/{label} was OOM-killed")
            if int(container.get("restart_count") or 0) != 0:
                failures.append(
                    f"{service}/{label} restarted {container.get('restart_count')} times"
                )
            if container.get("health") not in {None, "healthy"}:
                failures.append(
                    f"{service}/{label} health is {container.get('health')}"
                )
    for service in FORBIDDEN_CLUSTER_SERVICES:
        for container in containers.get(service, []):
            if container.get("running") is True:
                label = container.get("name") or container.get("id")
                failures.append(
                    f"forbidden standalone service {service}/{label} is running"
                )
    return failures


def validate_host_envelope(
    limits: dict[str, Any],
    expected_replicas: int,
    host: dict[str, Any],
) -> tuple[list[str], dict[str, Any]]:
    failures: list[str] = []
    docker_host = host.get("docker_host")
    if not isinstance(docker_host, dict):
        return (
            [
                "Docker host CPU/memory envelope is unavailable; "
                "syntactic Compose limits alone cannot bound this run"
            ],
            {
                "available": False,
                "requested_cpus": None,
                "requested_memory_bytes": None,
            },
        )
    host_cpus = docker_host.get("cpus")
    host_memory = docker_host.get("memory_bytes")
    if (
        not isinstance(host_cpus, (int, float))
        or isinstance(host_cpus, bool)
        or host_cpus <= 0
        or not isinstance(host_memory, int)
        or isinstance(host_memory, bool)
        or host_memory <= 0
    ):
        return (
            ["Docker host CPU/memory envelope is malformed or non-positive"],
            {
                "available": False,
                "requested_cpus": None,
                "requested_memory_bytes": None,
            },
        )

    replica_counts = {
        "chancela-cluster": expected_replicas,
        **SERVICE_REPLICA_COUNTS,
    }
    requested_cpus = sum(
        float(limits.get(service, {}).get("cpus") or 0) * replicas
        for service, replicas in replica_counts.items()
    )
    requested_memory = sum(
        int(limits.get(service, {}).get("memory_bytes") or 0) * replicas
        for service, replicas in replica_counts.items()
    )
    if requested_cpus > float(host_cpus):
        failures.append(
            f"aggregate requested CPU limit {requested_cpus:g} exceeds "
            f"Docker host envelope {float(host_cpus):g}"
        )
    if requested_memory > host_memory:
        failures.append(
            f"aggregate requested memory limit {requested_memory} exceeds "
            f"Docker host envelope {host_memory}"
        )
    return (
        failures,
        {
            "available": True,
            "within_envelope": not failures,
            "requested_cpus": requested_cpus,
            "requested_memory_bytes": requested_memory,
            "host_cpus": float(host_cpus),
            "host_memory_bytes": host_memory,
            "replica_counts": replica_counts,
        },
    )


def safe_host_evidence() -> dict[str, Any]:
    disk = shutil.disk_usage(pathlib.Path.cwd().anchor or "/")
    evidence: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version,
        "logical_cpus": os.cpu_count(),
        "disk_total_bytes": disk.total,
        "disk_free_bytes": disk.free,
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
        "git_sha": os.environ.get("GITHUB_SHA"),
    }
    if not evidence["git_sha"]:
        try:
            evidence["git_sha"] = command(["git", "rev-parse", "HEAD"])
        except TopologyError as error:
            evidence["git_sha_error"] = str(error)
    try:
        evidence["docker_server_version"] = command(
            ["docker", "version", "--format", "{{.Server.Version}}"]
        )
        raw_info = command(
            [
                "docker",
                "info",
                "--format",
                "{{.NCPU}}|{{.MemTotal}}|{{.OperatingSystem}}|{{.KernelVersion}}|{{.Driver}}",
            ]
        )
        cpus, memory, operating_system, kernel, driver = raw_info.split("|", 4)
        evidence["docker_host"] = {
            "cpus": int(cpus),
            "memory_bytes": int(memory),
            "operating_system": operating_system,
            "kernel": kernel,
            "storage_driver": driver,
        }
    except (TopologyError, ValueError) as error:
        evidence["docker_host_error"] = str(error)
    return evidence


def capture(
    compose_files: list[pathlib.Path],
    profiles: list[str],
    expected_replicas: int,
    project_name: str | None = None,
) -> dict[str, Any]:
    compose = ["docker", "compose"]
    if project_name:
        compose.extend(["--project-name", project_name])
    for compose_file in compose_files:
        compose.extend(["-f", str(compose_file)])
    for profile in profiles:
        compose.extend(["--profile", profile])
    rendered_text = command([*compose, "config", "--format", "json"])
    rendered = json.loads(rendered_text)
    failures, limits = validate_rendered_config(rendered)
    host = safe_host_evidence()
    envelope_failures, aggregate_envelope = validate_host_envelope(
        limits,
        expected_replicas,
        host,
    )
    failures.extend(envelope_failures)
    containers: dict[str, list[dict[str, Any]]] = {
        service: [] for service in CAPTURED_SERVICES
    }
    rendered_services = rendered.get("services", {})
    for service in CAPTURED_SERVICES:
        if service not in rendered_services:
            continue
        identifiers = [
            item
            for item in command(
                [*compose, "ps", "--all", "-q", service]
            ).splitlines()
            if item
        ]
        if identifiers:
            inspected = json.loads(command(["docker", "inspect", *identifiers]))
            containers[service] = [inspect_summary(item) for item in inspected]
    failures.extend(validate_containers(containers, expected_replicas))
    rendered_canonical = json.dumps(
        rendered, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "schema_version": 1,
        "captured_at": utc_now(),
        "preflight_passed": not failures,
        "failures": failures,
        "summary": {
            "project_name": project_name,
            "app_replicas": len(containers["chancela-cluster"]),
            "expected_app_replicas": expected_replicas,
            "service_limits": limits,
            "aggregate_resource_envelope": aggregate_envelope,
            "compose_files": [str(path) for path in compose_files],
            "profiles": list(profiles),
        },
        "host": host,
        "containers": containers,
        "rendered_config_sha256": hashlib.sha256(rendered_canonical).hexdigest(),
        "rendered_config": rendered,
    }


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


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
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help="capture failure evidence without making the command fail",
    )
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.expected_replicas <= 9:
            raise TopologyError("expected replicas must be between 1 and 9")
        report = capture(
            args.compose_file,
            args.profile,
            args.expected_replicas,
            args.project_name,
        )
        write_json(args.output, report)
        if not report["preflight_passed"] and not args.allow_degraded:
            print(
                "topology preflight failed: " + "; ".join(report["failures"]),
                file=sys.stderr,
            )
            return 1
        print(json.dumps({"output": str(args.output), "preflight": report["preflight_passed"]}))
        return 0
    except (TopologyError, json.JSONDecodeError, OSError) as error:
        failure = {
            "schema_version": 1,
            "captured_at": utc_now(),
            "preflight_passed": False,
            "failures": [f"{type(error).__name__}: {error}"],
        }
        write_json(args.output, failure)
        print(f"topology capture failed: {error}", file=sys.stderr)
        return 0 if args.allow_degraded else 1


if __name__ == "__main__":
    raise SystemExit(main())
