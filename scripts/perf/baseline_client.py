#!/usr/bin/env python3
"""Load-generator ceiling scaffolding for t57 B3 (10 000 req/s attempt).

Context (t57 plan §0.4, §2 Batch A): the existing harness's ``ApiClient``
(``harness.py``) opens a fresh TCP connection per request via
``urllib.request.urlopen()``. On this box that structurally caps new
connections at roughly ``ephemeral_port_range / TIME_WAIT_seconds`` — about
136/s on Windows defaults (16 384 ports, ~120 s TIME_WAIT) — long before the
server is ever a factor. Before any "10 000 req/s" attempt against the real
API is meaningful, the load generator's *own* ceiling must be measured in
isolation against a trivial endpoint, across three client shapes:

  (a) ``urllib``       — one TCP connection per request (today's shape;
                          reuses ``harness.ApiClient`` unmodified).
  (b) ``pooled``        — persistent HTTP/1.1 keep-alive connections, reused
                          across many requests, run by a thread pool.
  (c) ``multiprocess``  — the pooled shape replicated across worker
                          processes, to escape the single-process GIL.

This module is **scaffolding only**. It was built by t57-e1a, which is under
an explicit no-load, no-benchmark constraint: nothing in this file is
executed against a live duration-based load by that work. t57-e1b is the
executor that actually runs the three-way comparison (``main`` below) and
records the result alongside TCP state, per the t57 plan.

Metrics reuse ``harness.py``'s existing ``HttpResult``/``Reservoir``/
``percentile`` plumbing rather than duplicating it — same methodology as
every other measurement this harness produces.
"""

from __future__ import annotations

import argparse
import dataclasses
import http.client
import json
import multiprocessing
import pathlib
import random
import re
import subprocess
import sys
import threading
import time
import urllib.parse
from typing import Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from harness import ApiClient, HttpResult, Reservoir, percentile  # noqa: E402  (see sys.path.insert above)

DEFAULT_ENDPOINT = "/health"
DEFAULT_TIMEOUT_SECONDS = 5.0
SHAPES = ("urllib", "pooled", "multiprocess")

# Matches the TCP state column in `netstat -an` output on both Windows and
# POSIX (`Proto Local Foreign State` layout). Read-only text parsing; the
# caller decides where the text came from.
_NETSTAT_STATE_RE = re.compile(
    r"\b(ESTABLISHED|TIME_WAIT|CLOSE_WAIT|FIN_WAIT_1|FIN_WAIT_2|"
    r"SYN_SENT|SYN_RECEIVED|LISTENING|LAST_ACK|CLOSING|CLOSED)\b"
)


def sample_tcp_states(netstat_output: Optional[str] = None) -> dict:
    """Count TCP connections by state.

    Read-only: inspects the OS connection table, opens no sockets, sends no
    packets, and is safe to call at any time, including while idle. Pass
    ``netstat_output`` to test the parser against captured text without
    invoking the OS tool (used by this module's own tests).
    """
    if netstat_output is None:
        completed = subprocess.run(
            ["netstat", "-an"], capture_output=True, text=True, timeout=10, check=False
        )
        netstat_output = completed.stdout
    counts: dict = {}
    for line in netstat_output.splitlines():
        match = _NETSTAT_STATE_RE.search(line)
        if match:
            state = match.group(1)
            counts[state] = counts.get(state, 0) + 1
    return counts


def read_windows_ephemeral_port_range(netsh_output: Optional[str] = None):
    """Parse ``netsh int ipv4 show dynamicport tcp`` -> ``(start_port, num_ports)``.

    Read-only OS query (the §0.4(1) figure this module exists to confirm
    empirically). Returns ``None`` off Windows, or if the tool/output is
    unavailable, rather than raising — a missing figure is evidence too.
    """
    if netsh_output is None:
        try:
            completed = subprocess.run(
                ["netsh", "int", "ipv4", "show", "dynamicport", "tcp"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, FileNotFoundError):
            return None
        netsh_output = completed.stdout
    start_match = re.search(r"Start Port\s*:\s*(\d+)", netsh_output)
    count_match = re.search(r"Number of Ports\s*:\s*(\d+)", netsh_output)
    if not start_match or not count_match:
        return None
    return int(start_match.group(1)), int(count_match.group(1))


@dataclasses.dataclass
class ClientCeilingResult:
    """One shape's measured ceiling, always paired with TCP state at the same instant.

    Every field the t57 D2 decision requires as a "required field, not a
    footnote" is present directly on the result, not left to be reconstructed
    later from a log.
    """

    shape: str
    workers: int
    requests: int
    errors: int
    duration_seconds: float
    achieved_per_second: float
    p50_ms: Optional[float]
    p95_ms: Optional[float]
    p99_ms: Optional[float]
    tcp_state_before: dict
    tcp_state_after: dict
    ephemeral_port_range: Optional[tuple]

    def to_dict(self) -> dict:
        return {
            "shape": self.shape,
            "workers": self.workers,
            "requests": self.requests,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
            "achieved_per_second": self.achieved_per_second,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "tcp_state_before": self.tcp_state_before,
            "tcp_state_after": self.tcp_state_after,
            "ephemeral_port_range": (
                list(self.ephemeral_port_range) if self.ephemeral_port_range else None
            ),
        }


class PooledConnection:
    """A single persistent HTTP/1.1 keep-alive connection, reused across many requests.

    Isolates whether TCP handshake / TIME_WAIT overhead — not the app — is
    the request-rate ceiling (t57 plan §0.4(1)). Contrast with
    ``harness.ApiClient``, which opens a fresh connection every call.
    """

    def __init__(self, host: str, port: int, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._connection: Optional[http.client.HTTPConnection] = None

    def _connect(self) -> http.client.HTTPConnection:
        if self._connection is None:
            self._connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        return self._connection

    def request(self, method: str, path: str) -> HttpResult:
        connection = self._connect()
        started = time.perf_counter()
        try:
            connection.request(method, path, headers={"connection": "keep-alive"})
            response = connection.getresponse()
            body = response.read()
            return HttpResult(response.status, (time.perf_counter() - started) * 1000.0, body)
        except Exception as error:  # a broken keep-alive connection must not wedge the caller
            self._connection = None
            return HttpResult(
                None,
                (time.perf_counter() - started) * 1000.0,
                b"",
                f"{type(error).__name__}: {error}",
            )

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None


def _split_base_url(base_url: str) -> tuple:
    parsed = urllib.parse.urlsplit(base_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname, port


def _worker_loop(
    make_request,
    stop_at: float,
    reservoir: Reservoir,
    lock: threading.Lock,
    counters: dict,
) -> None:
    """Shared closed-loop worker body: request-as-fast-as-possible until ``stop_at``.

    Matches the closed-loop shape ``harness.py`` already uses for its mixed
    workload (see its own documented open-loop caveat, t57 plan §0.4(2)) —
    this module measures generator *capability*, not an arrival-rate SLO, so
    closed-loop is the right shape here even though it would not be for B3
    itself.
    """
    while time.perf_counter() < stop_at:
        result = make_request()
        with lock:
            counters["requests"] += 1
            if result.status is None or result.status >= 400:
                counters["errors"] += 1
            reservoir.add(result.latency_ms)


def run_shape_urllib(
    base_url: str,
    endpoint: str,
    client_count: int,
    duration_seconds: float,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ClientCeilingResult:
    """Shape (a): today's per-request-connection client, via `harness.ApiClient`."""
    tcp_before = sample_tcp_states()
    reservoir = Reservoir(limit=100_000, rng=random.Random(0))
    lock = threading.Lock()
    counters = {"requests": 0, "errors": 0}
    clients = [ApiClient(base_url, timeout=timeout) for _ in range(client_count)]
    stop_at = time.perf_counter() + duration_seconds
    threads = [
        threading.Thread(
            target=_worker_loop,
            args=(lambda c=client: c.request("GET", endpoint, authenticated=False), stop_at, reservoir, lock, counters),
        )
        for client in clients
    ]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started
    tcp_after = sample_tcp_states()
    return ClientCeilingResult(
        shape="urllib",
        workers=client_count,
        requests=counters["requests"],
        errors=counters["errors"],
        duration_seconds=elapsed,
        achieved_per_second=counters["requests"] / elapsed if elapsed else 0.0,
        p50_ms=percentile(reservoir.values, 0.50),
        p95_ms=percentile(reservoir.values, 0.95),
        p99_ms=percentile(reservoir.values, 0.99),
        tcp_state_before=tcp_before,
        tcp_state_after=tcp_after,
        ephemeral_port_range=read_windows_ephemeral_port_range(),
    )


def run_shape_pooled(
    base_url: str,
    endpoint: str,
    connection_count: int,
    duration_seconds: float,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ClientCeilingResult:
    """Shape (b): N persistent keep-alive connections, each driven by its own thread."""
    tcp_before = sample_tcp_states()
    host, port = _split_base_url(base_url)
    reservoir = Reservoir(limit=100_000, rng=random.Random(0))
    lock = threading.Lock()
    counters = {"requests": 0, "errors": 0}
    connections = [PooledConnection(host, port, timeout=timeout) for _ in range(connection_count)]
    stop_at = time.perf_counter() + duration_seconds
    threads = [
        threading.Thread(
            target=_worker_loop,
            args=(lambda c=connection: c.request("GET", endpoint), stop_at, reservoir, lock, counters),
        )
        for connection in connections
    ]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started
    for connection in connections:
        connection.close()
    tcp_after = sample_tcp_states()
    return ClientCeilingResult(
        shape="pooled",
        workers=connection_count,
        requests=counters["requests"],
        errors=counters["errors"],
        duration_seconds=elapsed,
        achieved_per_second=counters["requests"] / elapsed if elapsed else 0.0,
        p50_ms=percentile(reservoir.values, 0.50),
        p95_ms=percentile(reservoir.values, 0.95),
        p99_ms=percentile(reservoir.values, 0.99),
        tcp_state_before=tcp_before,
        tcp_state_after=tcp_after,
        ephemeral_port_range=read_windows_ephemeral_port_range(),
    )


def _multiprocess_worker(base_url: str, endpoint: str, threads_per_process: int, duration_seconds: float, timeout: float, out_queue) -> None:
    """Runs the pooled shape inside one worker process; posts its raw samples back.

    Kept process-local and dependency-light (no shared harness state across
    the process boundary) so this is genuinely CPU-parallel, escaping the
    parent's GIL — the point of shape (c) per t57 plan §0.4(3).
    """
    result = run_shape_pooled(base_url, endpoint, threads_per_process, duration_seconds, timeout)
    # Only aggregate counts cross the process boundary — shipping every raw
    # latency sample back over IPC would itself distort the throughput being
    # measured.
    out_queue.put((result.requests, result.errors))


def run_shape_multiprocess(
    base_url: str,
    endpoint: str,
    process_count: int,
    threads_per_process: int,
    duration_seconds: float,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ClientCeilingResult:
    """Shape (c): the pooled shape replicated across worker processes.

    Latency percentiles are not meaningful across the multiprocess boundary
    without shipping every sample back (which would itself distort the
    measurement), so this shape reports throughput/error aggregates with
    percentiles left ``None`` — callers needing per-request latency should
    use the pooled shape's own p50/p95/p99 as the same-tooling comparator.
    """
    tcp_before = sample_tcp_states()
    out_queue: multiprocessing.Queue = multiprocessing.Queue()
    processes = [
        multiprocessing.Process(
            target=_multiprocess_worker,
            args=(base_url, endpoint, threads_per_process, duration_seconds, timeout, out_queue),
        )
        for _ in range(process_count)
    ]
    started = time.perf_counter()
    for process in processes:
        process.start()
    total_requests = 0
    total_errors = 0
    for _ in processes:
        requests, errors = out_queue.get()
        total_requests += requests
        total_errors += errors
    for process in processes:
        process.join()
    elapsed = time.perf_counter() - started
    tcp_after = sample_tcp_states()
    return ClientCeilingResult(
        shape="multiprocess",
        workers=process_count * threads_per_process,
        requests=total_requests,
        errors=total_errors,
        duration_seconds=elapsed,
        achieved_per_second=total_requests / elapsed if elapsed else 0.0,
        p50_ms=None,
        p95_ms=None,
        p99_ms=None,
        tcp_state_before=tcp_before,
        tcp_state_after=tcp_after,
        ephemeral_port_range=read_windows_ephemeral_port_range(),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:18081")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--shape", choices=SHAPES, required=True)
    parser.add_argument("--duration-seconds", type=float, default=10.0)
    parser.add_argument("--workers", type=int, default=64, help="clients/connections for urllib/pooled")
    parser.add_argument("--processes", type=int, default=4, help="worker processes for multiprocess")
    parser.add_argument("--threads-per-process", type=int, default=16, help="connections per process for multiprocess")
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", type=pathlib.Path, default=None)
    return parser


def main(argv=None) -> int:
    """CLI entry point. Not invoked by t57-e1a: this is scaffolding for t57-e1b to run."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.shape == "urllib":
        result = run_shape_urllib(args.base_url, args.endpoint, args.workers, args.duration_seconds, args.timeout_seconds)
    elif args.shape == "pooled":
        result = run_shape_pooled(args.base_url, args.endpoint, args.workers, args.duration_seconds, args.timeout_seconds)
    else:
        result = run_shape_multiprocess(
            args.base_url,
            args.endpoint,
            args.processes,
            args.threads_per_process,
            args.duration_seconds,
            args.timeout_seconds,
        )
    payload = json.dumps(result.to_dict(), sort_keys=True)
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
