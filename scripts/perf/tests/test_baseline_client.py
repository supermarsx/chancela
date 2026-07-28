from __future__ import annotations

import json
import pathlib
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PERF_ROOT))

import baseline_client  # noqa: E402


NETSTAT_WINDOWS_SAMPLE = """
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    127.0.0.1:18081        127.0.0.1:52344        ESTABLISHED
  TCP    127.0.0.1:18081        127.0.0.1:52345        ESTABLISHED
  TCP    127.0.0.1:52346        127.0.0.1:18081        TIME_WAIT
  TCP    127.0.0.1:52347        127.0.0.1:18081        TIME_WAIT
  TCP    127.0.0.1:52348        127.0.0.1:18081        TIME_WAIT
"""

NETSH_DYNAMICPORT_SAMPLE = """
Protocol tcp Dynamic Port Range
---------------------------------
Start Port      : 49152
Number of Ports : 16384
"""


class FakeHealthHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # silence test output
        pass

    def do_GET(self):
        body = json.dumps({"status": "ok"}).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LocalHealthServer:
    """A tiny local fixture, matching the ThreadingHTTPServer pattern already
    used throughout test_harness.py for correctness checks (not benchmarks)."""

    def __enter__(self):
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), FakeHealthHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._server

    def __exit__(self, *_exc):
        self._server.shutdown()
        self._server.server_close()


class TcpStateSamplingTests(unittest.TestCase):
    def test_counts_each_state_from_captured_windows_netstat_text(self):
        counts = baseline_client.sample_tcp_states(NETSTAT_WINDOWS_SAMPLE)
        self.assertEqual(counts["ESTABLISHED"], 2)
        self.assertEqual(counts["TIME_WAIT"], 3)
        self.assertEqual(counts["LISTENING"], 1)

    def test_empty_text_yields_empty_counts(self):
        self.assertEqual(baseline_client.sample_tcp_states(""), {})

    def test_live_sample_is_read_only_and_returns_a_dict(self):
        # Exercises the real `netstat -an` invocation path. This inspects the
        # existing OS connection table; it opens no socket and sends no packet,
        # so it is not load generation.
        counts = baseline_client.sample_tcp_states()
        self.assertIsInstance(counts, dict)


class EphemeralPortRangeTests(unittest.TestCase):
    def test_parses_start_port_and_count(self):
        parsed = baseline_client.read_windows_ephemeral_port_range(NETSH_DYNAMICPORT_SAMPLE)
        self.assertEqual(parsed, (49152, 16384))

    def test_unparseable_text_returns_none(self):
        self.assertIsNone(baseline_client.read_windows_ephemeral_port_range("not netsh output"))


class ClientCeilingResultTests(unittest.TestCase):
    def test_to_dict_serializes_port_range_tuple_as_list(self):
        result = baseline_client.ClientCeilingResult(
            shape="pooled",
            workers=4,
            requests=40,
            errors=0,
            duration_seconds=1.0,
            achieved_per_second=40.0,
            p50_ms=1.0,
            p95_ms=2.0,
            p99_ms=3.0,
            tcp_state_before={},
            tcp_state_after={},
            ephemeral_port_range=(49152, 16384),
        )
        payload = result.to_dict()
        self.assertEqual(payload["ephemeral_port_range"], [49152, 16384])
        # Round-trips through JSON cleanly (evidence must be serializable).
        json.dumps(payload)

    def test_to_dict_handles_missing_port_range(self):
        result = baseline_client.ClientCeilingResult(
            shape="multiprocess",
            workers=1,
            requests=1,
            errors=0,
            duration_seconds=1.0,
            achieved_per_second=1.0,
            p50_ms=None,
            p95_ms=None,
            p99_ms=None,
            tcp_state_before={},
            tcp_state_after={},
            ephemeral_port_range=None,
        )
        self.assertIsNone(result.to_dict()["ephemeral_port_range"])


class PooledConnectionTests(unittest.TestCase):
    def test_reuses_the_same_underlying_connection_across_requests(self):
        # Fixed, tiny request count against a local loopback fixture — a
        # correctness check of connection reuse, not a throughput measurement.
        with LocalHealthServer() as server:
            connection = baseline_client.PooledConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                first = connection.request("GET", "/health")
                underlying_after_first = connection._connection
                second = connection.request("GET", "/health")
                self.assertEqual(first.status, 200)
                self.assertEqual(second.status, 200)
                # Same HTTPConnection object instance reused, not reopened.
                self.assertIs(connection._connection, underlying_after_first)
            finally:
                connection.close()
            self.assertIsNone(connection._connection)

    def test_reconnects_after_a_broken_connection(self):
        connection = baseline_client.PooledConnection("127.0.0.1", 1, timeout=0.2)
        result = connection.request("GET", "/health")
        self.assertIsNone(result.status)
        self.assertIsNotNone(result.error)
        self.assertIsNone(connection._connection)


class ShapeWiringTests(unittest.TestCase):
    """Bounded correctness checks that the shape functions wire together end to
    end. Duration is held to a fraction of a second with 1-2 workers, so total
    request volume is a handful — proving the plumbing, not measuring a
    ceiling. Ceiling measurement is t57-e1b's job, run against the real stack.
    """

    def test_run_shape_urllib_completes_and_reports_a_rate(self):
        with LocalHealthServer() as server:
            result = baseline_client.run_shape_urllib(
                f"http://127.0.0.1:{server.server_port}", "/health", client_count=1, duration_seconds=0.05
            )
        self.assertEqual(result.shape, "urllib")
        self.assertGreaterEqual(result.requests, 1)
        self.assertEqual(result.errors, 0)
        self.assertGreater(result.achieved_per_second, 0.0)

    def test_run_shape_pooled_completes_and_reports_a_rate(self):
        with LocalHealthServer() as server:
            result = baseline_client.run_shape_pooled(
                f"http://127.0.0.1:{server.server_port}", "/health", connection_count=1, duration_seconds=0.05
            )
        self.assertEqual(result.shape, "pooled")
        self.assertGreaterEqual(result.requests, 1)
        self.assertEqual(result.errors, 0)

    def test_run_shape_multiprocess_completes_and_aggregates_workers(self):
        with LocalHealthServer() as server:
            result = baseline_client.run_shape_multiprocess(
                f"http://127.0.0.1:{server.server_port}",
                "/health",
                process_count=1,
                threads_per_process=1,
                duration_seconds=0.05,
            )
        self.assertEqual(result.shape, "multiprocess")
        self.assertEqual(result.workers, 1)
        self.assertGreaterEqual(result.requests, 1)
        # Percentiles are not shipped across the process boundary by design.
        self.assertIsNone(result.p50_ms)


if __name__ == "__main__":
    unittest.main()
