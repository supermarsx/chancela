import json
import pathlib
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock


PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PERF_ROOT))

import harness  # noqa: E402


class DatasetTests(unittest.TestCase):
    def profile(self, root: pathlib.Path) -> pathlib.Path:
        path = root / "profile.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "name": "test",
                    "seed": 7,
                    "dataset": {
                        "users": 3,
                        "entities": 4,
                        "books": 6,
                        "signatures": 5,
                    },
                    "seed_concurrency": 2,
                    "workload": {
                        "mode": "steady",
                        "duration_seconds": 1,
                        "clients": 1,
                        "request_timeout_seconds": 1,
                        "weights": {"health": 1},
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_exact_counts_digests_and_determinism(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            profile = self.profile(root)
            first = harness.generate_dataset(profile, root / "first")
            second = harness.generate_dataset(profile, root / "second")
            self.assertEqual(
                {kind: first["files"][kind]["sha256"] for kind in harness.DATASET_FILES},
                {kind: second["files"][kind]["sha256"] for kind in harness.DATASET_FILES},
            )
            self.assertEqual(
                first["counts"],
                {"users": 3, "entities": 4, "books": 6, "signatures": 5},
            )
            self.assertTrue(harness.validate_dataset(root / "first")["valid"])

    def test_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            output = root / "dataset"
            harness.generate_dataset(self.profile(root), output)
            with (output / "users.jsonl").open("a", encoding="utf-8") as handle:
                handle.write("{}\n")
            with self.assertRaises(harness.HarnessError):
                harness.validate_dataset(output)

    def test_invalid_signature_ratio_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            profile_path = self.profile(root)
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            profile["dataset"]["signatures"] = 7
            with self.assertRaises(harness.HarnessError):
                harness.validate_profile(profile)


class MetricsTests(unittest.TestCase):
    def test_percentiles_interpolate(self):
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        self.assertEqual(harness.percentile(values, 0.5), 3.0)
        self.assertAlmostEqual(harness.percentile(values, 0.95), 4.8)
        self.assertAlmostEqual(harness.percentile(values, 0.99), 4.96)

    def test_modes_are_explicit(self):
        self.assertEqual(harness.active_clients("steady", 5, 10, 8), 8)
        self.assertEqual(harness.active_clients("soak", 5, 10, 8), 8)
        self.assertLess(harness.active_clients("ramp", 1, 10, 8), 8)
        self.assertEqual(harness.active_clients("spike", 5, 10, 8), 8)
        self.assertEqual(harness.active_clients("spike", 1, 10, 8), 2)

    def test_resource_size_parser(self):
        self.assertEqual(harness.parse_size_bytes("1KiB"), 1024)
        self.assertEqual(harness.parse_size_bytes("1.5 MiB"), 1.5 * 1024 * 1024)
        self.assertEqual(harness.parse_size_bytes("2GB"), 2_000_000_000)

    def test_null_slo_is_not_a_pass(self):
        result = harness.evaluate_slo(
            {"error_rate": 0.0, "throughput_per_second": 100, "operations": {}},
            {"containers": {}},
            {"global": {"max_error_rate": None}},
        )
        self.assertEqual(result["assessment"], "not_configured")
        self.assertEqual(result["configured_thresholds"], 0)

    def test_configured_slo_passes_and_fails_from_measurements(self):
        workload = {
            "error_rate": 0.01,
            "throughput_per_second": 50,
            "operations": {"entity_list": {"p95_ms": 20, "p99_ms": 30, "error_rate": 0}},
        }
        resources = {
            "containers": {
                "chancela": {"max_memory_bytes": 1000, "max_cpu_percent": 25}
            }
        }
        passing = {
            "global": {"max_error_rate": 0.02, "min_throughput_per_second": 40},
            "operations": {"entity_list": {"p95_ms": 25}},
            "resources": {"max_container_memory_bytes": 2000},
        }
        self.assertEqual(
            harness.evaluate_slo(workload, resources, passing)["assessment"], "passed"
        )
        failing = {"global": {"max_error_rate": 0.001}}
        self.assertEqual(
            harness.evaluate_slo(workload, resources, failing)["assessment"], "failed"
        )


class ParallelSeedTests(unittest.TestCase):
    def test_non_zero_ordinals_keep_every_identifier(self):
        records = [{"ordinal": 1}, {"ordinal": 2}]

        def create(record):
            return (
                record["ordinal"],
                harness.HttpResult(201, 1.0, b"{}"),
                f"id-{record['ordinal']}",
            )

        stage, identifiers = harness.parallel_seed(records, 2, 2, create, {201})
        self.assertEqual(stage.created, 2)
        self.assertEqual(identifiers, ["id-1", "id-2"])


class FakeApiHandler(BaseHTTPRequestHandler):
    counters = {"users": 0, "entities": 0, "books": 0, "acts": 0}

    def reply(self, status, value):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"status": "ok"})
        elif self.path in {"/v1/entities", "/v1/books", "/v1/users"}:
            self.reply(200, [])
        else:
            self.reply(200, {"id": self.path.rsplit("/", 1)[-1]})

    def do_PATCH(self):
        length = int(self.headers.get("content-length", "0"))
        if length:
            self.rfile.read(length)
        self.reply(200, {"ok": True})

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/v1/session":
            self.reply(201, {"token": "test-token"})
            return
        if self.path == "/v1/users":
            kind = "users"
        elif self.path == "/v1/entities":
            kind = "entities"
        elif self.path == "/v1/books":
            kind = "books"
        elif self.path == "/v1/acts":
            kind = "acts"
        elif self.path.endswith("/advance"):
            self.reply(200, {"ok": True})
            return
        elif "/signature/local/pkcs12/sign" in self.path:
            self.reply(200, {"family": "LocalPkcs12SoftwareCertificate"})
            return
        else:
            self.reply(404, {"error": self.path, "payload": payload})
            return
        type(self).counters[kind] += 1
        self.reply(201, {"id": f"{kind}-{type(self).counters[kind]}"})

    def log_message(self, _format, *_args):
        pass


class ApiIntegrationTests(unittest.TestCase):
    def test_small_exact_seed_and_mixed_workload(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            profile_path = DatasetTests().profile(root)
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            profile["workload"]["duration_seconds"] = 0.25
            profile["workload"]["clients"] = 2
            profile["workload"]["weights"] = {
                "health": 1,
                "entity_list": 1,
                "entity_get": 1,
                "book_list": 1,
                "book_get": 1,
                "user_list": 1,
                "auth_login": 1,
                "entity_write": 1,
                "signature_status": 1,
            }
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            dataset = root / "dataset"
            harness.generate_dataset(profile_path, dataset)
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApiHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = harness.ApiClient(
                    f"http://127.0.0.1:{server.server_port}", timeout=2
                )
                seed, index = harness.seed_dataset(
                    dataset, client, profile, harness.DEFAULT_PASSWORD
                )
                self.assertTrue(seed["exact"])
                self.assertEqual(len(index["users"]), 3)
                self.assertEqual(len(index["entities"]), 4)
                self.assertEqual(len(index["books"]), 6)
                self.assertEqual(len(index["signatures"]), 5)
                with mock.patch.object(harness, "docker_snapshot", return_value=[]):
                    workload, resources = harness.run_workload(
                        client, profile, index, harness.DEFAULT_PASSWORD
                    )
                self.assertGreater(workload["requests"], 0)
                self.assertEqual(workload["errors"], 0)
                self.assertEqual(workload["mode"], "steady")
                self.assertFalse(resources["available"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
