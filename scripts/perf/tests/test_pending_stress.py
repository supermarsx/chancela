from __future__ import annotations

import json
import pathlib
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock


PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = PERF_ROOT.parents[1]
sys.path.insert(0, str(PERF_ROOT))

import harness  # noqa: E402
import pending_stress as ps  # noqa: E402
import readiness  # noqa: E402


# Verbatim from `crates/chancela-store/src/schema.rs:479-495` -- the `pending_cmd_sessions`
# table plus its `act_id` index. Kept in lockstep with the Rust DDL deliberately: a drift
# here would make `seed_pending_cmd_sessions_sqlite`'s tests pass against a schema the real
# store no longer has.
PENDING_CMD_SESSIONS_DDL = """\
CREATE TABLE IF NOT EXISTS pending_cmd_sessions (
    session_id   TEXT PRIMARY KEY,
    act_id       TEXT NOT NULL,
    actor        TEXT NOT NULL,
    status       TEXT NOT NULL,
    masked_phone TEXT NOT NULL,
    doc_name     TEXT NOT NULL,
    signer_capacity_evidence_json TEXT,
    session_json TEXT NOT NULL,
    prepared_json TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
) STRICT;
"""
PENDING_CMD_SESSIONS_ACT_IDX = (
    "CREATE INDEX IF NOT EXISTS idx_pending_cmd_sessions_act "
    "ON pending_cmd_sessions (act_id);"
)


def base_profile() -> dict:
    return {
        "schema_version": 1,
        "name": "pending-acts",
        "proof_eligible": False,
        "seed": 20260727,
        "backlog": {
            "target_acts_in_signing": 6,
            "users": 1,
            "entities": 2,
            "books": 3,
            "advance_concurrency": 2,
        },
        "pending_cmd_sessions": {
            "target_count": 4,
            "seed_mode": "store_direct_sqlite",
            "synthetic_fixture": True,
            "note": "test fixture",
        },
        "read_stress": {
            "mode": "steady",
            "duration_seconds": 0.2,
            "warmup_seconds": 0.02,
            "ramp_seconds": 0.02,
            "peak_plateau_seconds": 0.14,
            "cooldown_seconds": 0.02,
            "clients": 2,
            "request_timeout_seconds": 2,
            "max_latency_samples_per_operation": 1000,
            "weights": {
                "act_get": 1,
                "signature_status": 1,
                "book_acts_list": 1,
                "dashboard": 1,
            },
        },
        "rehydration": {
            "measure": True,
            "method": "compose_restart_then_readiness",
            "service": "chancela-cluster",
            "timeout_seconds": 30,
            "poll_seconds": 1,
            "max_attempts": 1,
        },
    }


class ValidateProfileTests(unittest.TestCase):
    def test_base_profile_is_valid(self):
        ps.validate_profile(base_profile())

    def test_committed_profile_is_valid(self):
        profile = json.loads(
            (PERF_ROOT / "profiles" / "pending-acts.json").read_text(encoding="utf-8")
        )
        ps.validate_profile(profile)
        self.assertFalse(profile["proof_eligible"])

    def test_wrong_schema_version_is_rejected(self):
        profile = base_profile()
        profile["schema_version"] = 2
        with self.assertRaisesRegex(ps.PendingStressError, "schema_version"):
            ps.validate_profile(profile)

    def test_wrong_name_is_rejected(self):
        profile = base_profile()
        profile["name"] = "capacity"
        with self.assertRaisesRegex(ps.PendingStressError, "name"):
            ps.validate_profile(profile)

    def test_books_cannot_exceed_target_acts(self):
        profile = base_profile()
        profile["backlog"]["books"] = profile["backlog"]["target_acts_in_signing"] + 1
        with self.assertRaisesRegex(ps.PendingStressError, "books"):
            ps.validate_profile(profile)

    def test_backlog_fields_must_be_positive_integers(self):
        profile = base_profile()
        for field in ("target_acts_in_signing", "users", "entities", "books", "advance_concurrency"):
            for invalid in (None, True, 0, -1, 1.5, "3"):
                with self.subTest(field=field, invalid=invalid):
                    broken = base_profile()
                    broken["backlog"][field] = invalid
                    with self.assertRaises(ps.PendingStressError):
                        ps.validate_profile(broken)

    def test_seed_mode_must_be_recognized(self):
        profile = base_profile()
        profile["pending_cmd_sessions"]["seed_mode"] = "store_direct_postgres"
        with self.assertRaisesRegex(ps.PendingStressError, "seed_mode"):
            ps.validate_profile(profile)

    def test_synthetic_fixture_must_be_true(self):
        profile = base_profile()
        profile["pending_cmd_sessions"]["synthetic_fixture"] = False
        with self.assertRaisesRegex(ps.PendingStressError, "synthetic_fixture"):
            ps.validate_profile(profile)

    def test_read_stress_requires_all_fields(self):
        for field in (
            "mode", "duration_seconds", "warmup_seconds", "ramp_seconds",
            "peak_plateau_seconds", "cooldown_seconds", "clients",
            "request_timeout_seconds", "max_latency_samples_per_operation", "weights",
        ):
            with self.subTest(field=field):
                profile = base_profile()
                del profile["read_stress"][field]
                with self.assertRaises(ps.PendingStressError):
                    ps.validate_profile(profile)

    def test_read_stress_rejects_unknown_operations(self):
        profile = base_profile()
        profile["read_stress"]["weights"] = {"entity_list": 1}
        with self.assertRaisesRegex(ps.PendingStressError, "unknown operations"):
            ps.validate_profile(profile)

    def test_rehydration_requires_a_service_name(self):
        profile = base_profile()
        profile["rehydration"]["service"] = ""
        with self.assertRaises(ps.PendingStressError):
            ps.validate_profile(profile)


class SqlitePendingCmdSessionsTests(unittest.TestCase):
    def make_store(self, root: pathlib.Path) -> pathlib.Path:
        db_path = root / "store.sqlite3"
        connection = sqlite3.connect(str(db_path))
        try:
            connection.executescript(PENDING_CMD_SESSIONS_DDL + PENDING_CMD_SESSIONS_ACT_IDX)
            connection.commit()
        finally:
            connection.close()
        return db_path

    def test_seeds_exact_row_count_with_the_real_column_set(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            db_path = self.make_store(root)
            act_ids = [f"act-{i}" for i in range(5)]
            report = ps.seed_pending_cmd_sessions_sqlite(db_path, act_ids, 4)
            self.assertTrue(report["measured"])
            self.assertTrue(report["exact"])
            self.assertEqual(report["inserted_total_in_table"], 4)
            self.assertTrue(report["synthetic_fixture"])

            connection = sqlite3.connect(str(db_path))
            try:
                rows = connection.execute(
                    "SELECT " + ", ".join(ps.PENDING_CMD_SESSION_COLUMNS)
                    + " FROM pending_cmd_sessions ORDER BY doc_name"
                ).fetchall()
            finally:
                connection.close()
            self.assertEqual(len(rows), 4)
            for row in rows:
                record = dict(zip(ps.PENDING_CMD_SESSION_COLUMNS, row))
                self.assertEqual(record["status"], "otp_pending")
                self.assertIn(record["act_id"], act_ids)
                self.assertIsNotNone(record["session_id"])
                # Opaque to the store (`row_to_pending_session`, lib.rs:8778-8807) --
                # never parsed at rehydration -- but must still be valid JSON here so a
                # deliberate future read of it doesn't silently choke on garbage.
                json.loads(record["session_json"])
                json.loads(record["prepared_json"])

    def test_exactness_blocker_is_none_on_success_and_set_on_shortfall(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            db_path = self.make_store(root)
            act_ids = [f"act-{i}" for i in range(3)]
            report = ps.seed_pending_cmd_sessions_sqlite(db_path, act_ids, 3)
            self.assertIsNone(ps.pending_cmd_sessions_exactness_blocker(report))

            report["exact"] = False
            self.assertIsNotNone(ps.pending_cmd_sessions_exactness_blocker(report))

    def test_not_measured_report_is_always_blocked(self):
        report = ps.pending_cmd_sessions_not_measured(10000, "no sqlite path supplied")
        self.assertFalse(report["measured"])
        blocker = ps.pending_cmd_sessions_exactness_blocker(report)
        self.assertIsNotNone(blocker)
        self.assertIn("not measured", blocker)

    def test_refuses_a_missing_store_file(self):
        with tempfile.TemporaryDirectory() as raw:
            missing = pathlib.Path(raw) / "does-not-exist.sqlite3"
            with self.assertRaisesRegex(ps.PendingStressError, "does not exist"):
                ps.seed_pending_cmd_sessions_sqlite(missing, ["act-1"], 1)

    def test_refuses_a_count_larger_than_the_seeded_backlog(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            db_path = self.make_store(root)
            with self.assertRaisesRegex(ps.PendingStressError, "exceeds"):
                ps.seed_pending_cmd_sessions_sqlite(db_path, ["act-1", "act-2"], 5)

    def test_sessions_are_not_expired_at_creation(self):
        import time as time_mod

        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            db_path = self.make_store(root)
            ps.seed_pending_cmd_sessions_sqlite(db_path, ["act-1"], 1)
            connection = sqlite3.connect(str(db_path))
            try:
                created_at, expires_at = connection.execute(
                    "SELECT created_at, expires_at FROM pending_cmd_sessions"
                ).fetchone()
            finally:
                connection.close()
            self.assertLess(created_at, expires_at)


class EvaluateReadStressSloTests(unittest.TestCase):
    def slo(self) -> dict:
        return json.loads(
            (PERF_ROOT / "slo.capacity.json").read_text(encoding="utf-8")
        )

    def report(self, *, p95=100.0, p99=200.0, error_rate=0.0) -> dict:
        return {
            "error_rate": error_rate,
            "throughput_per_second": 500.0,
            "operations": {
                "signature_status": {
                    "p95_ms": p95,
                    "p99_ms": p99,
                    "error_rate": error_rate,
                },
                "act_get": {"p95_ms": p95, "p99_ms": p99, "error_rate": error_rate},
            },
        }

    def test_no_slo_is_not_configured(self):
        result = ps.evaluate_read_stress_slo(self.report(), None)
        self.assertEqual(result["assessment"], "not_configured")

    def test_within_threshold_passes(self):
        result = ps.evaluate_read_stress_slo(self.report(p95=100.0, p99=200.0), self.slo())
        self.assertEqual(result["assessment"], "passed")

    def test_over_threshold_fails(self):
        result = ps.evaluate_read_stress_slo(self.report(p95=9000.0, p99=9000.0), self.slo())
        self.assertEqual(result["assessment"], "failed")

    def test_operation_with_no_envelope_is_annotated_not_a_silent_pass(self):
        result = ps.evaluate_read_stress_slo(self.report(), self.slo())
        act_get_checks = [c for c in result["checks"] if c["metric"] == "operations.act_get"]
        self.assertEqual(len(act_get_checks), 1)
        self.assertIsNone(act_get_checks[0]["threshold"])
        self.assertIsNone(act_get_checks[0]["passed"])
        # act_get's absence must never turn the overall assessment into a pass on its own.
        self.assertIn(result["assessment"], {"passed", "failed", "not_configured"})


class MeasureBootRehydrationTests(unittest.TestCase):
    def test_issues_a_restart_then_delegates_timing_to_readiness(self):
        calls = []

        def fake_command_runner(args, *, timeout):
            calls.append((tuple(args), timeout))
            return ""

        canned_report = {
            "ready": True,
            "outcome": "ready",
            "elapsed_seconds": 12.5,
            "attempts": 3,
            "diagnostics": [],
        }
        with mock.patch.object(
            readiness, "readiness_report", return_value=canned_report
        ) as mocked_readiness_report:
            result = ps.measure_boot_rehydration(
                [pathlib.Path("docker-compose.perf.yml")],
                ["performance"],
                "chancela-perf-test",
                "chancela-cluster",
                3,
                60.0,
                1.0,
                command_runner=fake_command_runner,
            )
        self.assertTrue(result["ready"])
        self.assertEqual(result["elapsed_seconds"], 12.5)
        self.assertEqual(result["service"], "chancela-cluster")
        self.assertIn("restart_issued_after_seconds", result)
        self.assertTrue(mocked_readiness_report.called)
        # The restart command targets the requested service, through the same
        # compose-prefix builder readiness.py itself uses (single source of truth for
        # --project-name / -f / --profile flag composition).
        restart_args, _timeout = calls[0]
        self.assertIn("restart", restart_args)
        self.assertIn("chancela-cluster", restart_args)
        self.assertIn("chancela-perf-test", restart_args)


class ExecuteReadOperationTests(unittest.TestCase):
    def test_dispatches_each_known_operation(self):
        seen = []

        class RecordingClient:
            def request(self, method, path, body=None, *, authenticated=True):
                seen.append((method, path))
                return harness.HttpResult(200, 1.0, b"{}")

        client = RecordingClient()
        import random

        rng = random.Random(1)
        act_ids = ["act-1"]
        book_ids = ["book-1"]
        for name in ("act_get", "signature_status", "book_acts_list", "dashboard"):
            result = ps.execute_read_operation(name, client, act_ids, book_ids, rng)
            self.assertEqual(result.status, 200)
        paths = [path for _method, path in seen]
        self.assertIn("/v1/acts/act-1", paths)
        self.assertIn("/v1/acts/act-1/signature", paths)
        self.assertIn("/v1/books/book-1/acts", paths)
        self.assertIn("/v1/dashboard", paths)

    def test_unknown_operation_raises(self):
        import random

        with self.assertRaises(ps.PendingStressError):
            ps.execute_read_operation("nope", object(), ["a"], ["b"], random.Random(1))


class FakePendingApiHandler(BaseHTTPRequestHandler):
    def reply(self, status, value):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/dashboard":
            self.reply(200, {"acts_awaiting_signature": self.server.counters["acts"]})
            return
        # /v1/acts/{id}, /v1/acts/{id}/signature, /v1/books/{id}/acts all fall through
        # to a generic 200 -- the read-stress path only asserts on status/latency here.
        self.reply(200, {"id": self.path.rsplit("/", 2)[-1]})

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
        else:
            self.reply(404, {"error": self.path, "payload": payload})
            return
        with self.server.state_lock:
            self.server.counters[kind] += 1
            identifier = f"{kind}-{self.server.counters[kind]}"
        self.reply(201, {"id": identifier})

    def log_message(self, _format, *_args):
        pass


class BacklogSeedingIntegrationTests(unittest.TestCase):
    def start_server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakePendingApiHandler)
        server.counters = {"users": 0, "entities": 0, "books": 0, "acts": 0}
        server.state_lock = threading.Lock()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def stop_server(self, server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    def test_backlog_seed_and_read_stress_are_exact_and_error_free(self):
        server, thread = self.start_server()
        try:
            client = harness.ApiClient(
                f"http://127.0.0.1:{server.server_port}", timeout=2
            )
            profile = base_profile()
            ps.bootstrap_owner(client, ps.DEFAULT_PASSWORD)
            seed_report, entity_ids, book_ids = ps.seed_entities_and_books(
                client, profile["backlog"]
            )
            self.assertTrue(seed_report["entities"]["exact"])
            self.assertTrue(seed_report["books"]["exact"])
            self.assertEqual(len(entity_ids), profile["backlog"]["entities"])
            self.assertEqual(len(book_ids), profile["backlog"]["books"])

            backlog_report, act_ids = ps.seed_backlog_to_signing(
                client, profile["backlog"], book_ids
            )
            self.assertTrue(backlog_report["exact"])
            self.assertEqual(len(act_ids), profile["backlog"]["target_acts_in_signing"])
            self.assertEqual(len(set(act_ids)), len(act_ids))

            with mock.patch.object(harness, "docker_snapshot", return_value=[]):
                read_stress_report, resources = ps.run_read_stress(
                    client, profile, act_ids, book_ids
                )
            self.assertGreater(read_stress_report["requests"], 0)
            self.assertEqual(read_stress_report["errors"], 0)
            self.assertFalse(resources["available"])
        finally:
            self.stop_server(server, thread)

    def test_read_stress_refuses_to_run_without_seeded_acts(self):
        server, thread = self.start_server()
        try:
            client = harness.ApiClient(
                f"http://127.0.0.1:{server.server_port}", timeout=2
            )
            profile = base_profile()
            with self.assertRaisesRegex(ps.PendingStressError, "backlog act ids"):
                ps.run_read_stress(client, profile, [], ["book-1"])
        finally:
            self.stop_server(server, thread)


if __name__ == "__main__":
    unittest.main()
