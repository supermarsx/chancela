import pathlib
import subprocess
import sys
import unittest


PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = PERF_ROOT.parents[1]
sys.path.insert(0, str(PERF_ROOT))

import readiness  # noqa: E402


def container(
    *,
    name="container",
    running=True,
    status="running",
    health="healthy",
    restart_count=0,
    oom_killed=False,
):
    return {
        "name": name,
        "running": running,
        "status": status,
        "health": health,
        "restart_count": restart_count,
        "oom_killed": oom_killed,
    }


def snapshot(health="healthy"):
    return {
        "chancela-cluster": [
            container(name=f"app-{number}", health=health)
            for number in range(1, 4)
        ],
        "search-projector-postgres": [
            container(name="projector", health=health)
        ],
        "postgres": [container(name="postgres", health=health)],
        "redis": [container(name="redis", health=health)],
        "perf-gateway": [container(name="gateway", health=health)],
        "server-postgres": [],
        "server-sqlite": [],
        "search-projector-sqlite": [],
    }


class Clock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


class ReadinessTests(unittest.TestCase):
    def test_starting_converges_at_fixed_cadence(self):
        states = [snapshot("starting"), snapshot("starting"), snapshot()]
        clock = Clock()
        report = readiness.readiness_report(
            lambda _deadline: states.pop(0),
            3,
            120,
            2,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
        self.assertTrue(report["ready"])
        self.assertEqual(report["outcome"], readiness.READY)
        self.assertEqual(report["attempts"], 3)
        self.assertEqual(report["elapsed_seconds"], 4)
        self.assertEqual(clock.sleeps, [2, 2])

    def test_unhealthy_is_terminal_without_retry(self):
        observed = snapshot()
        observed["search-projector-postgres"][0]["health"] = "unhealthy"
        clock = Clock()
        report = readiness.readiness_report(
            lambda _deadline: observed,
            3,
            120,
            2,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
        self.assertEqual(report["outcome"], readiness.TERMINAL)
        self.assertEqual(report["attempts"], 1)
        self.assertEqual(clock.sleeps, [])
        self.assertIn("health is 'unhealthy'", report["diagnostics"][0])

    def test_restart_and_oom_are_terminal_without_retry(self):
        for field, value, marker in (
            ("restart_count", 1, "restarted 1 times"),
            ("oom_killed", True, "OOM-killed"),
        ):
            with self.subTest(field=field):
                observed = snapshot("starting")
                observed["search-projector-postgres"][0][field] = value
                state, diagnostics = readiness.classify_snapshot(observed, 3)
                self.assertEqual(state, readiness.TERMINAL)
                self.assertTrue(any(marker in item for item in diagnostics))

    def test_missing_non_running_and_healthless_shapes_are_terminal(self):
        cases = {}
        missing = snapshot("starting")
        missing["chancela-cluster"].pop()
        cases["missing"] = missing
        stopped = snapshot("starting")
        stopped["postgres"][0].update(running=False, status="exited")
        cases["stopped"] = stopped
        healthless = snapshot("starting")
        healthless["redis"][0]["health"] = None
        cases["healthless"] = healthless
        for name, observed in cases.items():
            with self.subTest(name=name):
                state, diagnostics = readiness.classify_snapshot(observed, 3)
                self.assertEqual(state, readiness.TERMINAL)
                self.assertTrue(diagnostics)

    def test_timeout_reports_attempts_elapsed_and_last_snapshot(self):
        clock = Clock()
        report = readiness.readiness_report(
            lambda _deadline: snapshot("starting"),
            3,
            5,
            2,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
        self.assertFalse(report["ready"])
        self.assertEqual(report["outcome"], "timeout")
        self.assertEqual(report["attempts"], 3)
        self.assertEqual(report["elapsed_seconds"], 5)
        self.assertEqual(clock.sleeps, [2, 2, 1])
        projector = report["last_snapshot"]["search-projector-postgres"][0]
        self.assertEqual(
            {
                key: projector[key]
                for key in (
                    "name",
                    "status",
                    "health",
                    "restart_count",
                    "oom_killed",
                )
            },
            {
                "name": "projector",
                "status": "running",
                "health": "starting",
                "restart_count": 0,
                "oom_killed": False,
            },
        )

    def test_snapshot_commands_share_the_remaining_hard_deadline(self):
        clock = Clock()
        observed_timeouts = []

        def consume_one_second(_args, *, timeout):
            observed_timeouts.append(timeout)
            clock.value += min(1, timeout)
            return ""

        with self.assertRaisesRegex(
            Exception,
            "snapshot exhausted its deadline",
        ):
            readiness.capture_snapshot(
                ["docker", "compose"],
                6,
                monotonic=clock.monotonic,
                command_runner=consume_one_second,
            )
        self.assertEqual(observed_timeouts, [5, 5, 4, 3, 2, 1])
        self.assertEqual(clock.value, 6)

    def test_slow_snapshot_reaches_timeout_without_an_extra_poll(self):
        clock = Clock()
        calls = []

        def consume_remaining(deadline):
            calls.append(deadline)
            clock.value = deadline
            return snapshot("starting")

        report = readiness.readiness_report(
            consume_remaining,
            3,
            5,
            2,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
        self.assertEqual(report["outcome"], "timeout")
        self.assertEqual(report["attempts"], 1)
        self.assertEqual(report["elapsed_seconds"], 5)
        self.assertEqual(calls, [5])
        self.assertEqual(clock.sleeps, [])

    def test_command_timeout_is_serialized_as_timeout_evidence(self):
        clock = Clock()

        def command_timeout(args, *, timeout):
            clock.value += timeout
            raise subprocess.TimeoutExpired(args, timeout)

        report = readiness.readiness_report(
            lambda deadline: readiness.capture_snapshot(
                ["docker", "compose"],
                deadline,
                monotonic=clock.monotonic,
                command_runner=command_timeout,
            ),
            3,
            5,
            2,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
        self.assertEqual(report["outcome"], "timeout")
        self.assertFalse(report["ready"])
        self.assertEqual(report["attempts"], 1)
        self.assertEqual(report["elapsed_seconds"], 5)
        self.assertIn("command timed out after 5.000s", report["diagnostics"][0])
        self.assertEqual(
            set(report["last_snapshot"]),
            set(readiness.topology.CAPTURED_SERVICES),
        )

    def test_bounds_are_positive_and_capped(self):
        readiness.validate_bounds(120, 2)
        for timeout, poll in ((0, 2), (901, 2), (120, 0), (120, 31), (1, 2)):
            with self.subTest(timeout=timeout, poll=poll):
                with self.assertRaises(Exception):
                    readiness.validate_bounds(timeout, poll)

    def test_run_compose_keeps_strict_gate_after_readiness(self):
        script = (PERF_ROOT / "run-compose.sh").read_text(encoding="utf-8")
        wait_call = script.index('if ! "${READINESS_ARGS[@]}"')
        strict_call = script.index('"${TOPOLOGY_ARGS[@]}" --output "$TOPOLOGY_INITIAL"')
        harness_call = script.index('"${args[@]}" 2>&1 | tee')
        self.assertLess(wait_call, strict_call)
        self.assertLess(strict_call, harness_call)
        strict_line = script[strict_call : script.index("\n", strict_call)]
        self.assertNotIn("--allow-degraded", strict_line)
        self.assertIn("topology-readiness-compose-ps.log", script)
        self.assertIn("topology-readiness-compose.log", script)


if __name__ == "__main__":
    unittest.main()
