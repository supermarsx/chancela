import json
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.parse
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
                        "warmup_seconds": 0.1,
                        "ramp_seconds": 0.1,
                        "peak_plateau_seconds": 0.7,
                        "cooldown_seconds": 0.1,
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

    def test_explicit_phases_require_a_nonzero_plateau_and_exact_duration(self):
        with tempfile.TemporaryDirectory() as raw:
            profile_path = self.profile(pathlib.Path(raw))
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            profile["workload"]["peak_plateau_seconds"] = 0
            with self.assertRaisesRegex(harness.HarnessError, "peak_plateau"):
                harness.validate_profile(profile)
            profile["workload"]["peak_plateau_seconds"] = 0.6
            with self.assertRaisesRegex(harness.HarnessError, "must sum"):
                harness.validate_profile(profile)


class FailureReportTests(unittest.TestCase):
    def test_malformed_slo_writes_a_harness_failure_report(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            profile_path = DatasetTests().profile(root)
            dataset = root / "dataset"
            harness.generate_dataset(profile_path, dataset)
            slo = root / "malformed-slo.json"
            slo.write_text(
                json.dumps({"schema_version": 1, "operations": []}),
                encoding="utf-8",
            )
            report_dir = root / "report"
            args = mock.Mock(
                profile=profile_path,
                dataset_dir=dataset,
                report_dir=report_dir,
                base_url="http://127.0.0.1:1",
                slo=slo,
                topology_evidence=None,
                final_topology_evidence=None,
                duration_budget_evidence=None,
                search_readiness_timeout_seconds=1,
                cryptographic_config=None,
            )
            with mock.patch.object(harness, "docker_snapshot", return_value=[]):
                with self.assertRaises(harness.HarnessError):
                    harness.run_command(args)
            failure = json.loads(
                (report_dir / "report.json").read_text(encoding="utf-8")
            )
            self.assertFalse(failure["slo"]["proof_ready"])
            self.assertIn("HarnessError", failure["seed"]["fatal_error"])
            self.assertNotIn("AttributeError", failure["seed"]["fatal_error"])

    def test_final_topology_is_enforced_before_proof_classification(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            profile_path = DatasetTests().profile(root)
            dataset = root / "dataset"
            harness.generate_dataset(profile_path, dataset)
            containers = {
                "chancela-cluster": [
                    {"id": "app-1"},
                    {"id": "app-2"},
                    {"id": "app-3"},
                ],
                "postgres": [{"id": "postgres-1"}],
                "redis": [{"id": "redis-1"}],
                "perf-gateway": [{"id": "gateway-1"}],
            }
            initial = {
                "preflight_passed": True,
                "failures": [],
                "summary": {
                    "project_name": "custom-stack",
                    "app_replicas": 3,
                    "expected_app_replicas": 3,
                    "aggregate_resource_envelope": {"within_envelope": True},
                    "compose_files": ["compose.yml"],
                    "profiles": ["performance"],
                },
                "containers": containers,
            }
            final = {
                **initial,
                "preflight_passed": False,
                "failures": ["chancela-cluster/app-1 restarted 1 times"],
            }
            topology_path = root / "topology-initial.json"
            topology_path.write_text(json.dumps(initial), encoding="utf-8")
            budget_path = root / "duration-budget.json"
            budget_path.write_text(
                json.dumps({"budget_passed": True}),
                encoding="utf-8",
            )
            slo_path = root / "slo.json"
            slo_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "global": {"max_error_rate": 1},
                    }
                ),
                encoding="utf-8",
            )
            report_dir = root / "report"
            args = mock.Mock(
                profile=profile_path,
                dataset_dir=dataset,
                report_dir=report_dir,
                base_url="http://127.0.0.1:1",
                slo=slo_path,
                topology_evidence=topology_path,
                final_topology_evidence=report_dir / "topology-final.json",
                duration_budget_evidence=budget_path,
                search_readiness_timeout_seconds=1,
                cryptographic_config=None,
            )
            resources = {
                "available": True,
                "containers": {
                    "app": {"max_memory_bytes": 1, "max_cpu_percent": 1}
                },
                "phases": {
                    phase: {
                        "containers": {
                            "app": {"max_memory_bytes": 1, "max_cpu_percent": 1}
                        }
                    }
                    for phase in ("seed", "search_catch_up", "mixed_workload")
                },
            }
            sampler = mock.Mock()
            sampler.finish.return_value = resources
            workload = {
                "mode": "steady",
                "duration_seconds": 1,
                "requests": 1,
                "errors": 0,
                "error_rate": 0,
                "throughput_per_second": 1,
                "operations": {},
                "phases": {"model": "explicit", "peak_plateau_complete": True},
            }
            readiness = {
                "ready": True,
                "duration_seconds": 0,
                "status": {"generation": 1},
                "pagination_probe": {"cursor_exercised": True},
            }
            index = {
                "users": ["user-1"],
                "entities": ["entity-1"],
                "books": ["book-1"],
                "signatures": ["act-1"],
            }
            seed = {
                "exact": True,
                "coverage_gap": "Synthetic evidence boundary.",
            }
            with (
                mock.patch.object(harness, "ResourceSampler", return_value=sampler),
                mock.patch.object(harness, "seed_dataset", return_value=(seed, index)),
                mock.patch.object(
                    harness,
                    "wait_for_search_ready",
                    return_value=readiness,
                ),
                mock.patch.object(
                    harness,
                    "run_workload",
                    return_value=(workload, resources),
                ),
                mock.patch.object(
                    harness,
                    "capture_final_topology",
                    return_value=final,
                ),
            ):
                exit_code = harness.run_command(args)
            self.assertEqual(exit_code, 5)
            report = json.loads(
                (report_dir / "report.json").read_text(encoding="utf-8")
            )
            self.assertFalse(report["slo"]["proof_ready"])
            self.assertEqual(report["slo"]["assessment"], "not_configured")
            self.assertIn("initial", report["topology"])
            self.assertIn("final", report["topology"])
            self.assertIn(
                "restarted",
                " ".join(report["slo"]["proof_blockers"]),
            )


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

    def test_explicit_workload_phases_sustain_peak_clients(self):
        workload = {
            "mode": "ramp",
            "duration_seconds": 40,
            "clients": 8,
            "warmup_seconds": 5,
            "ramp_seconds": 10,
            "peak_plateau_seconds": 20,
            "cooldown_seconds": 5,
        }
        self.assertEqual(harness.workload_phase_and_clients(workload, 1), ("warmup", 2))
        self.assertEqual(harness.workload_phase_and_clients(workload, 10)[0], "ramp")
        self.assertEqual(
            harness.workload_phase_and_clients(workload, 20),
            ("peak_plateau", 8),
        )
        self.assertEqual(harness.workload_phase_and_clients(workload, 38)[0], "cooldown")
        report = harness.workload_phase_report(workload, 40)
        self.assertTrue(report["peak_plateau_complete"])
        self.assertEqual(report["peak_plateau_observed_seconds"], 20)

    def test_resource_size_parser(self):
        self.assertEqual(harness.parse_size_bytes("1KiB"), 1024)
        self.assertEqual(harness.parse_size_bytes("1.5 MiB"), 1.5 * 1024 * 1024)
        self.assertEqual(harness.parse_size_bytes("2GB"), 2_000_000_000)

    def test_null_slo_is_not_a_pass(self):
        result = harness.evaluate_slo(
            {
                "error_rate": 0.0,
                "throughput_per_second": 100,
                "operations": {},
                "phases": {"model": "explicit", "peak_plateau_complete": True},
            },
            {"containers": {}},
            {"schema_version": 1, "global": {"max_error_rate": None}},
        )
        self.assertEqual(result["assessment"], "not_configured")
        self.assertEqual(result["configured_thresholds"], 0)

    def test_configured_slo_passes_and_fails_from_measurements(self):
        workload = {
            "error_rate": 0.01,
            "throughput_per_second": 50,
            "operations": {"entity_list": {"p95_ms": 20, "p99_ms": 30, "error_rate": 0}},
            "phases": {"model": "explicit", "peak_plateau_complete": True},
        }
        resources = {
            "available": True,
            "containers": {
                "chancela": {"max_memory_bytes": 1000, "max_cpu_percent": 25}
            },
            "phases": {
                phase: {
                    "containers": {
                        "chancela": {
                            "max_memory_bytes": 1000,
                            "max_cpu_percent": 25,
                        }
                    }
                }
                for phase in ("seed", "search_catch_up", "mixed_workload")
            },
        }
        passing = {
            "schema_version": 1,
            "global": {"max_error_rate": 0.02, "min_throughput_per_second": 40},
            "operations": {"entity_list": {"p95_ms": 25}},
            "resources": {"max_container_memory_bytes": 2000},
        }
        self.assertEqual(
            harness.evaluate_slo(workload, resources, passing)["assessment"], "passed"
        )
        failing = {"schema_version": 1, "global": {"max_error_rate": 0.001}}
        self.assertEqual(
            harness.evaluate_slo(workload, resources, failing)["assessment"], "failed"
        )

    def test_requested_crypto_without_complete_reviewed_thresholds_is_not_configured(self):
        workload = {
            "error_rate": 0.0,
            "throughput_per_second": 50,
            "operations": {},
            "phases": {"model": "explicit", "peak_plateau_complete": True},
        }
        resources = {
            "available": True,
            "containers": {"app": {"max_memory_bytes": 1000, "max_cpu_percent": 20}},
            "phases": {
                phase: {
                    "containers": {
                        "app": {"max_memory_bytes": 900, "max_cpu_percent": 15}
                    }
                }
                for phase in (
                    "seed",
                    "search_catch_up",
                    "cryptographic_signing",
                    "mixed_workload",
                )
            },
        }
        crypto = {
            "enabled": True,
            "requested": 10000,
            "signed": 10000,
            "exact": True,
            "duration_seconds": 100,
            "throughput_per_second": 100,
            "sign_operation": {"error_rate": 0, "p95_ms": 10, "p99_ms": 15},
        }
        incomplete = {
            "schema_version": 1,
            "global": {"max_error_rate": 0.01},
            "cryptographic_signing": {"min_completed": 10000},
        }
        result = harness.evaluate_slo(workload, resources, incomplete, crypto)
        self.assertEqual(result["assessment"], "not_configured")
        self.assertIn("p99_ms", " ".join(result["proof_blockers"]))

        complete = {
            "schema_version": 1,
            "global": {"max_error_rate": 0.01},
            "cryptographic_signing": {
                "min_completed": 10000,
                "max_error_rate": 0,
                "min_throughput_per_second": 90,
                "p95_ms": 20,
                "p99_ms": 25,
                "max_duration_seconds": 120,
                "max_phase_memory_bytes": 1000,
                "max_phase_cpu_percent": 20,
            },
        }
        self.assertEqual(
            harness.evaluate_slo(workload, resources, complete, crypto)["assessment"],
            "passed",
        )
        incomplete_volume = {
            **crypto,
            "signed": 9_999,
            "exact": False,
        }
        lower_minimum = {
            **complete,
            "cryptographic_signing": {
                **complete["cryptographic_signing"],
                "min_completed": 1,
            },
        }
        result = harness.evaluate_slo(
            workload,
            resources,
            lower_minimum,
            incomplete_volume,
        )
        self.assertEqual(result["assessment"], "not_configured")
        self.assertFalse(result["proof_ready"])
        self.assertIn("exact requested volume", " ".join(result["proof_blockers"]))

    def test_slo_nested_shapes_and_threshold_types_are_strict(self):
        workload = {
            "error_rate": 0.0,
            "throughput_per_second": 100,
            "operations": {},
            "phases": {"model": "explicit", "peak_plateau_complete": True},
        }
        resources = {"available": False, "containers": {}, "phases": {}}
        malformed = [
            {"schema_version": 1, "global": []},
            {"schema_version": 1, "operations": {"entity_list": []}},
            {"schema_version": 1, "resources": "unbounded"},
            {"schema_version": 1, "cryptographic_signing": []},
            {"schema_version": 1, "global": {"max_error_rate": True}},
            {
                "schema_version": 1,
                "operations": {"entity_list": {"p95_ms": "fast"}},
            },
        ]
        for slo in malformed:
            with self.subTest(slo=slo):
                with self.assertRaises(harness.HarnessError):
                    harness.evaluate_slo(workload, resources, slo)

    def test_unavailable_resource_sampling_cannot_be_a_performance_pass(self):
        workload = {
            "error_rate": 0.0,
            "throughput_per_second": 100,
            "operations": {},
            "phases": {"model": "explicit", "peak_plateau_complete": True},
        }
        result = harness.evaluate_slo(
            workload,
            {"available": False, "containers": {}, "phases": {}},
            {"schema_version": 1, "global": {"max_error_rate": 0.01}},
        )
        self.assertEqual(result["assessment"], "not_configured")
        self.assertFalse(result["proof_ready"])
        self.assertIn("unavailable", " ".join(result["proof_blockers"]))

    def test_resource_samples_are_aggregated_by_phase(self):
        sampler = harness.ResourceSampler()
        sampler.samples = [
            {
                "container": "app",
                "cpu_percent": 10,
                "memory_bytes": 100,
                "phase": "seed",
            },
            {
                "container": "app",
                "cpu_percent": 30,
                "memory_bytes": 200,
                "phase": "cryptographic_signing",
            },
        ]
        report = sampler.report()
        self.assertEqual(report["containers"]["app"]["max_cpu_percent"], 30)
        self.assertEqual(
            report["phases"]["cryptographic_signing"]["containers"]["app"][
                "max_memory_bytes"
            ],
            200,
        )

    def test_resource_sampler_discovers_a_custom_compose_project_by_label(self):
        discovered = mock.Mock(returncode=0, stdout="abc123\n", stderr="")
        stats = mock.Mock(
            returncode=0,
            stdout=json.dumps(
                {
                    "Name": "custom-stack-api-1",
                    "CPUPerc": "12.5%",
                    "MemUsage": "32MiB / 1GiB",
                }
            )
            + "\n",
            stderr="",
        )
        with mock.patch.object(
            harness.subprocess,
            "run",
            side_effect=[discovered, stats],
        ) as run:
            samples = harness.docker_snapshot("custom-stack")
        self.assertEqual(samples[0]["container"], "custom-stack-api-1")
        discovery_command = run.call_args_list[0].args[0]
        self.assertIn(
            "label=com.docker.compose.project=custom-stack",
            discovery_command,
        )
        self.assertNotIn("chancela", samples[0]["container"])

    def test_soak_plus_10k_crypto_has_a_deterministic_whole_job_budget(self):
        profile = json.loads(
            (PERF_ROOT / "profiles" / "soak.json").read_text(encoding="utf-8")
        )
        crypto = {"count": 10_000}
        combined_run = harness.duration_budget_report(
            profile,
            workflow_timeout_seconds=360 * 60,
            search_readiness_timeout_seconds=900,
            cryptographic_config=crypto,
        )
        self.assertFalse(combined_run["budget_passed"])
        soak_only = harness.duration_budget_report(
            profile,
            workflow_timeout_seconds=360 * 60,
            search_readiness_timeout_seconds=900,
        )
        self.assertTrue(soak_only["budget_passed"])
        self.assertGreater(
            soak_only["components"]["cleanup_and_artifact_upload"],
            0,
        )

    def test_final_topology_regression_blocks_combined_proof(self):
        def snapshot(*, passed=True, app_ids=("app-1", "app-2", "app-3")):
            containers = {
                "chancela-cluster": [{"id": identifier} for identifier in app_ids],
                "postgres": [{"id": "postgres-1"}],
                "redis": [{"id": "redis-1"}],
                "perf-gateway": [{"id": "gateway-1"}],
            }
            return {
                "preflight_passed": passed,
                "failures": [] if passed else ["chancela-cluster/app-1 restarted"],
                "summary": {
                    "project_name": "custom-stack",
                    "app_replicas": len(app_ids),
                    "expected_app_replicas": 3,
                    "aggregate_resource_envelope": {"within_envelope": True},
                },
                "containers": containers,
            }

        stable = harness.combine_topology_evidence(snapshot(), snapshot())
        self.assertTrue(stable["preflight_passed"])
        regressed = harness.combine_topology_evidence(
            snapshot(),
            snapshot(passed=False, app_ids=("app-1", "app-2")),
        )
        self.assertFalse(regressed["preflight_passed"])
        self.assertTrue(any("final:" in item for item in regressed["failures"]))
        self.assertTrue(any("container set changed" in item for item in regressed["failures"]))


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


class SearchReadinessTests(unittest.TestCase):
    def index(self):
        return {
            "entities": ["entity-1"],
            "books": ["book-1"],
            "signatures": ["act-1"],
        }

    def test_readiness_timeout_reports_non_current_status(self):
        client = mock.Mock()
        client.request.return_value = harness.HttpResult(
            200,
            1.0,
            json.dumps(
                {
                    "enabled": True,
                    "phase": "rebuilding",
                    "partial": True,
                    "stale": True,
                    "generation": 1,
                    "document_count": 3,
                }
            ).encode(),
        )
        with self.assertRaisesRegex(harness.HarnessError, "readiness timed out"):
            harness.wait_for_search_ready(
                client,
                self.index(),
                3,
                timeout_seconds=0.02,
                poll_seconds=0.001,
            )

    def test_missing_known_hit_cannot_be_reported_ready(self):
        client = mock.Mock()
        client.request.return_value = harness.HttpResult(
            200,
            1.0,
            json.dumps(
                {
                    "enabled": True,
                    "phase": "idle",
                    "partial": False,
                    "stale": False,
                    "generation": 2,
                    "document_count": 3,
                }
            ).encode(),
        )
        with mock.patch.object(
            harness,
            "search_probe",
            return_value={"matched": False},
        ):
            with self.assertRaisesRegex(harness.HarnessError, "last_probes"):
                harness.wait_for_search_ready(
                    client,
                    self.index(),
                    3,
                    timeout_seconds=0.02,
                    poll_seconds=0.001,
                )

    @staticmethod
    def pagination_response(
        identifier: str,
        *,
        offset: int,
        total: int = 2,
        has_more: bool,
        cursor: str | None,
        generation: int = 2,
    ) -> harness.HttpResult:
        return harness.HttpResult(
            200,
            1.0,
            json.dumps(
                {
                    "page": {
                        "total": total,
                        "offset": offset,
                        "limit": 1,
                        "has_more": has_more,
                        "hits": [{"entity_id": identifier, "kind": "entity"}],
                    },
                    "next_cursor": cursor,
                    "index": {"generation": generation},
                }
            ).encode(),
        )

    def test_cursor_probe_requires_distinct_nonempty_coherent_stable_pages(self):
        first = self.pagination_response(
            "entity-1",
            offset=0,
            has_more=True,
            cursor="cursor-1",
        )
        valid_second = self.pagination_response(
            "entity-2",
            offset=1,
            has_more=False,
            cursor=None,
        )
        client = mock.Mock()
        client.request.side_effect = [first, valid_second]
        self.assertTrue(
            harness.search_pagination_probe(client, 2)["cursor_exercised"]
        )

        invalid_seconds = {
            "empty": harness.HttpResult(
                200,
                1.0,
                json.dumps(
                    {
                        "page": {
                            "total": 2,
                            "offset": 1,
                            "limit": 1,
                            "has_more": False,
                            "hits": [],
                        },
                        "next_cursor": None,
                        "index": {"generation": 2},
                    }
                ).encode(),
            ),
            "duplicate": self.pagination_response(
                "entity-1",
                offset=1,
                has_more=False,
                cursor=None,
            ),
            "generation": self.pagination_response(
                "entity-2",
                offset=1,
                has_more=False,
                cursor=None,
                generation=3,
            ),
            "total": self.pagination_response(
                "entity-2",
                offset=1,
                total=3,
                has_more=True,
                cursor="cursor-2",
            ),
            "has_more_cursor": self.pagination_response(
                "entity-2",
                offset=1,
                has_more=True,
                cursor=None,
            ),
        }
        for case, second in invalid_seconds.items():
            with self.subTest(case=case):
                client = mock.Mock()
                client.request.side_effect = [first, second]
                result = harness.search_pagination_probe(client, 2)
                self.assertFalse(result["cursor_exercised"])
                self.assertIn("error", result)


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
        elif self.path == "/v1/search/status":
            self.reply(
                200,
                {
                    "details_redacted": False,
                    "enabled": True,
                    "partial": False,
                    "stale": False,
                    "phase": "idle",
                    "generation": 2,
                    "document_count": 15,
                    "indexed_content_chars": 1000,
                    "content_truncated": False,
                    "truncated_document_count": 0,
                },
            )
        elif self.path.startswith("/v1/search?"):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            kind = query.get("kind", ["entity"])[0]
            cursor = query.get("cursor", [None])[0]
            if "," in kind:
                relation_key = "entity_id"
                identifier = "entities-2" if cursor else "entities-1"
                offset = 1 if cursor else 0
                next_cursor = "test-cursor-2" if cursor else "test-cursor"
                total = 15
            elif kind == "book":
                relation_key, identifier = "book_id", "books-1"
                offset, next_cursor, total = 0, None, 1
            elif kind == "act":
                relation_key, identifier = "act_id", "acts-1"
                offset, next_cursor, total = 0, None, 1
            else:
                relation_key, identifier = "entity_id", "entities-1"
                offset, next_cursor, total = 0, None, 1
            self.reply(
                200,
                {
                    "page": {
                        "total": total,
                        "offset": offset,
                        "limit": 1,
                        "has_more": next_cursor is not None,
                        "facets_truncated": False,
                        "hits": [{relation_key: identifier, "kind": kind}],
                        "facets": {},
                    },
                    "next_cursor": next_cursor,
                    "pagination_truncated": False,
                    "index": {"generation": 2},
                },
            )
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
            profile["workload"]["warmup_seconds"] = 0.02
            profile["workload"]["ramp_seconds"] = 0.03
            profile["workload"]["peak_plateau_seconds"] = 0.18
            profile["workload"]["cooldown_seconds"] = 0.02
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
                "search_query": 1,
                "search_status": 1,
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
                readiness = harness.wait_for_search_ready(
                    client,
                    index,
                    15,
                    timeout_seconds=1,
                    poll_seconds=0.01,
                )
                self.assertTrue(readiness["ready"])
                self.assertTrue(readiness["pagination_probe"]["cursor_exercised"])
                self.assertTrue(
                    all(
                        probe["matched"]
                        for probe in readiness["known_record_probes"]
                    )
                )
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
