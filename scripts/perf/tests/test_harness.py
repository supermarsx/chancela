from __future__ import annotations

import copy
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
REPO_ROOT = PERF_ROOT.parents[1]
sys.path.insert(0, str(PERF_ROOT))

import harness  # noqa: E402


EXPECTED_CAPACITY_POLICY = {
    "schema_version": 1,
    "global": {
        "max_error_rate": 0.005,
        "min_throughput_per_second": 100,
    },
    "operations": {
        "health": {"p95_ms": 200, "p99_ms": 500, "max_error_rate": 0.001},
        "entity_list": {
            "p95_ms": 500,
            "p99_ms": 1000,
            "max_error_rate": 0.01,
        },
        "entity_get": {
            "p95_ms": 250,
            "p99_ms": 500,
            "max_error_rate": 0.01,
        },
        "book_list": {
            "p95_ms": 750,
            "p99_ms": 1500,
            "max_error_rate": 0.01,
        },
        "book_get": {
            "p95_ms": 250,
            "p99_ms": 500,
            "max_error_rate": 0.01,
        },
        "user_list": {
            "p95_ms": 750,
            "p99_ms": 1500,
            "max_error_rate": 0.01,
        },
        "auth_login": {
            "p95_ms": 1500,
            "p99_ms": 3000,
            "max_error_rate": 0.01,
        },
        "entity_write": {
            "p95_ms": 500,
            "p99_ms": 1000,
            "max_error_rate": 0.01,
        },
        "signature_status": {
            "p95_ms": 250,
            "p99_ms": 500,
            "max_error_rate": 0.01,
        },
        "search_query": {
            "p95_ms": 750,
            "p99_ms": 1500,
            "max_error_rate": 0.01,
        },
        "search_status": {
            "p95_ms": 250,
            "p99_ms": 500,
            "max_error_rate": 0.01,
        },
    },
    "cryptographic_signing": {
        "min_completed": 10000,
        "max_error_rate": 0,
        "min_throughput_per_second": 2,
        "p95_ms": 1000,
        "p99_ms": 2000,
        "max_duration_seconds": 7200,
        "max_phase_memory_bytes": 900000000,
        "max_phase_cpu_percent": 190,
    },
    "resources": {
        "max_container_memory_bytes": 900000000,
        "max_container_cpu_percent": 190,
    },
}


class DatasetTests(unittest.TestCase):
    def profile(self, root: pathlib.Path) -> pathlib.Path:
        path = root / "profile.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "name": "test",
                    "proof_eligible": True,
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

    def test_seed_concurrency_must_be_a_positive_integer(self):
        with tempfile.TemporaryDirectory() as raw:
            profile_path = self.profile(pathlib.Path(raw))
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            for invalid in (None, True, 0, -1, 1.5, "12"):
                with self.subTest(invalid=invalid):
                    profile["seed_concurrency"] = invalid
                    with self.assertRaisesRegex(
                        harness.HarnessError,
                        "seed_concurrency must be a positive integer",
                    ):
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


class ProofEligibilityTests(unittest.TestCase):
    def test_profile_proof_eligibility_is_required_and_pr_smoke_cannot_enable_it(self):
        with tempfile.TemporaryDirectory() as raw:
            profile_path = DatasetTests().profile(pathlib.Path(raw))
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            profile.pop("proof_eligible")
            with self.assertRaisesRegex(harness.HarnessError, "proof_eligible"):
                harness.validate_profile(profile)

            profile["proof_eligible"] = "yes"
            with self.assertRaisesRegex(harness.HarnessError, "proof_eligible"):
                harness.validate_profile(profile)

            profile["proof_eligible"] = True
            profile["name"] = "pr-smoke"
            with self.assertRaisesRegex(harness.HarnessError, "must not"):
                harness.validate_profile(profile)

    def test_committed_profiles_freeze_proof_eligibility(self):
        eligibility = {}
        for profile_name in ("capacity", "soak", "pr-smoke"):
            profile = json.loads(
                (PERF_ROOT / "profiles" / f"{profile_name}.json").read_text(
                    encoding="utf-8"
                )
            )
            harness.validate_profile(profile)
            eligibility[profile_name] = profile["proof_eligible"]
        self.assertEqual(
            eligibility,
            {"capacity": True, "soak": True, "pr-smoke": False},
        )

    def test_pr_smoke_is_non_proof_even_if_a_passing_report_is_misdeclared(self):
        profile = {"name": "pr-smoke", "proof_eligible": True}
        source = {
            "kind": "local",
            "ref": "main",
            "commit_sha": "a" * 40,
            "working_tree_dirty": False,
            "proof_eligible": True,
        }
        slo_report = {
            "assessment": "passed",
            "proof_ready": True,
            "proof_blockers": [],
            "message": "Every explicitly configured threshold passed.",
        }
        harness.add_proof_blockers(
            slo_report,
            harness.proof_context_blockers(profile, source),
        )
        self.assertEqual(slo_report["assessment"], "not_configured")
        self.assertFalse(slo_report["proof_ready"])
        self.assertIn("evidence-only", " ".join(slo_report["proof_blockers"]))

    def test_github_actions_proof_requires_main_ref_and_valid_commit_sha(self):
        profile = {"name": "capacity", "proof_eligible": True}
        for ref, commit_sha, expected in (
            ("refs/heads/main", "a" * 40, True),
            ("refs/heads/main", "short-sha", False),
            ("refs/heads/main", None, False),
            ("refs/heads/feature", "a" * 40, False),
            ("refs/pull/42/merge", "a" * 40, False),
            (None, "a" * 40, False),
        ):
            environment = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "example/chancela",
            }
            if ref is not None:
                environment["GITHUB_REF"] = ref
            if commit_sha is not None:
                environment["GITHUB_SHA"] = commit_sha
            with self.subTest(ref=ref, commit_sha=commit_sha), mock.patch.dict(
                harness.os.environ,
                environment,
                clear=True,
            ):
                source = harness.capture_source_context()
                blockers = harness.proof_context_blockers(profile, source)
                self.assertEqual(source["proof_eligible"], expected)
                self.assertEqual(not blockers, expected)
                self.assertEqual(source["ref"], ref)

    def test_clean_detached_local_source_is_recorded_without_blocking_proof(self):
        profile = {"name": "capacity", "proof_eligible": True}
        with (
            mock.patch.dict(harness.os.environ, {}, clear=True),
            mock.patch.object(
                harness,
                "_git_output",
                side_effect=["b" * 40, "HEAD", ""],
            ),
        ):
            source = harness.capture_source_context()
        self.assertEqual(source["kind"], "local")
        self.assertEqual(source["commit_sha"], "b" * 40)
        self.assertEqual(source["ref"], "HEAD")
        self.assertFalse(source["working_tree_dirty"])
        self.assertEqual(source["working_tree_status_entries"], 0)
        self.assertTrue(source["proof_eligible"])
        self.assertEqual(harness.proof_context_blockers(profile, source), [])

    def test_local_dirty_unknown_or_unidentified_source_blocks_proof(self):
        profile = {"name": "capacity", "proof_eligible": True}
        cases = (
            (
                {
                    "kind": "local",
                    "ref": "main",
                    "commit_sha": "a" * 40,
                    "working_tree_dirty": True,
                },
                "known-clean",
            ),
            (
                {
                    "kind": "local",
                    "ref": "main",
                    "commit_sha": "a" * 40,
                    "working_tree_dirty": None,
                },
                "known-clean",
            ),
            (
                {
                    "kind": "local",
                    "ref": "main",
                    "commit_sha": "not-a-sha",
                    "working_tree_dirty": False,
                },
                "40-hex",
            ),
            (
                {
                    "kind": "local",
                    "ref": "main",
                    "commit_sha": None,
                    "working_tree_dirty": False,
                },
                "40-hex",
            ),
        )
        for source, expected_message in cases:
            with self.subTest(source=source):
                blockers = harness.proof_context_blockers(profile, source)
                self.assertTrue(blockers)
                self.assertIn(expected_message, " ".join(blockers))
                slo_report = {
                    "assessment": "passed",
                    "proof_ready": True,
                    "proof_blockers": [],
                    "message": "Every explicitly configured threshold passed.",
                }
                harness.add_proof_blockers(slo_report, blockers)
                self.assertEqual(slo_report["assessment"], "not_configured")
                self.assertFalse(slo_report["proof_ready"])


class WorkflowPolicyWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (
            REPO_ROOT / ".github" / "workflows" / "performance.yml"
        ).read_text(encoding="utf-8")
        cls.actionlint_config = (
            REPO_ROOT / ".github" / "actionlint.yaml"
        ).read_text(encoding="utf-8")

    def test_actionlint_declares_only_the_custom_capacity_runner_labels(self):
        self.assertEqual(
            self.actionlint_config,
            "self-hosted-runner:\n"
            "  labels:\n"
            "    - chancela-capacity\n"
            "    - cpu-12-plus\n",
        )

    def test_harness_self_test_installs_pcsc_before_running_the_python_suite(self):
        harness_job = self.workflow.split("  harness-self-test:", 1)[1].split(
            "\n  exact-volume-run:",
            1,
        )[0]
        self.assertIn(
            "      - name: Install PC/SC system deps (Linux)\n"
            "        run: sudo apt-get update && "
            "sudo apt-get install -y libpcsclite-dev pcscd\n"
            "      - name: Compile and unit-test the harness",
            harness_job,
        )

    def test_workflow_uses_only_the_committed_policy_for_proof_eligible_profiles(self):
        dispatch = self.workflow.split("  workflow_dispatch:", 1)[1].split(
            "\npermissions:",
            1,
        )[0]
        self.assertNotIn("slo_path:", dispatch)

        exact_job = self.workflow.split("  exact-volume-run:", 1)[1]
        environment = exact_job.split("    env:", 1)[1].split("    steps:", 1)[0]
        self.assertIn(
            "PERF_PROFILE: ${{ github.event_name == 'schedule' && 'capacity' || inputs.profile }}",
            environment,
        )
        self.assertIn(
            "(github.event_name == 'schedule' || inputs.profile != 'pr-smoke')",
            environment,
        )
        self.assertIn("'scripts/perf/slo.capacity.json'", environment)
        self.assertIn("|| '' }}", environment)
        self.assertNotIn("inputs.slo_path", environment)

    def test_exact_runs_require_the_explicit_capacity_runner_labels(self):
        exact_job = self.workflow.split("  exact-volume-run:", 1)[1]
        runs_on = exact_job.split("    runs-on:", 1)[1].split(
            "    timeout-minutes:",
            1,
        )[0]
        self.assertEqual(
            [
                line.removeprefix("      - ")
                for line in runs_on.splitlines()
                if line.startswith("      - ")
            ],
            ["self-hosted", "linux", "x64", "chancela-capacity", "cpu-12-plus"],
        )
        self.assertNotIn("ubuntu-latest", runs_on)


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
            self.assertTrue(failure["profile_proof_eligible"])
            self.assertIn(failure["source"]["kind"], {"local", "github_actions"})
            self.assertIn("ref", failure["source"])
            self.assertIn("commit_sha", failure["source"])
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
                "search-projector-postgres": [{"id": "projector-1"}],
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
    def test_committed_capacity_policy_is_complete_before_measurement(self):
        profile = json.loads(
            (PERF_ROOT / "profiles" / "capacity.json").read_text(encoding="utf-8")
        )
        policy = json.loads(
            (PERF_ROOT / "slo.capacity.json").read_text(encoding="utf-8")
        )
        harness.validate_profile(profile)
        harness.validate_slo_schema(policy)
        self.assertEqual(policy, EXPECTED_CAPACITY_POLICY)

        self.assertTrue(
            all(value is not None for value in policy["global"].values())
        )
        self.assertTrue(
            all(value is not None for value in policy["resources"].values())
        )
        measured_operations = {
            operation
            for operation, weight in profile["workload"]["weights"].items()
            if weight > 0
        }
        self.assertEqual(set(policy["operations"]), measured_operations)
        for thresholds in policy["operations"].values():
            self.assertEqual(set(thresholds), harness.SLO_OPERATION_FIELDS)
            self.assertTrue(all(value is not None for value in thresholds.values()))
        self.assertEqual(
            set(policy["cryptographic_signing"]),
            harness.CRYPTO_SLO_FIELDS,
        )
        self.assertTrue(
            all(
                value is not None
                for value in policy["cryptographic_signing"].values()
            )
        )

    def test_committed_capacity_profile_freezes_setup_and_proof_contract(self):
        profile = json.loads(
            (PERF_ROOT / "profiles" / "capacity.json").read_text(encoding="utf-8")
        )
        harness.validate_profile(profile)
        self.assertTrue(profile["proof_eligible"])
        self.assertEqual(
            profile["dataset"],
            {
                "users": 15_000,
                "entities": 10_000,
                "books": 50_000,
                "signatures": 10_000,
            },
        )
        self.assertEqual(profile["seed_concurrency"], 12)
        self.assertEqual(profile["workload"]["clients"], 64)
        self.assertEqual(profile["workload"]["duration_seconds"], 1_800)
        self.assertEqual(profile["workload"]["peak_plateau_seconds"], 1_080)

        budget = harness.duration_budget_report(
            profile,
            workflow_timeout_seconds=21_600,
            search_readiness_timeout_seconds=900,
            cryptographic_config={"count": 10_000},
        )
        self.assertTrue(budget["budget_passed"])
        self.assertEqual(budget["required_seconds"], 17_100)
        self.assertEqual(budget["workflow_timeout_seconds"], 21_600)
        self.assertEqual(budget["remaining_seconds"], 4_500)

    def test_committed_capacity_policy_boundaries_are_inclusive_and_breaches_fail(self):
        policy = copy.deepcopy(EXPECTED_CAPACITY_POLICY)
        workload = {
            "error_rate": policy["global"]["max_error_rate"],
            "throughput_per_second": policy["global"][
                "min_throughput_per_second"
            ],
            "operations": {
                operation: {
                    "p95_ms": thresholds["p95_ms"],
                    "p99_ms": thresholds["p99_ms"],
                    "error_rate": thresholds["max_error_rate"],
                }
                for operation, thresholds in policy["operations"].items()
            },
            "phases": {"model": "explicit", "peak_plateau_complete": True},
        }
        resource_container = {
            "max_memory_bytes": policy["resources"][
                "max_container_memory_bytes"
            ],
            "max_cpu_percent": policy["resources"]["max_container_cpu_percent"],
        }
        resources = {
            "available": True,
            "containers": {"app": resource_container},
            "phases": {
                phase: {"containers": {"app": resource_container}}
                for phase in ("seed", "search_catch_up", "mixed_workload")
            },
        }

        boundary = harness.evaluate_slo(workload, resources, policy)
        self.assertEqual(boundary["assessment"], "passed")
        self.assertTrue(boundary["proof_ready"])

        throughput_breach = copy.deepcopy(workload)
        throughput_breach["throughput_per_second"] -= 0.001
        error_breach = copy.deepcopy(workload)
        error_breach["error_rate"] += 0.000001
        latency_breach = copy.deepcopy(workload)
        latency_breach["operations"]["health"]["p99_ms"] += 0.001
        cpu_breach = copy.deepcopy(resources)
        cpu_breach["containers"]["app"]["max_cpu_percent"] += 0.001
        for name, candidate_workload, candidate_resources in (
            ("throughput", throughput_breach, resources),
            ("error rate", error_breach, resources),
            ("operation latency", latency_breach, resources),
            ("container CPU", workload, cpu_breach),
        ):
            with self.subTest(boundary=name):
                result = harness.evaluate_slo(
                    candidate_workload,
                    candidate_resources,
                    policy,
                )
                self.assertEqual(result["assessment"], "failed")
                self.assertFalse(result["proof_ready"])

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
            "operations": {
                "entity_list": {
                    "p95_ms": 25,
                    "p99_ms": 35,
                    "max_error_rate": 0.01,
                }
            },
            "resources": {
                "max_container_memory_bytes": 2000,
                "max_container_cpu_percent": 50,
            },
        }
        result = harness.evaluate_slo(workload, resources, passing)
        self.assertEqual(result["assessment"], "passed")
        self.assertTrue(result["proof_ready"])
        failing = {"schema_version": 1, "global": {"max_error_rate": 0.001}}
        result = harness.evaluate_slo(workload, resources, failing)
        self.assertEqual(result["assessment"], "failed")
        self.assertFalse(result["proof_ready"])

    def test_partial_capacity_policy_is_explicitly_non_proof(self):
        workload = {
            "error_rate": 0.0,
            "throughput_per_second": 50,
            "operations": {
                "entity_list": {
                    "p95_ms": 20,
                    "p99_ms": 30,
                    "error_rate": 0,
                }
            },
            "phases": {"model": "explicit", "peak_plateau_complete": True},
        }
        resources = {
            "available": True,
            "containers": {
                "app": {"max_memory_bytes": 1000, "max_cpu_percent": 20}
            },
            "phases": {
                phase: {
                    "containers": {
                        "app": {"max_memory_bytes": 1000, "max_cpu_percent": 20}
                    }
                }
                for phase in ("seed", "search_catch_up", "mixed_workload")
            },
        }
        partial = {
            "schema_version": 1,
            "global": {
                "max_error_rate": 0.01,
                "min_throughput_per_second": 40,
            },
            "operations": {"entity_list": {"p95_ms": 25}},
            "resources": {"max_container_memory_bytes": 2000},
        }
        result = harness.evaluate_slo(workload, resources, partial)
        self.assertEqual(result["assessment"], "not_configured")
        self.assertFalse(result["proof_ready"])
        blockers = " ".join(result["proof_blockers"])
        self.assertIn("operations.entity_list.p99_ms", blockers)
        self.assertIn("operations.entity_list.max_error_rate", blockers)
        self.assertIn("resources.max_container_cpu_percent", blockers)

    def test_requested_crypto_without_complete_reviewed_thresholds_is_not_configured(self):
        workload = {
            "error_rate": 0.0,
            "throughput_per_second": 50,
            "operations": {
                "entity_list": {
                    "p95_ms": 10,
                    "p99_ms": 15,
                    "error_rate": 0,
                }
            },
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
            "global": {
                "max_error_rate": 0.01,
                "min_throughput_per_second": 40,
            },
            "operations": {
                "entity_list": {
                    "p95_ms": 20,
                    "p99_ms": 25,
                    "max_error_rate": 0.01,
                }
            },
            "resources": {
                "max_container_memory_bytes": 2000,
                "max_container_cpu_percent": 30,
            },
            "cryptographic_signing": {"min_completed": 10000},
        }
        result = harness.evaluate_slo(workload, resources, incomplete, crypto)
        self.assertEqual(result["assessment"], "not_configured")
        self.assertIn("p99_ms", " ".join(result["proof_blockers"]))

        complete = {
            **incomplete,
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
                "search-projector-postgres": [{"id": "projector-1"}],
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


class LocalCryptographicIsolationTests(unittest.TestCase):
    @staticmethod
    def settings_document() -> dict:
        return {
            "schema_version": 1,
            "organization": {"name": "Preserve this organization"},
            "signing": {
                "preferred_family": "CartaoCidadao",
                "tsa_url": "https://tsa.example.test",
                "tsa_providers": [
                    {
                        "id": "tsa",
                        "name": "Configured TSA",
                        "enabled": True,
                        "default": True,
                    }
                ],
                "providers": [{"id": "runtime-before"}],
                "require_qualified_for_seal": False,
            },
            "connectors": {
                "allowed_hosts": ["api.example.test"],
                "environment_ceiling": ["api.example.test"],
            },
            "documents": {
                "locale": "pt-PT",
                "numbering_scheme_default": "Sequential",
            },
            "appearance": {
                "theme": "dark",
                "leather_texture": False,
                "texture_intensity": 42,
                "button_texture": False,
            },
            "ui": {
                "external_signature_notice_snooze_days": 90,
                "phone_pairing_share_email_enabled": True,
                "phone_pairing_share_whatsapp_enabled": False,
            },
        }

    def test_tsa_override_retries_read_preserves_settings_and_returns_sanitized_evidence(
        self,
    ):
        before = self.settings_document()
        captured_put = []
        get_results = [
            harness.HttpResult(401, 1.0, b'{"error":"session pending"}'),
            harness.HttpResult(200, 1.0, json.dumps(before).encode()),
        ]

        def request(method, path, body=None, *, authenticated=True):
            self.assertTrue(authenticated)
            if method == "GET":
                self.assertEqual(path, "/v1/settings")
                return get_results.pop(0)
            self.assertEqual((method, path), ("PUT", "/v1/settings"))
            captured_put.append(copy.deepcopy(body))
            committed = copy.deepcopy(body)
            committed["signing"]["providers"] = [{"id": "runtime-after"}]
            committed["connectors"]["environment_ceiling"] = None
            return harness.HttpResult(200, 1.0, json.dumps(committed).encode())

        client = mock.Mock()
        client.request.side_effect = request
        with mock.patch.object(harness.time, "sleep") as sleep:
            evidence = harness.disable_external_timestamping_for_local_signing(
                client
            )

        self.assertEqual(evidence["get_statuses"], [401, 200])
        self.assertEqual(evidence["put_status"], 200)
        self.assertTrue(evidence["tsa_disabled"])
        self.assertTrue(evidence["non_tsa_settings_preserved"])
        self.assertEqual(evidence["before_tsa_provider_count"], 1)
        self.assertEqual(evidence["effective_tsa_provider_count"], 0)
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(len(captured_put), 1)
        expected = copy.deepcopy(before)
        expected["signing"]["tsa_url"] = None
        expected["signing"]["tsa_providers"] = []
        self.assertEqual(captured_put[0], expected)
        self.assertEqual(before["signing"]["tsa_url"], "https://tsa.example.test")
        self.assertNotIn("tsa.example.test", json.dumps(evidence))
        self.assertNotIn("Configured TSA", json.dumps(evidence))

    def test_tsa_override_is_bounded_and_fails_closed(self):
        client = mock.Mock()
        client.request.return_value = harness.HttpResult(
            401, 1.0, b'{"error":"session pending"}'
        )
        with (
            mock.patch.object(harness.time, "sleep") as sleep,
            self.assertRaisesRegex(harness.HarnessError, "statuses=\\[401, 401, 401\\]"),
        ):
            harness.disable_external_timestamping_for_local_signing(
                client,
                attempts=3,
            )
        self.assertEqual(client.request.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

        invalid_documents = (
            ({}, "no signing object"),
            (
                {"signing": {"tsa_url": None, "tsa_providers": {}}},
                "tsa_providers is not an array",
            ),
        )
        for document, message in invalid_documents:
            with self.subTest(message=message):
                malformed = mock.Mock()
                malformed.request.return_value = harness.HttpResult(
                    200, 1.0, json.dumps(document).encode()
                )
                with self.assertRaisesRegex(harness.HarnessError, message):
                    harness.disable_external_timestamping_for_local_signing(
                        malformed
                    )
                self.assertEqual(malformed.request.call_count, 1)

        before = self.settings_document()
        rejected = mock.Mock()
        rejected.request.side_effect = [
            harness.HttpResult(200, 1.0, json.dumps(before).encode()),
            harness.HttpResult(
                422,
                1.0,
                b'{"error":"refused https://sensitive.example.test/tsa"}',
            ),
        ]
        with self.assertRaisesRegex(
            harness.HarnessError,
            "could not disable TSA",
        ) as rejected_error:
            harness.disable_external_timestamping_for_local_signing(rejected)
        self.assertNotIn("sensitive.example.test", str(rejected_error.exception))

        ineffective = mock.Mock()
        ineffective.request.side_effect = [
            harness.HttpResult(200, 1.0, json.dumps(before).encode()),
            harness.HttpResult(200, 1.0, json.dumps(before).encode()),
        ]
        with self.assertRaisesRegex(
            harness.HarnessError,
            "did not disable both TSA selectors",
        ):
            harness.disable_external_timestamping_for_local_signing(ineffective)

        malformed = mock.Mock()
        malformed.request.return_value = harness.HttpResult(
            200,
            1.0,
            b'not-json https://sensitive.example.test/tsa',
        )
        with self.assertRaisesRegex(
            harness.HarnessError,
            "response is not valid JSON",
        ) as malformed_error:
            harness.disable_external_timestamping_for_local_signing(malformed)
        self.assertNotIn("sensitive.example.test", str(malformed_error.exception))

    def test_valid_opt_in_crypto_disables_tsa_before_any_act_mutation(self):
        with tempfile.TemporaryDirectory() as raw:
            pfx = pathlib.Path(raw) / "identity.p12"
            pfx.write_bytes(b"disposable-pfx")
            config = {
                "provider": "local-pkcs12",
                "count": 1,
                "concurrency": 1,
                "pkcs12_path": str(pfx),
                "passphrase_env": "CHANCELA_TEST_PFX_PASSPHRASE",
                "friendly_name": "Disposable test identity",
            }
            timestamping = {
                "tsa_disabled": True,
                "non_tsa_settings_preserved": True,
            }
            events = []
            client = mock.Mock()

            def request(method, path, body=None, *, authenticated=True):
                events.append((method, path))
                return harness.HttpResult(200, 1.0, b'{"ok":true}')

            client.request.side_effect = request

            def disable(_client):
                events.append(("TSA", "disabled"))
                return timestamping

            with (
                mock.patch.dict(
                    harness.os.environ,
                    {"CHANCELA_TEST_PFX_PASSPHRASE": "not-recorded"},
                    clear=False,
                ),
                mock.patch.object(
                    harness,
                    "disable_external_timestamping_for_local_signing",
                    side_effect=disable,
                ) as disable_mock,
            ):
                report = harness.run_cryptographic_signing(
                    client,
                    ["act-1"],
                    config,
                )

            disable_mock.assert_called_once_with(client)
            self.assertEqual(events[0], ("TSA", "disabled"))
            self.assertEqual(report["timestamping"], timestamping)
            self.assertTrue(report["exact"])
            self.assertEqual(report["signed"], 1)
            self.assertNotIn("not-recorded", json.dumps(report))

    def test_invalid_crypto_config_does_not_mutate_settings(self):
        with mock.patch.object(
            harness,
            "disable_external_timestamping_for_local_signing",
        ) as disable:
            with self.assertRaisesRegex(harness.HarnessError, "positive integer"):
                harness.run_cryptographic_signing(
                    mock.Mock(),
                    ["act-1"],
                    {
                        "provider": "local-pkcs12",
                        "count": 0,
                    },
                )
        disable.assert_not_called()


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
            with self.server.state_lock:
                document_count = len(self.server.search_documents)
            self.reply(
                200,
                {
                    "details_redacted": False,
                    "enabled": True,
                    "partial": False,
                    "stale": False,
                    "phase": "idle",
                    "generation": 2,
                    "document_count": document_count,
                    "indexed_content_chars": 1000,
                    "content_truncated": False,
                    "truncated_document_count": 0,
                },
            )
        elif self.path.startswith("/v1/search?"):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            search_text = query.get("q", [""])[0].casefold()
            kinds = set(query.get("kind", ["entity"])[0].split(","))
            cursor = query.get("cursor", [None])[0]
            limit = int(query.get("limit", ["10"])[0])
            offset = int(cursor.rsplit("-", 1)[-1]) if cursor else 0
            with self.server.state_lock:
                matching = [
                    dict(document)
                    for document in self.server.search_documents
                    if document["kind"] in kinds
                    and search_text in document["search_text"]
                ]
            page_documents = matching[offset : offset + limit]
            has_more = offset + limit < len(matching)
            next_cursor = f"test-cursor-{offset + limit}" if has_more else None
            self.reply(
                200,
                {
                    "page": {
                        "total": len(matching),
                        "offset": offset,
                        "limit": limit,
                        "has_more": has_more,
                        "facets_truncated": False,
                        "hits": [
                            {
                                document["relation_key"]: document["identifier"],
                                "kind": document["kind"],
                            }
                            for document in page_documents
                        ],
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
        with self.server.state_lock:
            self.server.counters[kind] += 1
            identifier = f"{kind}-{self.server.counters[kind]}"
            searchable_fields = {
                "entities": ("entity", "entity_id", ("name",)),
                "books": ("book", "book_id", ("purpose",)),
                "acts": ("act", "act_id", ("title",)),
            }
            if kind in searchable_fields:
                search_kind, relation_key, fields = searchable_fields[kind]
                search_text = " ".join(
                    [identifier, *(str(payload.get(field, "")) for field in fields)]
                ).casefold()
                self.server.search_documents.append(
                    {
                        "kind": search_kind,
                        "relation_key": relation_key,
                        "identifier": identifier,
                        "search_text": search_text,
                    }
                )
        self.reply(201, {"id": identifier})

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
            server.counters = {"users": 0, "entities": 0, "books": 0, "acts": 0}
            server.search_documents = []
            server.state_lock = threading.Lock()
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
