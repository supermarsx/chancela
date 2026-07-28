import copy
import json
import multiprocessing
import pathlib
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock


PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PERF_ROOT))

import loadgen  # noqa: E402


PROFILE_PATH = PERF_ROOT / "profiles" / "throughput-10k.json"
SLO_PATH = PERF_ROOT / "slo.throughput.json"


def read_profile():
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def read_slo():
    return json.loads(SLO_PATH.read_text(encoding="utf-8"))


def complete_figure(**overrides):
    """A figure with every required field present, for negative-space testing."""

    figure = {
        "stage": "raised-quota",
        "step": "raised-10000",
        "proof_eligible": False,
        "container_cpu_quota_per_app_node": 5.0,
        "container_cpu_quota_app_replicas": 3,
        "container_cpu_quota_app_total": 15.0,
        "container_cpu_quota_source": "observed",
        "generator_worker_processes": 16,
        "generator_cpu_allocation": 24,
        "generator_cpu_utilization_of_allocation": 0.4,
        "generator_cpu_pinning": {"workers": 16, "pinned_workers": 16, "applied": True},
        "docker_vm_logical_cpus": 26,
        "host_logical_cpus": 80,
        "transport_path": "direct-container-network",
        "transport_disclosure": loadgen.DIRECT_DISCLOSURE,
        "offered_rate_per_second": 10000.0,
        "issued_rate_per_second": 10000.0,
        "achieved_rate_per_second": 10000.0,
        "error_rate": 0.0,
        "corrected_p99_ms": 120.0,
        "service_p99_ms": 90.0,
        "longest_sustained_seconds_at_target": 60,
        "target_rate_per_second": 10000.0,
        "bottleneck": loadgen.OUTCOME_TARGET_MET,
        "server_capacity_interpretable": True,
        "connection_reuse_ratio": 0.999,
        "time_wait_peak": 90,
    }
    figure.update(overrides)
    return figure


class ProfileValidationTests(unittest.TestCase):
    def test_committed_profile_is_valid_and_never_proof_eligible(self):
        profile = read_profile()
        loadgen.validate_profile(profile)
        self.assertFalse(profile["proof_eligible"])

    def test_a_proof_eligible_throughput_profile_is_rejected(self):
        profile = read_profile()
        profile["proof_eligible"] = True
        with self.assertRaisesRegex(loadgen.LoadGenError, "proof_eligible: false"):
            loadgen.validate_profile(profile)

    def test_unknown_endpoints_are_rejected(self):
        profile = read_profile()
        profile["stages"][0]["weights"]["auth_login"] = 5
        with self.assertRaisesRegex(loadgen.LoadGenError, "unknown endpoints"):
            loadgen.validate_profile(profile)

    def test_a_step_shorter_than_its_warmup_is_rejected(self):
        profile = read_profile()
        profile["stages"][0]["steps"][0]["warmup_seconds"] = 999
        with self.assertRaisesRegex(loadgen.LoadGenError, "must exceed warmup_seconds"):
            loadgen.validate_profile(profile)

    def test_duplicate_stage_names_are_rejected(self):
        profile = read_profile()
        profile["stages"].append(copy.deepcopy(profile["stages"][0]))
        with self.assertRaisesRegex(loadgen.LoadGenError, "duplicate stage"):
            loadgen.validate_profile(profile)

    def test_unknown_threshold_fields_are_rejected(self):
        profile = read_profile()
        profile["thresholds"]["be_generous"] = 1.0
        with self.assertRaisesRegex(loadgen.LoadGenError, "unknown fields"):
            loadgen.validate_profile(profile)


class CommittedProfileShapeTests(unittest.TestCase):
    """The profile encodes the D2 decision; these assertions keep it encoded."""

    def setUp(self):
        self.profile = read_profile()
        self.stages = {stage["name"]: stage for stage in self.profile["stages"]}

    def test_a_governed_two_cpu_baseline_stage_exists_for_comparison(self):
        baseline = self.stages["governed-baseline"]
        self.assertEqual(baseline["app_cpus"], 2.0)
        self.assertEqual(baseline["search_projector_cpus"], 1.5)

    def test_the_raised_stage_actually_raises_the_quota(self):
        raised = self.stages["raised-quota"]
        self.assertGreater(raised["app_cpus"], self.stages["governed-baseline"]["app_cpus"])
        self.assertEqual(raised["app_cpus"] * raised["app_replicas"], 15.0)

    def test_baseline_and_raised_stages_share_one_endpoint_mix(self):
        """A comparator is only a comparator if it measures the same thing."""

        self.assertEqual(
            self.stages["governed-baseline"]["weights"],
            self.stages["raised-quota"]["weights"],
        )

    def test_container_budget_fits_inside_the_measured_docker_vm(self):
        """The Docker Desktop VM has 26 CPUs, not the host's 80."""

        docker_vm_cpus = 26
        gateway_cpus = 1.0
        raised = self.stages["raised-quota"]
        allocated = (
            raised["app_cpus"] * raised["app_replicas"]
            + raised["search_projector_cpus"]
            + gateway_cpus
        )
        self.assertLess(allocated, docker_vm_cpus)
        self.assertGreaterEqual(docker_vm_cpus - allocated, 5.0)

    def test_generator_and_containers_do_not_oversubscribe_the_host(self):
        generator = self.profile["generator"]
        docker_vm_cpus = 26
        host_cpus = 80
        self.assertLess(generator["cpu_allocation"] + docker_vm_cpus, host_cpus)

    def test_the_ladder_reaches_ten_thousand_with_a_sixty_second_measured_window(self):
        raised = self.stages["raised-quota"]
        at_target = [
            step
            for step in raised["steps"]
            if step["target_rate_per_second"] >= loadgen.B3_TARGET_RATE_PER_SECOND
        ]
        self.assertTrue(at_target)
        for step in at_target:
            measured = step["duration_seconds"] - step["warmup_seconds"]
            self.assertGreaterEqual(measured, loadgen.B3_MIN_SUSTAINED_SECONDS)

    def test_persistent_connections_replace_per_request_connections(self):
        """1024 held sockets, not 10 000 new ones per second — this is the fix."""

        generator = self.profile["generator"]
        pooled = generator["worker_processes"] * generator["connections_per_worker"]
        self.assertGreaterEqual(pooled, 512)
        # The measured Windows ephemeral range is 16 384 ports.
        self.assertLess(pooled, 16_384)

    def test_the_client_ceiling_stage_needs_no_seeded_identifiers(self):
        ceiling = self.stages["client-ceiling"]
        for name, weight in ceiling["weights"].items():
            if weight:
                self.assertIsNone(loadgen.ENDPOINTS[name]["identifiers"])


class SloTests(unittest.TestCase):
    def test_committed_slo_matches_the_fixed_pass_criteria(self):
        loadgen.validate_slo(read_slo())

    def test_every_criterion_refuses_to_be_softened(self):
        softened = {
            "target_rate_per_second": 5_000.0,
            "min_sustained_seconds": 10.0,
            "max_error_rate": 0.05,
            "max_p99_ms": 5_000.0,
        }
        for field, value in softened.items():
            slo = read_slo()
            slo["pass_criteria"][field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(loadgen.LoadGenError, "not softened"):
                    loadgen.validate_slo(slo)

    def test_unknown_criteria_are_rejected(self):
        slo = read_slo()
        slo["pass_criteria"]["allow_peak_instead_of_sustained"] = True
        with self.assertRaisesRegex(loadgen.LoadGenError, "unknown fields"):
            loadgen.validate_slo(slo)

    def test_the_constants_are_the_plan_values(self):
        self.assertEqual(loadgen.B3_TARGET_RATE_PER_SECOND, 10_000.0)
        self.assertEqual(loadgen.B3_MIN_SUSTAINED_SECONDS, 60.0)
        self.assertEqual(loadgen.B3_MAX_ERROR_RATE, 0.005)
        self.assertEqual(loadgen.B3_MAX_P99_MS, 1_000.0)


class ScheduleTests(unittest.TestCase):
    def test_the_schedule_is_computed_before_the_run_at_the_requested_rate(self):
        offsets = loadgen.intended_offsets(1_000.0, 10.0, 0, 1)
        self.assertAlmostEqual(len(offsets) / 10.0, 1_000.0, delta=1.0)
        self.assertAlmostEqual(offsets[1] - offsets[0], 0.001, places=9)

    def test_workers_interleave_into_one_evenly_spaced_arrival_process(self):
        workers = 4
        combined = sorted(
            offset
            for index in range(workers)
            for offset in loadgen.intended_offsets(400.0, 1.0, index, workers)
        )
        gaps = [b - a for a, b in zip(combined, combined[1:])]
        for gap in gaps:
            self.assertAlmostEqual(gap, 1 / 400.0, places=9)

    def test_a_worker_index_outside_the_pool_is_rejected(self):
        with self.assertRaises(loadgen.LoadGenError):
            loadgen.intended_offsets(100.0, 1.0, 4, 4)


class SustainedWindowTests(unittest.TestCase):
    def test_sustained_means_continuous_not_average(self):
        counts = {0: 10_000, 1: 10_000, 2: 1, 3: 10_000, 4: 10_000}
        self.assertEqual(loadgen.longest_sustained_seconds(counts, 10_000), 2)

    def test_a_missing_second_breaks_the_run(self):
        counts = {0: 10_000, 2: 10_000}
        self.assertEqual(loadgen.longest_sustained_seconds(counts, 10_000), 1)

    def test_a_full_minute_at_target_is_sixty(self):
        counts = {second: 10_000 for second in range(60)}
        self.assertEqual(loadgen.longest_sustained_seconds(counts, 10_000), 60)


class HistogramTests(unittest.TestCase):
    def test_buckets_are_monotonic_and_cover_the_range(self):
        previous = -1.0
        for index in range(loadgen.HISTOGRAM_OVERFLOW_INDEX):
            bound = loadgen.histogram_upper_bound(index)
            self.assertGreater(bound, previous)
            previous = bound

    def test_a_value_lands_in_a_bucket_whose_upper_bound_is_at_least_the_value(self):
        for value in (0.0, 0.05, 1.5, 99.99, 100.0, 999.0, 1_000.0, 9_999.0, 50_000.0):
            index = loadgen.histogram_index(value)
            with self.subTest(value=value):
                self.assertGreaterEqual(loadgen.histogram_upper_bound(index), value)

    def test_percentiles_never_understate_latency(self):
        histogram = loadgen.new_histogram()
        for value in [10.0] * 99 + [900.0]:
            histogram[loadgen.histogram_index(value)] += 1
        self.assertGreaterEqual(loadgen.histogram_percentile(histogram, 0.99), 10.0)
        self.assertGreaterEqual(loadgen.histogram_percentile(histogram, 1.0), 900.0)

    def test_histograms_merge_exactly_across_processes(self):
        first = loadgen.new_histogram()
        second = loadgen.new_histogram()
        first[loadgen.histogram_index(5.0)] += 3
        second[loadgen.histogram_index(5.0)] += 7
        second[loadgen.histogram_index(50.0)] += 1
        merged = loadgen.merge_histograms([first, second])
        self.assertEqual(sum(merged), 11)
        self.assertEqual(merged[loadgen.histogram_index(5.0)], 10)

    def test_an_empty_histogram_reports_no_percentile_rather_than_zero(self):
        self.assertIsNone(loadgen.histogram_percentile(loadgen.new_histogram(), 0.99))


class BottleneckClassificationTests(unittest.TestCase):
    """R9: a CPU-starved client looks exactly like a server ceiling."""

    def base_metrics(self, **overrides):
        metrics = {
            "generator_cpu_utilization_of_allocation": 0.30,
            "dispatch_deficit_fraction": 0.0,
            "dispatch_blocked_fraction": 0.0,
            "dispatch_lag_p99_ms": 2.0,
            "connection_reuse_ratio": 0.999,
            "time_wait_fraction_of_ephemeral_range": 0.01,
            "error_rate": 0.0,
            "corrected_p99_ms": 100.0,
            "offered_rate_per_second": 10_000.0,
            "achieved_rate_per_second": 10_000.0,
            "longest_sustained_seconds_at_target": 60,
            "target_rate_per_second": 10_000.0,
        }
        metrics.update(overrides)
        return metrics

    def test_a_clean_run_at_target_is_named_as_such(self):
        result = loadgen.classify_bottleneck(self.base_metrics())
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_TARGET_MET)
        self.assertTrue(result["server_capacity_interpretable"])
        self.assertIsNone(result["server_capacity_blocker"])

    def test_generator_cpu_saturation_is_a_named_outcome(self):
        result = loadgen.classify_bottleneck(
            self.base_metrics(generator_cpu_utilization_of_allocation=0.92)
        )
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_CLIENT_CPU)
        self.assertTrue(result["client_saturated"])

    def test_client_saturation_wins_over_a_server_symptom(self):
        """The whole point: a starved client must never be reported as a server result."""

        result = loadgen.classify_bottleneck(
            self.base_metrics(
                generator_cpu_utilization_of_allocation=0.95,
                error_rate=0.30,
                corrected_p99_ms=9_000.0,
                achieved_rate_per_second=2_000.0,
            )
        )
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_CLIENT_CPU)
        self.assertFalse(result["server_capacity_interpretable"])
        self.assertIn("not", result["server_capacity_blocker"])

    def test_undispatched_sends_are_a_client_outcome(self):
        result = loadgen.classify_bottleneck(self.base_metrics(dispatch_deficit_fraction=0.20))
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_CLIENT_DISPATCH_LAG)
        self.assertFalse(result["server_capacity_interpretable"])

    def test_dispatch_lag_means_the_offered_rate_was_not_offered(self):
        result = loadgen.classify_bottleneck(self.base_metrics(dispatch_lag_p99_ms=500.0))
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_CLIENT_DISPATCH_LAG)

    def test_pool_starvation_is_a_client_outcome(self):
        result = loadgen.classify_bottleneck(self.base_metrics(dispatch_blocked_fraction=0.10))
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_CLIENT_CONNECTION_STARVED)

    def test_lost_connection_reuse_is_reported_as_port_pressure(self):
        result = loadgen.classify_bottleneck(self.base_metrics(connection_reuse_ratio=0.10))
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_CLIENT_PORT_PRESSURE)

    def test_time_wait_depth_is_reported_as_port_pressure(self):
        result = loadgen.classify_bottleneck(
            self.base_metrics(time_wait_fraction_of_ephemeral_range=0.80)
        )
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_CLIENT_PORT_PRESSURE)

    def test_server_errors_are_only_reached_once_the_client_is_exonerated(self):
        result = loadgen.classify_bottleneck(self.base_metrics(error_rate=0.20))
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_SERVER_ERRORS)
        self.assertTrue(result["server_capacity_interpretable"])

    def test_server_latency_is_named_separately_from_errors(self):
        result = loadgen.classify_bottleneck(self.base_metrics(corrected_p99_ms=4_000.0))
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_SERVER_LATENCY)

    def test_a_shortfall_with_no_named_cause_is_indeterminate_not_a_server_result(self):
        result = loadgen.classify_bottleneck(
            self.base_metrics(achieved_rate_per_second=4_000.0, longest_sustained_seconds_at_target=0)
        )
        self.assertEqual(result["bottleneck"], loadgen.OUTCOME_INDETERMINATE)

    def test_every_outcome_is_from_the_closed_set(self):
        for metrics in (
            self.base_metrics(),
            self.base_metrics(generator_cpu_utilization_of_allocation=0.99),
            self.base_metrics(error_rate=0.9),
            self.base_metrics(achieved_rate_per_second=1.0),
        ):
            self.assertIn(loadgen.classify_bottleneck(metrics)["bottleneck"], loadgen.ALL_OUTCOMES)

    def test_every_client_outcome_carries_a_blocker_sentence(self):
        for outcome in loadgen.CLIENT_BOTTLENECKS:
            self.assertIn(outcome, loadgen.CLIENT_BOTTLENECK_BLOCKER)


class PassCriteriaTests(unittest.TestCase):
    def test_a_clean_run_at_target_passes(self):
        result = loadgen.evaluate_pass_criteria(complete_figure())
        self.assertEqual(result["assessment"], "passed")
        self.assertEqual(result["shortfall_reasons"], [])

    def test_a_client_limited_run_can_never_pass(self):
        figure = complete_figure(
            server_capacity_interpretable=False,
            bottleneck=loadgen.OUTCOME_CLIENT_CPU,
        )
        result = loadgen.evaluate_pass_criteria(figure)
        self.assertEqual(result["assessment"], "shortfall")
        self.assertTrue(
            any("load generator was the limiter" in reason for reason in result["shortfall_reasons"])
        )

    def test_ten_thousand_with_too_many_errors_is_not_ten_thousand(self):
        result = loadgen.evaluate_pass_criteria(complete_figure(error_rate=0.02))
        self.assertEqual(result["assessment"], "shortfall")

    def test_a_peak_without_a_sustained_minute_is_not_a_pass(self):
        result = loadgen.evaluate_pass_criteria(
            complete_figure(longest_sustained_seconds_at_target=12)
        )
        self.assertEqual(result["assessment"], "shortfall")

    def test_a_lower_rate_step_cannot_pass_the_ten_thousand_criterion(self):
        result = loadgen.evaluate_pass_criteria(
            complete_figure(target_rate_per_second=1_000.0, achieved_rate_per_second=1_000.0)
        )
        self.assertEqual(result["assessment"], "shortfall")

    def test_passing_never_makes_a_figure_coverage_eligible(self):
        for figure in (complete_figure(), complete_figure(error_rate=0.9)):
            result = loadgen.evaluate_pass_criteria(figure)
            self.assertFalse(result["coverage_claim_eligible"])
            self.assertIn("flips no", result["coverage_boundary"].replace("It ", "").lower() + " ")


class RequiredFieldTests(unittest.TestCase):
    """D2: quota and generator allocation are required fields, not footnotes."""

    def test_a_complete_figure_renders(self):
        figure = complete_figure()
        figure["pass_criteria"] = loadgen.evaluate_pass_criteria(figure)
        markdown = loadgen.render_figure_markdown(figure)
        self.assertIn("Container CPU quota: 5.0 CPUs per app node", markdown)
        self.assertIn("Generator CPU allocation: 24 logical CPUs", markdown)

    def test_a_figure_without_its_cpu_quota_refuses_to_render(self):
        figure = complete_figure()
        figure["container_cpu_quota_per_app_node"] = None
        with self.assertRaisesRegex(loadgen.LoadGenError, "container_cpu_quota_per_app_node"):
            loadgen.render_figure_markdown(figure)

    def test_a_figure_without_the_generator_allocation_refuses_to_render(self):
        figure = complete_figure()
        figure["generator_cpu_allocation"] = None
        with self.assertRaisesRegex(loadgen.LoadGenError, "generator_cpu_allocation"):
            loadgen.render_figure_markdown(figure)

    def test_the_bottleneck_is_a_required_field(self):
        self.assertIn("bottleneck", loadgen.REQUIRED_FIGURE_FIELDS)
        self.assertIn("server_capacity_interpretable", loadgen.REQUIRED_FIGURE_FIELDS)

    def test_a_client_saturated_figure_shouts_it_in_the_rendered_output(self):
        figure = complete_figure(
            bottleneck=loadgen.OUTCOME_CLIENT_CPU,
            server_capacity_interpretable=False,
            server_capacity_blocker=loadgen.CLIENT_BOTTLENECK_BLOCKER[loadgen.OUTCOME_CLIENT_CPU],
        )
        figure["pass_criteria"] = loadgen.evaluate_pass_criteria(figure)
        markdown = loadgen.render_figure_markdown(figure)
        self.assertIn("CLIENT SATURATED", markdown)
        self.assertIn("NOT A SERVER RESULT", markdown)

    def test_the_loopback_disclosure_is_carried_on_every_report(self):
        report = {
            "generated_at": "2026-07-27T00:00:00Z",
            "transport_disclosure": loadgen.LOOPBACK_DISCLOSURE,
            "figures": [],
        }
        markdown = loadgen.render_report_markdown(report)
        self.assertIn("Docker Desktop port proxy", markdown)
        self.assertIn("load generator and server share the machine", markdown)
        self.assertIn("not a networked benchmark", " ".join(markdown.split()))


class QuotaVerificationTests(unittest.TestCase):
    def stage(self, **overrides):
        stage = {
            "name": "raised-quota",
            "app_cpus": 5.0,
            "app_replicas": 3,
            "search_projector_cpus": 3.0,
        }
        stage.update(overrides)
        return stage

    def test_an_unobservable_quota_is_a_blocker_not_an_assumption(self):
        blockers = loadgen.quota_blockers(self.stage(), {"available": False})
        self.assertEqual(len(blockers), 1)
        self.assertIn("unverified", blockers[0])

    def test_a_quota_mismatch_is_a_blocker(self):
        observed = {
            "available": True,
            "consistent": True,
            "per_container_cpus": 2.0,
            "containers": [{}, {}, {}],
        }
        blockers = loadgen.quota_blockers(self.stage(), observed)
        self.assertTrue(any("Docker is enforcing 2.0" in blocker for blocker in blockers))

    def test_a_matching_quota_with_the_right_replica_count_is_clean(self):
        observed = {
            "available": True,
            "consistent": True,
            "per_container_cpus": 5.0,
            "containers": [{}, {}, {}],
        }
        self.assertEqual(loadgen.quota_blockers(self.stage(), observed), [])

    def test_a_wrong_replica_count_is_a_blocker(self):
        observed = {
            "available": True,
            "consistent": True,
            "per_container_cpus": 5.0,
            "containers": [{}, {}],
        }
        blockers = loadgen.quota_blockers(self.stage(), observed)
        self.assertTrue(any("2 are running" in blocker for blocker in blockers))

    def test_unlimited_containers_are_a_blocker_when_a_quota_is_declared(self):
        observed = {
            "available": True,
            "consistent": True,
            "per_container_cpus": None,
            "containers": [{}, {}, {}],
        }
        blockers = loadgen.quota_blockers(self.stage(), observed)
        self.assertTrue(any("no CPU quota at all" in blocker for blocker in blockers))


class EnvironmentSnapshotReuseTests(unittest.TestCase):
    """The in-container direct path must not lose the observed quota."""

    def setUp(self):
        import tempfile

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = pathlib.Path(self.directory.name) / "environment.json"
        self.stage = loadgen.find_stage(read_profile(), "raised-quota")

    def write(self, **overrides):
        snapshot = {
            "stage": "raised-quota",
            "declared_app_cpus": 5.0,
            "host_logical_cpus": 80,
            "docker_vm_logical_cpus": 26,
            "observed_app_cpu_quota": {
                "available": True,
                "consistent": True,
                "per_container_cpus": 5.0,
                "containers": [{}, {}, {}],
            },
        }
        snapshot.update(overrides)
        self.path.write_text(json.dumps(snapshot), encoding="utf-8")
        return self.path

    def test_a_matching_snapshot_is_reused_with_its_observed_quota(self):
        environment = loadgen.load_environment_snapshot(self.write(), self.stage)
        self.assertEqual(environment["quota_blockers"], [])
        self.assertEqual(environment["observed_app_cpu_quota"]["per_container_cpus"], 5.0)

    def test_a_snapshot_from_another_stage_is_refused(self):
        with self.assertRaisesRegex(loadgen.LoadGenError, "must never be attached to another"):
            loadgen.load_environment_snapshot(
                self.write(stage="governed-baseline"), self.stage
            )

    def test_a_snapshot_declaring_a_different_quota_is_refused(self):
        with self.assertRaisesRegex(loadgen.LoadGenError, "declares 2.0 app CPUs"):
            loadgen.load_environment_snapshot(self.write(declared_app_cpus=2.0), self.stage)

    def test_a_snapshot_missing_the_host_topology_is_refused(self):
        snapshot = json.loads(self.write().read_text(encoding="utf-8"))
        del snapshot["docker_vm_logical_cpus"]
        self.path.write_text(json.dumps(snapshot), encoding="utf-8")
        with self.assertRaisesRegex(loadgen.LoadGenError, "docker_vm_logical_cpus"):
            loadgen.load_environment_snapshot(self.path, self.stage)

    def test_a_stale_snapshot_whose_quota_no_longer_matches_yields_a_blocker(self):
        environment = loadgen.load_environment_snapshot(
            self.write(
                observed_app_cpu_quota={
                    "available": True,
                    "consistent": True,
                    "per_container_cpus": 2.0,
                    "containers": [{}, {}, {}],
                }
            ),
            self.stage,
        )
        self.assertTrue(
            any("Docker is enforcing 2.0" in blocker for blocker in environment["quota_blockers"])
        )


class CpuPartitionTests(unittest.TestCase):
    def test_the_budget_is_dealt_across_every_worker(self):
        slices = loadgen.generator_cpu_slices(4, 8, 8, 80)
        self.assertEqual(len(slices), 4)
        flattened = sorted(index for chunk in slices for index in chunk)
        self.assertEqual(flattened, list(range(8, 16)))

    def test_the_budget_stays_addressable_by_one_affinity_mask(self):
        # Windows pins through a single mask, which addresses one processor
        # group, so an 80-CPU host must still yield indices a mask can name.
        # The platform is forced rather than inherited: this invariant is
        # Windows-only, and a Linux runner would otherwise assert nothing.
        with mock.patch.object(loadgen.sys, "platform", "win32"):
            slices = loadgen.generator_cpu_slices(2, 24, 60, 80)
        for chunk in slices:
            for index in chunk:
                self.assertLess(index, loadgen.WINDOWS_AFFINITY_MASK_LIMIT)

    def test_the_budget_is_not_clamped_where_pinning_is_not_mask_based(self):
        # sched_setaffinity takes a CPU set, not a 64-bit mask, so the mask
        # limit does not apply and clamping to it would strand CPUs the
        # generator is entitled to use.
        with mock.patch.object(loadgen.sys, "platform", "linux"):
            slices = loadgen.generator_cpu_slices(2, 24, 60, 80)
        flattened = sorted(index for chunk in slices for index in chunk)
        self.assertEqual(flattened, list(range(56, 80)))

    def test_pinning_is_reported_rather_than_assumed(self):
        summary = loadgen.summarize_affinity(
            [
                {"affinity": {"applied": True}},
                {"affinity": {"applied": False, "reason": "unsupported platform"}},
            ]
        )
        self.assertFalse(summary["applied"])
        self.assertEqual(summary["pinned_workers"], 1)
        self.assertIn("unsupported platform", summary["reasons"])
        self.assertIn("hypervisor-scheduled", summary["caveat"])


class AggregationTests(unittest.TestCase):
    def worker(self, **overrides):
        service = loadgen.new_histogram()
        corrected = loadgen.new_histogram()
        lag = loadgen.new_histogram()
        for _ in range(100):
            service[loadgen.histogram_index(5.0)] += 1
            corrected[loadgen.histogram_index(6.0)] += 1
            lag[loadgen.histogram_index(1.0)] += 1
        result = {
            "worker_index": 0,
            "failed": False,
            "scheduled": 100,
            "issued": 100,
            "dispatch_blocked": 0,
            "responses": 100,
            "errors": 0,
            "connections_opened": 2,
            "requests_on_reused_connection": 98,
            "service_histogram": service,
            "corrected_histogram": corrected,
            "lag_histogram": lag,
            "per_second": {0: 50, 1: 50},
            "statuses": {"200": 100},
            "cpu_seconds": 1.0,
            "wall_seconds": 10.0,
            "affinity": {"applied": True},
        }
        result.update(overrides)
        return result

    def test_reuse_ratio_reflects_pooled_connections(self):
        metrics = loadgen.aggregate_worker_results(
            [self.worker()],
            measured_seconds=10.0,
            total_seconds=10.0,
            generator_cpu_allocation=4,
            ephemeral_ports=16_384,
            time_wait_peak=80,
        )
        self.assertAlmostEqual(metrics["connection_reuse_ratio"], 0.98)
        self.assertAlmostEqual(metrics["achieved_rate_per_second"], 10.0)
        self.assertEqual(metrics["error_rate"], 0.0)

    def test_generator_cpu_utilization_is_measured_against_its_allocation(self):
        metrics = loadgen.aggregate_worker_results(
            [self.worker(cpu_seconds=8.0, wall_seconds=10.0)],
            measured_seconds=10.0,
            total_seconds=10.0,
            generator_cpu_allocation=1,
            ephemeral_ports=16_384,
            time_wait_peak=None,
        )
        self.assertAlmostEqual(metrics["generator_cpu_utilization_of_allocation"], 0.8)

    def test_undispatched_sends_surface_as_a_deficit(self):
        metrics = loadgen.aggregate_worker_results(
            [self.worker(issued=60, dispatch_blocked=40)],
            measured_seconds=10.0,
            total_seconds=10.0,
            generator_cpu_allocation=4,
            ephemeral_ports=16_384,
            time_wait_peak=None,
        )
        self.assertAlmostEqual(metrics["dispatch_deficit_fraction"], 0.40)
        self.assertAlmostEqual(metrics["dispatch_blocked_fraction"], 0.40)

    def test_a_crashed_worker_is_recorded_not_swallowed(self):
        metrics = loadgen.aggregate_worker_results(
            [self.worker(), {"worker_index": 1, "failed": True, "error": "OSError: boom"}],
            measured_seconds=10.0,
            total_seconds=10.0,
            generator_cpu_allocation=4,
            ephemeral_ports=16_384,
            time_wait_peak=None,
        )
        self.assertEqual(len(metrics["worker_failures"]), 1)
        self.assertIn("boom", metrics["worker_failures"][0]["error"])

    def test_time_wait_is_reported_against_the_ephemeral_range(self):
        metrics = loadgen.aggregate_worker_results(
            [self.worker()],
            measured_seconds=10.0,
            total_seconds=10.0,
            generator_cpu_allocation=4,
            ephemeral_ports=16_384,
            time_wait_peak=8_192,
        )
        self.assertAlmostEqual(metrics["time_wait_fraction_of_ephemeral_range"], 0.5)


class FigureAssemblyTests(unittest.TestCase):
    def worker_result(self, responses=600_000, errors=0):
        corrected = loadgen.new_histogram()
        service = loadgen.new_histogram()
        lag = loadgen.new_histogram()
        corrected[loadgen.histogram_index(120.0)] += responses
        service[loadgen.histogram_index(90.0)] += responses
        lag[loadgen.histogram_index(1.0)] += responses
        return {
            "worker_index": 0,
            "failed": False,
            "scheduled": 900_000,
            "issued": 900_000,
            "dispatch_blocked": 0,
            "responses": responses,
            "errors": errors,
            "connections_opened": 1_024,
            "requests_on_reused_connection": responses - 1_024,
            "service_histogram": service,
            "corrected_histogram": corrected,
            "lag_histogram": lag,
            "per_second": {second: 10_000 for second in range(30, 90)},
            "statuses": {"200": responses},
            "cpu_seconds": 240.0,
            "wall_seconds": 90.0,
            "affinity": {"applied": True},
        }

    def test_a_figure_built_from_metrics_carries_its_whole_environment(self):
        stage = {
            "name": "raised-quota",
            "app_cpus": 5.0,
            "app_replicas": 3,
            "search_projector_cpus": 3.0,
            "weights": {"health": 1},
        }
        step = {
            "name": "raised-10000",
            "target_rate_per_second": 10_000.0,
            "duration_seconds": 90.0,
            "warmup_seconds": 30.0,
        }
        metrics = loadgen.aggregate_worker_results(
            [self.worker_result()],
            measured_seconds=60.0,
            total_seconds=90.0,
            generator_cpu_allocation=24,
            ephemeral_ports=16_384,
            time_wait_peak=100,
        )
        environment = {
            "host_logical_cpus": 80,
            "docker_vm_logical_cpus": 26,
            "observed_app_cpu_quota": {
                "available": True,
                "consistent": True,
                "per_container_cpus": 5.0,
                "containers": [{}, {}, {}],
            },
            "quota_blockers": [],
        }
        figure = loadgen.build_figure(
            stage=stage,
            step=step,
            metrics=metrics,
            environment=environment,
            generator={
                "worker_processes": 16,
                "connections_per_worker": 64,
                "cpu_allocation": 24,
            },
            transport_path="direct-container-network",
            thresholds={},
        )
        self.assertEqual(loadgen.missing_required_fields(figure), [])
        self.assertEqual(figure["container_cpu_quota_source"], "observed")
        self.assertEqual(figure["container_cpu_quota_app_total"], 15.0)
        self.assertEqual(figure["offered_rate_per_second"], 10_000.0)
        self.assertEqual(figure["longest_sustained_seconds_at_target"], 60)
        self.assertFalse(figure["proof_eligible"])
        self.assertIsNone(figure["measurement_void_reason"])
        loadgen.render_figure_markdown(figure)

    def test_a_step_that_measured_nothing_still_reports_its_quota(self):
        """A totally failed step must be reportable, not an exception mid-window."""

        stage = {
            "name": "raised-quota",
            "app_cpus": 5.0,
            "app_replicas": 3,
            "search_projector_cpus": 3.0,
            "weights": {"health": 1},
        }
        step = {
            "name": "raised-10000",
            "target_rate_per_second": 10_000.0,
            "duration_seconds": 90.0,
            "warmup_seconds": 30.0,
        }
        metrics = loadgen.aggregate_worker_results(
            [self.worker_result(responses=0)],
            measured_seconds=60.0,
            total_seconds=90.0,
            generator_cpu_allocation=24,
            ephemeral_ports=16_384,
            time_wait_peak=None,
        )
        self.assertEqual(metrics["error_rate"], 1.0)
        self.assertIn("no response was received", metrics["measurement_void_reason"])
        figure = loadgen.build_figure(
            stage=stage,
            step=step,
            metrics=metrics,
            environment={
                "host_logical_cpus": 80,
                "docker_vm_logical_cpus": 26,
                "observed_app_cpu_quota": {
                    "available": True,
                    "consistent": True,
                    "per_container_cpus": 5.0,
                    "containers": [{}, {}, {}],
                },
                "quota_blockers": [],
            },
            generator={
                "worker_processes": 16,
                "connections_per_worker": 64,
                "cpu_allocation": 24,
            },
            transport_path="direct-container-network",
            thresholds={},
        )
        markdown = loadgen.render_figure_markdown(figure)
        self.assertIn("Nothing was measured", markdown)
        self.assertIn("Container CPU quota: 5.0 CPUs per app node", markdown)
        self.assertEqual(figure["pass_criteria"]["assessment"], "shortfall")

    def test_an_unverified_quota_is_labelled_as_declared_not_observed(self):
        stage = {
            "name": "raised-quota",
            "app_cpus": 5.0,
            "app_replicas": 3,
            "search_projector_cpus": 3.0,
            "weights": {"health": 1},
        }
        step = {
            "name": "raised-1000",
            "target_rate_per_second": 1_000.0,
            "duration_seconds": 90.0,
            "warmup_seconds": 30.0,
        }
        metrics = loadgen.aggregate_worker_results(
            [],
            measured_seconds=60.0,
            total_seconds=90.0,
            generator_cpu_allocation=24,
            ephemeral_ports=None,
            time_wait_peak=None,
        )
        figure = loadgen.build_figure(
            stage=stage,
            step=step,
            metrics=metrics,
            environment={
                "host_logical_cpus": 80,
                "docker_vm_logical_cpus": 26,
                "observed_app_cpu_quota": {"available": False},
                "quota_blockers": ["unverified"],
            },
            generator={
                "worker_processes": 16,
                "connections_per_worker": 64,
                "cpu_allocation": 24,
            },
            transport_path="docker-desktop-port-proxy",
            thresholds={},
        )
        self.assertEqual(figure["container_cpu_quota_source"], "declared-unverified")
        self.assertEqual(figure["container_cpu_quota_blockers"], ["unverified"])
        self.assertEqual(figure["transport_disclosure"], loadgen.LOOPBACK_DISCLOSURE)


class RunGateTests(unittest.TestCase):
    """Being build-complete is not authorization to generate load."""

    class Args:
        exclusive_window_released = False

    def test_the_run_is_refused_without_both_the_flag_and_the_environment(self):
        import os

        previous = os.environ.pop(loadgen.RELEASE_ENV, None)
        try:
            blockers = loadgen.run_release_blockers(self.Args())
            self.assertEqual(len(blockers), 2)
            os.environ[loadgen.RELEASE_ENV] = "1"
            self.assertEqual(len(loadgen.run_release_blockers(self.Args())), 1)
        finally:
            os.environ.pop(loadgen.RELEASE_ENV, None)
            if previous is not None:
                os.environ[loadgen.RELEASE_ENV] = previous

    def test_run_exits_nonzero_when_the_window_is_not_released(self):
        import os

        previous = os.environ.pop(loadgen.RELEASE_ENV, None)
        try:
            code = loadgen.main(
                [
                    "run",
                    "--profile",
                    str(PROFILE_PATH),
                    "--stage",
                    "raised-quota",
                    "--base-url",
                    "http://127.0.0.1:18081",
                    "--report-dir",
                    str(PERF_ROOT / "does-not-exist"),
                    "--transport-path",
                    "docker-desktop-port-proxy",
                ]
            )
            self.assertEqual(code, 3)
            self.assertFalse((PERF_ROOT / "does-not-exist").exists())
        finally:
            if previous is not None:
                os.environ[loadgen.RELEASE_ENV] = previous


class CliTests(unittest.TestCase):
    def test_plan_and_env_generate_no_load(self):
        self.assertEqual(loadgen.main(["plan", "--profile", str(PROFILE_PATH)]), 0)
        self.assertEqual(
            loadgen.main(
                ["env", "--profile", str(PROFILE_PATH), "--stage", "governed-baseline"]
            ),
            0,
        )

    def test_env_emits_the_compose_quota_variables(self):
        profile = read_profile()
        stage = loadgen.find_stage(profile, "raised-quota")
        exports = loadgen.stage_environment_exports(stage)
        self.assertIn("CHANCELA_PERF_APP_CPUS=5.0", exports)
        self.assertIn("CHANCELA_PERF_SEARCH_PROJECTOR_CPUS=3.0", exports)
        self.assertIn("CHANCELA_CLUSTER_REPLICAS=3", exports)

    def test_verify_slo_passes_on_the_committed_policy(self):
        self.assertEqual(loadgen.main(["verify-slo", "--slo", str(SLO_PATH)]), 0)

    def test_an_unknown_stage_is_an_error_not_a_default(self):
        with self.assertRaisesRegex(loadgen.LoadGenError, "unknown stage"):
            loadgen.find_stage(read_profile(), "make-it-fast")

    def test_identifier_bearing_endpoints_fail_closed_without_identifiers(self):
        with self.assertRaisesRegex(loadgen.LoadGenError, "needs seeded entities"):
            loadgen._build_paths({"entity_get": 1}, {"entities": []}, __import__("random").Random(0), 1)


# ---------------------------------------------------------------------------
# The only tests that touch a socket. They exist because connection reuse is the
# entire point of this rework and cannot be asserted from pure logic. The load is
# a few hundred requests against a local Python server in this process: no Docker
# stack, no application, no benchmark.
# ---------------------------------------------------------------------------


class _StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class _StubServer:
    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.server.server_address

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        return False


def worker_config(host, port, **overrides):
    config = {
        "worker_index": 0,
        "worker_count": 1,
        "cpu_indices": [],
        "target_rate_per_second": 200.0,
        "duration_seconds": 1.0,
        "warmup_seconds": 0.0,
        "connections_per_worker": 4,
        "request_timeout_seconds": 10.0,
        "weights": {"health": 1},
        "identifiers": {"entities": [], "books": [], "signatures": []},
        "targets": [[host, port]],
        "session_token": None,
        "seed": 1,
        "start_at_perf_ns": time.perf_counter_ns(),
    }
    config.update(overrides)
    return config


class ConnectionReuseTests(unittest.TestCase):
    def test_the_pooled_client_reuses_connections_instead_of_churning_them(self):
        """~200 requests over at most 4 sockets. urllib would have opened ~200."""

        with _StubServer() as (host, port):
            result = loadgen._worker_run(worker_config(host, port))
        self.assertFalse(result["failed"])
        self.assertGreater(result["responses"], 100)
        self.assertLessEqual(result["connections_opened"], 4)
        metrics = loadgen.aggregate_worker_results(
            [result],
            measured_seconds=1.0,
            total_seconds=1.0,
            generator_cpu_allocation=4,
            ephemeral_ports=16_384,
            time_wait_peak=0,
        )
        self.assertGreater(metrics["connection_reuse_ratio"], 0.95)
        self.assertEqual(metrics["errors"], 0)

    def test_the_dispatcher_does_not_wait_for_responses(self):
        """Open loop: every scheduled send is issued within the step's own window."""

        with _StubServer() as (host, port):
            result = loadgen._worker_run(worker_config(host, port))
        self.assertEqual(result["issued"] + result["dispatch_blocked"], result["scheduled"])
        self.assertGreater(result["issued"], 0)

    def test_corrected_latency_is_measured_from_the_intended_send_time(self):
        with _StubServer() as (host, port):
            result = loadgen._worker_run(worker_config(host, port))
        corrected = loadgen.histogram_percentile(result["corrected_histogram"], 0.99)
        service = loadgen.histogram_percentile(result["service_histogram"], 0.99)
        self.assertIsNotNone(corrected)
        self.assertIsNotNone(service)
        # Corrected latency includes the wait from intended send, so it can only
        # be greater than or equal to service time at the same quantile.
        self.assertGreaterEqual(corrected, service)


class MultiProcessSmokeTests(unittest.TestCase):
    """De-risks the spawn path before the exclusive window, at ~200 requests."""

    def test_two_spawned_workers_report_back_through_the_queue(self):
        with _StubServer() as (host, port):
            context = multiprocessing.get_context("spawn")
            result_queue = context.Queue()
            start_at = time.perf_counter_ns() + int(1e9)
            processes = []
            for index in range(2):
                config = worker_config(
                    host,
                    port,
                    worker_index=index,
                    worker_count=2,
                    start_at_perf_ns=start_at,
                )
                process = context.Process(target=loadgen._worker_main, args=(config, result_queue))
                process.start()
                processes.append(process)
            results = []
            deadline = time.monotonic() + 90
            while len(results) < 2 and time.monotonic() < deadline:
                try:
                    results.append(result_queue.get(timeout=5))
                except Exception:
                    continue
            for process in processes:
                process.join(timeout=30)

        self.assertEqual(len(results), 2, "both spawned workers must report")
        for result in results:
            self.assertFalse(result.get("failed"), result.get("error"))
        metrics = loadgen.aggregate_worker_results(
            results,
            measured_seconds=1.0,
            total_seconds=1.0,
            generator_cpu_allocation=2,
            ephemeral_ports=16_384,
            time_wait_peak=0,
        )
        self.assertGreater(metrics["responses"], 100)
        self.assertEqual(metrics["errors"], 0)
        self.assertIsNotNone(metrics["generator_cpu_utilization_of_allocation"])


if __name__ == "__main__":
    unittest.main()
