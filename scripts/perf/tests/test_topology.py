import pathlib
import sys
import unittest


PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PERF_ROOT))

import topology  # noqa: E402


class TopologyValidationTests(unittest.TestCase):
    def config(self):
        return {
            "services": {
                service: {
                    "deploy": {
                        "resources": {
                            "limits": {"cpus": "2.0", "memory": "1GiB"}
                        }
                    }
                }
                for service in topology.REQUIRED_SERVICES
            }
        }

    def test_every_required_service_must_have_bounded_resources(self):
        failures, limits = topology.validate_rendered_config(self.config())
        self.assertEqual(failures, [])
        self.assertEqual(
            limits["chancela-cluster"]["memory_bytes"],
            1024**3,
        )

        invalid = self.config()
        invalid["services"]["chancela-cluster"]["deploy"]["resources"][
            "limits"
        ].pop("memory")
        failures, _ = topology.validate_rendered_config(invalid)
        self.assertIn(
            "chancela-cluster has no positive memory limit",
            failures,
        )

    def test_replica_restart_and_oom_state_are_strict_preflight_failures(self):
        healthy = {
            "name": "container",
            "running": True,
            "health": "healthy",
            "restart_count": 0,
            "oom_killed": False,
        }
        containers = {
            "chancela-cluster": [dict(healthy) for _ in range(3)],
            "postgres": [dict(healthy)],
            "redis": [dict(healthy)],
            "perf-gateway": [dict(healthy)],
        }
        self.assertEqual(topology.validate_containers(containers, 3), [])
        containers["chancela-cluster"][0]["oom_killed"] = True
        containers["redis"][0]["restart_count"] = 1
        failures = topology.validate_containers(containers, 3)
        self.assertTrue(any("OOM-killed" in failure for failure in failures))
        self.assertTrue(any("restarted 1 times" in failure for failure in failures))

    def test_aggregate_limits_must_fit_the_docker_host_envelope(self):
        failures, limits = topology.validate_rendered_config(self.config())
        self.assertEqual(failures, [])
        enough_host = {
            "docker_host": {
                "cpus": 12,
                "memory_bytes": 6 * 1024**3,
            }
        }
        failures, envelope = topology.validate_host_envelope(limits, 3, enough_host)
        self.assertEqual(failures, [])
        self.assertTrue(envelope["within_envelope"])
        self.assertEqual(envelope["requested_cpus"], 12)
        self.assertEqual(envelope["requested_memory_bytes"], 6 * 1024**3)

        failures, envelope = topology.validate_host_envelope(
            limits,
            3,
            {"docker_host": {"cpus": 8, "memory_bytes": 4 * 1024**3}},
        )
        self.assertFalse(envelope["within_envelope"])
        self.assertTrue(any("CPU" in failure for failure in failures))
        self.assertTrue(any("memory" in failure for failure in failures))

        failures, envelope = topology.validate_host_envelope(limits, 3, {})
        self.assertFalse(envelope["available"])
        self.assertTrue(any("unavailable" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
