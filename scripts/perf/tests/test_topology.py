import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import unittest


PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PERF_ROOT))

import topology  # noqa: E402


DEFAULT_SERVICE_MEMORY_BYTES = {
    "chancela-cluster": 1024**3,
    "search-projector-postgres": 1024**3,
    "postgres": 1024**3,
    "redis": 320 * 1024**2,
    "perf-gateway": 256 * 1024**2,
}
DEFAULT_THREE_REPLICA_MEMORY_BYTES = 5_972_688_896


class TopologyValidationTests(unittest.TestCase):
    def test_dedicated_database_acknowledgement_is_performance_only(self):
        repository = PERF_ROOT.parents[1]
        performance_overlay = (
            repository / "scripts/perf/docker-compose.perf.yml"
        ).read_text(encoding="utf-8")
        normal_compose = (
            repository / "docker/docker-compose.yml"
        ).read_text(encoding="utf-8")
        hardened_compose = (
            repository / "docker-compose.hardened.yml"
        ).read_text(encoding="utf-8")

        self.assertRegex(
            performance_overlay,
            re.compile(
                r"^  search-projector-role-init:\n"
                r"    environment:\n"
                r"(?:      #.*\n)+"
                r'      CHANCELA_PROJECTOR_DEDICATED_DATABASE: "true"$',
                re.MULTILINE,
            ),
        )
        fail_closed_default = (
            "CHANCELA_PROJECTOR_DEDICATED_DATABASE: "
            "${CHANCELA_PROJECTOR_DEDICATED_DATABASE:-}"
        )
        self.assertIn(fail_closed_default, normal_compose)
        self.assertIn(fail_closed_default, hardened_compose)
        self.assertNotIn(
            'CHANCELA_PROJECTOR_DEDICATED_DATABASE: "true"',
            normal_compose,
        )
        self.assertNotIn(
            'CHANCELA_PROJECTOR_DEDICATED_DATABASE: "true"',
            hardened_compose,
        )

    def config(self):
        defaults = {
            "chancela-cluster": {"cpus": "2.0", "memory": "1g"},
            "search-projector-postgres": {"cpus": "1.5", "memory": "1g"},
            "postgres": {"cpus": "2.0", "memory": "1g"},
            "redis": {"cpus": "1.0", "memory": "320m"},
            "perf-gateway": {"cpus": "1.0", "memory": "256m"},
        }
        return {
            "services": {
                service: {
                    "deploy": {
                        "resources": {
                            "limits": defaults[service]
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

    def test_memory_suffix_variants_follow_compose_binary_semantics(self):
        cases = {
            "1k": 1024,
            "1KB": 1024,
            "1KiB": 1024,
            "1m": 1024**2,
            "1MB": 1024**2,
            "1MiB": 1024**2,
            "1g": 1024**3,
            "1GB": 1024**3,
            "1GiB": 1024**3,
            "1t": 1024**4,
            "1TB": 1024**4,
            "1TiB": 1024**4,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(topology.parse_memory_bytes(value), expected)

    def test_inactive_forbidden_services_may_remain_declared(self):
        for forbidden in topology.FORBIDDEN_CLUSTER_SERVICES:
            with self.subTest(forbidden=forbidden):
                rendered = self.config()
                rendered["services"][forbidden] = {
                    "profiles": ["inactive-for-performance"]
                }
                failures, _ = topology.validate_rendered_config(rendered)
                self.assertEqual(failures, [])

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
            "search-projector-postgres": [dict(healthy)],
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

    def test_only_running_forbidden_containers_fail_preflight(self):
        healthy = {
            "name": "container",
            "running": True,
            "health": "healthy",
            "restart_count": 0,
            "oom_killed": False,
        }
        containers = {
            "chancela-cluster": [dict(healthy) for _ in range(3)],
            "search-projector-postgres": [dict(healthy)],
            "postgres": [dict(healthy)],
            "redis": [dict(healthy)],
            "perf-gateway": [dict(healthy)],
            "server-postgres": [
                {
                    "name": "stopped-standalone",
                    "running": False,
                    "restart_count": 0,
                    "oom_killed": False,
                }
            ],
            "server-sqlite": [],
            "search-projector-sqlite": [],
        }
        self.assertEqual(topology.validate_containers(containers, 3), [])
        containers["server-postgres"][0]["running"] = True
        failures = topology.validate_containers(containers, 3)
        self.assertEqual(
            failures,
            [
                "forbidden standalone service "
                "server-postgres/stopped-standalone is running"
            ],
        )

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
        self.assertEqual(envelope["requested_cpus"], 11.5)
        self.assertEqual(
            envelope["requested_memory_bytes"],
            DEFAULT_THREE_REPLICA_MEMORY_BYTES,
        )

        failures, envelope = topology.validate_host_envelope(
            limits,
            3,
            {
                "docker_host": {
                    "cpus": 12,
                    "memory_bytes": DEFAULT_THREE_REPLICA_MEMORY_BYTES - 1,
                }
            },
        )
        self.assertFalse(envelope["within_envelope"])
        self.assertEqual(
            failures,
            [
                "aggregate requested memory limit 5972688896 exceeds "
                "Docker host envelope 5972688895"
            ],
        )

        failures, envelope = topology.validate_host_envelope(
            limits,
            3,
            {
                "docker_host": {
                    "cpus": 11,
                    "memory_bytes": DEFAULT_THREE_REPLICA_MEMORY_BYTES,
                }
            },
        )
        self.assertFalse(envelope["within_envelope"])
        self.assertTrue(any("CPU" in failure for failure in failures))
        self.assertFalse(any("memory" in failure for failure in failures))

        failures, envelope = topology.validate_host_envelope(limits, 3, {})
        self.assertFalse(envelope["available"])
        self.assertTrue(any("unavailable" in failure for failure in failures))

    def test_real_compose_render_contract_when_docker_compose_is_available(self):
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("Docker CLI is unavailable")
        version = subprocess.run(
            [docker, "compose", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if version.returncode != 0:
            self.skipTest("Docker Compose plugin is unavailable")

        repository = PERF_ROOT.parents[1]
        environment = os.environ.copy()
        environment.update(
            {
                "CHANCELA_PERF_APP_CPUS": "2.0",
                "CHANCELA_PERF_APP_MEMORY": "1g",
                "CHANCELA_PERF_SEARCH_PROJECTOR_CPUS": "1.5",
                "CHANCELA_PERF_SEARCH_PROJECTOR_MEMORY": "1g",
            }
        )
        rendered = subprocess.run(
            [
                docker,
                "compose",
                "--project-name",
                "chancela-perf-contract",
                "-f",
                "docker/docker-compose.yml",
                "-f",
                "docker/docker-compose.cluster.yml",
                "-f",
                "scripts/perf/docker-compose.perf.yml",
                "--profile",
                "postgres",
                "--profile",
                "cluster",
                "--profile",
                "performance",
                "config",
                "--format",
                "json",
            ],
            cwd=repository,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        config = json.loads(rendered.stdout)
        self.assertEqual(
            config["services"]["search-projector-role-init"]["environment"][
                "CHANCELA_PROJECTOR_DEDICATED_DATABASE"
            ],
            "true",
        )
        failures, limits = topology.validate_rendered_config(config)
        self.assertEqual(failures, [])
        self.assertEqual(set(limits), set(topology.REQUIRED_SERVICES))
        for service, expected in DEFAULT_SERVICE_MEMORY_BYTES.items():
            with self.subTest(service=service):
                self.assertEqual(limits[service]["memory_bytes"], expected)

        host = {
            "docker_host": {
                "cpus": 12,
                "memory_bytes": 6 * 1024**3,
            }
        }
        failures, envelope = topology.validate_host_envelope(limits, 3, host)
        self.assertEqual(failures, [])
        self.assertEqual(
            envelope["requested_memory_bytes"],
            DEFAULT_THREE_REPLICA_MEMORY_BYTES,
        )

        host["docker_host"]["memory_bytes"] = (
            DEFAULT_THREE_REPLICA_MEMORY_BYTES - 1
        )
        failures, envelope = topology.validate_host_envelope(limits, 3, host)
        self.assertFalse(envelope["within_envelope"])
        self.assertEqual(
            failures,
            [
                "aggregate requested memory limit 5972688896 exceeds "
                "Docker host envelope 5972688895"
            ],
        )


if __name__ == "__main__":
    unittest.main()
