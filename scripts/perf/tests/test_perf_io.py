import ast
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PERF_ROOT))

import harness  # noqa: E402
import perf_io  # noqa: E402
import topology  # noqa: E402


class Python39FilesystemCompatibilityTests(unittest.TestCase):
    def test_production_never_passes_newline_to_path_write_text(self):
        offenders = []
        for path in sorted(PERF_ROOT.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "write_text":
                    continue
                if any(keyword.arg == "newline" for keyword in node.keywords):
                    offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(
            offenders,
            [],
            "Path.write_text(newline=...) requires Python 3.10+: "
            + ", ".join(offenders),
        )

    def test_lf_writers_do_not_call_path_write_text(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            with mock.patch.object(
                pathlib.Path,
                "write_text",
                side_effect=AssertionError("Path.write_text must not be used"),
            ):
                perf_io.write_text_lf(root / "plain.txt", "alpha\nbeta\n")
                perf_io.atomic_write_text_lf(
                    root / "atomic.txt",
                    "gamma\ndelta\n",
                )
            self.assertEqual(
                (root / "plain.txt").read_bytes(),
                b"alpha\nbeta\n",
            )
            self.assertEqual(
                (root / "atomic.txt").read_bytes(),
                b"gamma\ndelta\n",
            )
            self.assertFalse((root / "atomic.txt.tmp").exists())

    def test_json_evidence_bytes_remain_deterministic_and_atomic(self):
        value = {"zeta": [2, 1], "alpha": {"enabled": True}}
        expected = (
            json.dumps(value, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            harness_path = root / "harness.json"
            topology_path = root / "topology.json"
            harness.write_json(harness_path, value)
            topology.write_json(topology_path, value)
            self.assertEqual(harness_path.read_bytes(), expected)
            self.assertEqual(topology_path.read_bytes(), expected)
            self.assertFalse((root / "harness.json.tmp").exists())
            self.assertFalse((root / "topology.json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
