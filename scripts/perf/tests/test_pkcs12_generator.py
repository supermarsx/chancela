from __future__ import annotations

import os
import pathlib
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


PERF_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = PERF_ROOT.parents[1]
GENERATOR = PERF_ROOT / "generate-test-pkcs12.sh"
PASSPHRASE_ENV = "CHANCELA_PERF_PKCS12_PASSPHRASE"
WRONG_PASSPHRASE_ENV = "CHANCELA_PERF_PKCS12_WRONG_PASSPHRASE"
PFX_PATH_ENV = "CHANCELA_PERF_GENERATED_PKCS12_PATH"
RUNTIME_TEST = "generated_performance_pkcs12_loads_and_signs_detached_cades"


class Pkcs12GeneratorTests(unittest.TestCase):
    def test_generator_pins_the_bounded_loader_compatible_profile(self):
        script = GENERATOR.read_text(encoding="utf-8")
        self.assertIn("-keypbe PBE-SHA1-3DES", script)
        self.assertIn("-certpbe PBE-SHA1-3DES", script)
        self.assertIn("-macalg sha1", script)
        self.assertIn("disposable", script)
        self.assertIn("never use this legacy profile for real certificate export", script)
        self.assertNotIn("-passout pass:", script)
        self.assertNotIn("pass:${passphrase}", script)
        self.assertIn(
            "-passout env:CHANCELA_PERF_PKCS12_PASSPHRASE",
            script,
        )

    def shell_path(self, path: pathlib.Path) -> str:
        if os.name != "nt":
            return str(path)
        cygpath = shutil.which("cygpath")
        if cygpath is None:
            self.skipTest("a POSIX path converter is unavailable for the Windows shell")
        converted = subprocess.run(
            [cygpath, "-u", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if converted.returncode != 0 or not converted.stdout.strip():
            self.skipTest(f"cygpath could not convert {path}")
        return converted.stdout.strip()

    def cargo_env_path(self, path: pathlib.Path) -> str:
        if not sys.platform.startswith("cygwin"):
            return str(path)
        cygpath = shutil.which("cygpath")
        if cygpath is None:
            self.skipTest("cygpath is required to pass a fixture path to native Cargo")
        converted = subprocess.run(
            [cygpath, "-w", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if converted.returncode != 0 or not converted.stdout.strip():
            self.skipTest(f"cygpath could not convert Cargo fixture path {path}")
        return converted.stdout.strip()

    def test_generated_identity_is_parseable_with_the_pinned_algorithms(self):
        shell = shutil.which("sh")
        openssl = shutil.which("openssl")
        cargo = shutil.which("cargo")
        if shell is None or openssl is None or cargo is None:
            self.skipTest(
                "sh, openssl, and cargo are required for the generator integration test"
            )
        openssl_input_path = None
        if os.name == "nt":
            # Do not mix Cygwin sh with an MSYS/OpenSSL binary (or vice versa):
            # their `/tmp` path conventions are different. Prefer the OpenSSL
            # installed beside the selected POSIX shell and pin that directory
            # first in PATH for the script as well.
            adjacent = pathlib.Path(shell).with_name("openssl.exe")
            if adjacent.is_file():
                openssl = str(adjacent)

        with tempfile.TemporaryDirectory() as raw:
            output = pathlib.Path(raw) / "identity.p12"
            passphrase = secrets.token_urlsafe(32)
            wrong_passphrase = secrets.token_urlsafe(32)
            environment = os.environ.copy()
            environment[PASSPHRASE_ENV] = passphrase
            environment[WRONG_PASSPHRASE_ENV] = wrong_passphrase
            environment["PATH"] = (
                str(pathlib.Path(shell).parent)
                + os.pathsep
                + environment.get("PATH", "")
            )
            openssl_input_path = (
                self.shell_path(output)
                if os.name == "nt"
                and pathlib.Path(openssl).parent == pathlib.Path(shell).parent
                else str(output)
            )
            generated = subprocess.run(
                [
                    shell,
                    self.shell_path(GENERATOR),
                    self.shell_path(output),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=30,
            )
            generated_output = generated.stdout + generated.stderr
            if passphrase in generated_output:
                self.fail("generator output exposed its passphrase; output redacted")
            self.assertEqual(
                generated.returncode,
                0,
                f"generator failed\nstdout:\n{generated.stdout}\nstderr:\n{generated.stderr}",
            )
            self.assertTrue(output.is_file())
            self.assertGreater(output.stat().st_size, 0)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

            inspected = subprocess.run(
                [
                    openssl,
                    "pkcs12",
                    "-in",
                    openssl_input_path,
                    "-passin",
                    f"env:{PASSPHRASE_ENV}",
                    "-info",
                    "-noout",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=30,
            )
            inspected_output = inspected.stdout + inspected.stderr
            if passphrase in inspected_output:
                self.fail("OpenSSL inspection exposed the passphrase; output redacted")
            self.assertEqual(
                inspected.returncode,
                0,
                f"generated PFX was not readable\nstdout:\n{inspected.stdout}"
                f"\nstderr:\n{inspected.stderr}",
            )
            algorithm_report = (inspected.stdout + inspected.stderr).casefold()
            self.assertIn("mac: sha1", algorithm_report)
            self.assertGreaterEqual(
                algorithm_report.count("pbewithsha1and3-keytripledes-cbc"),
                2,
                algorithm_report,
            )

            wrong_password = subprocess.run(
                [
                    openssl,
                    "pkcs12",
                    "-in",
                    openssl_input_path,
                    "-passin",
                    f"env:{WRONG_PASSPHRASE_ENV}",
                    "-info",
                    "-noout",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=30,
            )
            wrong_password_output = wrong_password.stdout + wrong_password.stderr
            if wrong_passphrase in wrong_password_output:
                self.fail("wrong-password output exposed the passphrase; output redacted")
            self.assertNotEqual(wrong_password.returncode, 0)

            runtime_environment = environment.copy()
            runtime_environment[PFX_PATH_ENV] = self.cargo_env_path(output)
            runtime_loader = subprocess.run(
                [
                    cargo,
                    "test",
                    "--locked",
                    "-p",
                    "chancela-signing",
                    "--test",
                    "soft_cert_pkcs12",
                    RUNTIME_TEST,
                    "--",
                    "--ignored",
                    "--exact",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
                env=runtime_environment,
                timeout=300,
            )
            runtime_output = runtime_loader.stdout + runtime_loader.stderr
            if passphrase in runtime_output:
                self.fail("runtime-loader output exposed the passphrase; output redacted")
            self.assertEqual(
                runtime_loader.returncode,
                0,
                "generated PFX did not load and sign through Pkcs12SigningSource"
                f"\nstdout:\n{runtime_loader.stdout}"
                f"\nstderr:\n{runtime_loader.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
