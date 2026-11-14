import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PST = ROOT / "pst.py"


def run_pst(*arguments):
    return subprocess.run(
        [sys.executable, str(PST), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True
    )


class PSTCommandLineTests(unittest.TestCase):

    def test_version(self):
        result = run_pst("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("PST 1.9.1", result.stdout)

    def test_help(self):
        result = run_pst("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("AVAILABLE COMMANDS", result.stdout)
        self.assertIn("SHA-256", result.stdout)

    def test_sha256_hash(self):
        content = b"Pigeon Security Toolkit test"
        expected = hashlib.sha256(content).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            test_file = Path(directory) / "sample.txt"
            test_file.write_bytes(content)

            result = run_pst("hash", str(test_file))

        self.assertEqual(result.returncode, 0)
        self.assertIn(expected, result.stdout)

    def test_missing_file(self):
        result = run_pst("hash", "file_that_does_not_exist.txt")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("File not found", result.stdout)

    def test_hash_requires_file_argument(self):
        result = run_pst("hash")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stdout)

    def test_unknown_command(self):
        result = run_pst("invalid-command")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown command", result.stdout)


if __name__ == "__main__":
    unittest.main()
