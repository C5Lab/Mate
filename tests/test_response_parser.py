"""Host tests for scan_networks / show_scan_results CSV parsing. No ESP-IDF required."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ScanCsvTests(unittest.TestCase):
    def test_rfc4180_scan_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = str(Path(tmp) / "scan_csv")
            cmd = [
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT / "main"),
                str(ROOT / "main" / "response_parser.c"),
                str(ROOT / "tests" / "response_parser_test.c"),
                "-o", executable,
            ]
            subprocess.run(cmd, check=True)
            self.assertIn(
                "scan CSV parser PASS",
                subprocess.check_output([executable], text=True),
            )


if __name__ == "__main__":
    unittest.main()
