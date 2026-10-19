"""Deterministic, network-free ProofCanvas tests (stdlib unittest)."""
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proofcanvas as pc

SAMPLE = """INITIALIZE = PASS | protocol=2025-11-25
TOOL_DISCOVERY = PASS | 8 tools
UNAPPROVED_BLOCK = PASS | blocked
DRIFT_BLOCK = PASS | denied
"""

class ProofCanvasTest(unittest.TestCase):
    def test_all_pass(self):
        checks = pc.parse_transcript(SAMPLE)
        self.assertEqual(pc.summarize(checks)["verdict"], "PASSED")
        self.assertEqual(pc.summarize(checks)["total"], 4)

    def test_failure_does_not_get_inflated(self):
        checks = pc.parse_transcript("INITIALIZE = PASS\nDRIFT_BLOCK = FAIL\n")
        self.assertEqual(pc.summarize(checks)["verdict"], "FAILED")

    def test_skip_is_incomplete(self):
        checks = pc.parse_transcript("INITIALIZE = PASS\nVERIFY = SKIP\n")
        self.assertEqual(pc.summarize(checks)["verdict"], "INCOMPLETE")

    def test_error_is_failure(self):
        checks = pc.parse_transcript("INITIALIZE = ERROR\n")
        self.assertEqual(pc.summarize(checks)["verdict"], "FAILED")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            pc.parse_transcript("ALL CHECKS PASSED\n")

    def test_rejects_duplicate(self):
        with self.assertRaises(ValueError):
            pc.parse_transcript("INITIALIZE = PASS\nINITIALIZE = FAIL\n")

    def test_unknown_label_is_pseudonymized(self):
        checks = pc.parse_transcript("SECRET_CUSTOMER_456 = PASS | client=Private\n")
        self.assertEqual(checks[0]["code"], "CHECK_01")
        self.assertNotIn("CUSTOMER", repr(checks))

    def test_detail_not_copied_even_unusual_secret_formats(self):
        secret = "super_private_token_@#123"
        parsed = pc.parse_transcript("INITIALIZE = PASS | Proprietary: " + secret)
        rendered = pc.render_html(parsed, pc.summarize(parsed), "Tests")
        self.assertNotIn(secret, rendered)
        self.assertNotIn("Proprietary", rendered)
        self.assertIn("Initialize the MCP client", rendered)

    def test_label_html_escaped(self):
        checks = pc.parse_transcript(SAMPLE)
        rendered = pc.render_html(checks, pc.summarize(checks), "<script>alert(1)</script>")
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_control_character_stripped_from_label(self):
        self.assertNotIn("\x00", pc.redact("My\x00Report"))

    def test_content_and_accessibility(self):
        checks = pc.parse_transcript(SAMPLE)
        page = pc.render_html(checks, pc.summarize(checks), "Demo")
        self.assertIn('role="progressbar"', page)
        self.assertIn('name="viewport"', page)
        self.assertIn("No telemetry", page)
        self.assertIn("not</strong> a third-party signature", page)
        self.assertEqual(page.count('<li class="check">'), 4)

    def test_unique_fingerprint(self):
        a = pc.summarize(pc.parse_transcript("INITIALIZE = PASS"))
        b = pc.summarize(pc.parse_transcript("INITIALIZE = FAIL"))
        self.assertNotEqual(a["report_sha256"], b["report_sha256"])

    def test_cli_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "sample.txt"
            out = Path(d) / "report.html"
            inp.write_text(SAMPLE, encoding="utf-8")
            self.assertEqual(pc.main(["--input", str(inp), "--output", str(out)]), 0)
            self.assertIn("Evidence, not", out.read_text(encoding="utf-8"))
            self.assertEqual(pc.main(["--input", str(inp), "--output", str(out)]), 2)

    def test_strict_mode_rejects_failed_log(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "input.txt"
            out = Path(d) / "result.html"
            inp.write_text("INITIALIZE = FAIL\n", encoding="utf-8")
            self.assertEqual(pc.main(["--input", str(inp), "--output", str(out), "--strict"]), 1)
            self.assertTrue(out.exists())

    def test_oversized_input_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "huge.txt"
            out = Path(d) / "result.html"
            inp.write_bytes(b"x" * (pc.MAX_INPUT_BYTES + 1))
            self.assertEqual(pc.main(["--input", str(inp), "--output", str(out)]), 2)
            self.assertFalse(out.exists())

if __name__ == "__main__":
    unittest.main()
