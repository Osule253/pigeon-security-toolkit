import unittest
from datetime import datetime, timezone

import pst


class PSTFindingTests(unittest.TestCase):

    def test_finding_has_required_fields(self):
        findings = []

        finding = pst.add_finding(
            findings,
            "high",
            "Missing security header",
            "The website does not return the expected header.",
            module="website",
            recommendation="Configure the security header."
        )

        required = {
            "id",
            "timestamp",
            "module",
            "severity",
            "issue",
            "detail",
            "recommendation"
        }

        self.assertTrue(required.issubset(finding.keys()))
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["module"], "website")
        self.assertEqual(len(findings), 1)

    def test_finding_ids_are_unique(self):
        findings = []

        first = pst.add_finding(
            findings, "LOW", "First issue", "First detail"
        )
        second = pst.add_finding(
            findings, "MEDIUM", "Second issue", "Second detail"
        )

        self.assertNotEqual(first["id"], second["id"])
        self.assertTrue(first["id"].startswith("PST-F-"))
        self.assertTrue(second["id"].startswith("PST-F-"))

    def test_timestamp_is_timezone_aware(self):
        findings = []

        finding = pst.add_finding(
            findings, "INFO", "Test issue", "Test detail"
        )

        timestamp = datetime.fromisoformat(finding["timestamp"])

        self.assertIsNotNone(timestamp.tzinfo)
        self.assertEqual(timestamp.utcoffset(), timezone.utc.utcoffset(timestamp))

    def test_severity_is_normalized(self):
        findings = []

        finding = pst.add_finding(
            findings, "medium", "Test issue", "Test detail"
        )

        self.assertEqual(finding["severity"], "MEDIUM")

    def test_invalid_severity_is_rejected(self):
        with self.assertRaises(ValueError):
            pst.add_finding(
                [], "UNKNOWN", "Test issue", "Test detail"
            )

    def test_empty_issue_is_rejected(self):
        with self.assertRaises(ValueError):
            pst.add_finding(
                [], "HIGH", "   ", "Test detail"
            )

    def test_original_four_argument_call_still_works(self):
        findings = []

        finding = pst.add_finding(
            findings, "LOW", "Legacy issue", "Legacy detail"
        )

        self.assertEqual(finding["module"], "website")
        self.assertEqual(finding["recommendation"], "")


if __name__ == "__main__":
    unittest.main()
