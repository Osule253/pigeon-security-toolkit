import unittest
import json
import tempfile
from pathlib import Path
import pst


class AssessmentNormalizationTests(unittest.TestCase):

    def test_duplicate_ids_are_replaced(self):
        findings = [
            {"id": "PST-F-AAAAAAAAAAAA", "severity": "HIGH"},
            {"id": "PST-F-AAAAAAAAAAAA", "severity": "LOW"}
        ]

        pst.normalize_assessment_findings(findings)

        self.assertNotEqual(findings[0]["id"], findings[1]["id"])

    def test_malformed_id_is_replaced(self):
        findings = [{"id": "bad-id", "severity": "INFO"}]

        pst.normalize_assessment_findings(findings)

        self.assertRegex(
            findings[0]["id"],
            r"^PST-F-[0-9A-F]{12}$"
        )

    def test_unknown_severity_becomes_info(self):
        findings = [{"severity": "UNKNOWN"}]

        counts = pst.normalize_assessment_findings(findings)

        self.assertEqual(findings[0]["severity"], "INFO")
        self.assertEqual(findings[0]["original_severity"], "UNKNOWN")
        self.assertEqual(counts["INFO"], 1)

    def test_severity_counts_are_correct(self):
        findings = [
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "LOW"},
            {"severity": "CRITICAL"}
        ]

        counts = pst.normalize_assessment_findings(findings)

        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(sum(counts.values()), 4)

    def test_required_fields_are_added(self):
        findings = [{"severity": "MEDIUM"}]

        pst.normalize_assessment_findings(findings)

        required = {
            "id", "timestamp", "module", "severity",
            "issue", "detail", "recommendation"
        }

        self.assertTrue(required.issubset(findings[0].keys()))



    def test_assessment_report_json_round_trip(self):
        findings = [
            {
                "severity": "HIGH",
                "issue": "Test security finding",
                "detail": "Test detail",
                "recommendation": "Test recommendation"
            },
            {
                "severity": "LOW",
                "issue": "Second test finding",
                "detail": "Second detail",
                "recommendation": "Second recommendation"
            }
        ]

        counts = pst.normalize_assessment_findings(findings)

        report = {
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "severity_counts": counts
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "test-assessment.json"
            output.write_text(json.dumps(report, indent=4))

            loaded = json.loads(output.read_text())

        self.assertEqual(len(loaded["findings"]), 2)
        self.assertEqual(loaded["summary"]["total_findings"], 2)
        self.assertEqual(
            loaded["summary"]["severity_counts"]["HIGH"], 1
        )
        self.assertEqual(
            loaded["summary"]["severity_counts"]["LOW"], 1
        )
        self.assertTrue(loaded["findings"][0]["id"].startswith("PST-F-"))
        self.assertIn("timestamp", loaded["findings"][0])

if __name__ == "__main__":
    unittest.main()
