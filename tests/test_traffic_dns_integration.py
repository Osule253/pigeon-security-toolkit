import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pst


class DNSTrafficIntegrationTests(unittest.TestCase):
    def test_unified_assessment_records_existing_dns_answers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / "pigeon_portscan.py").write_text("# Mock scanner placeholder")
            dns_calls = []

            def fake_dns_query(domain, record_type):
                dns_calls.append((domain, record_type))

                answers = {
                    "A": [{"data": "192.0.2.10"}],
                    "AAAA": [{"data": "2001:db8::10"}],
                    "TXT": [],
                    "MX": [],
                    "NS": [],
                    "CNAME": [],
                    "CAA": [],
                }

                return {
                    "Status": 0,
                    "Answer": answers.get(record_type, []),
                }

            def fake_website(url, response_capture=None, traffic_recorder=None):
                if response_capture is not None:
                    response_capture.update({
                        "final_url": url,
                        "http_status": 200,
                        "content_type": "text/html",
                        "body": "<html><body>Test page</body></html>",
                    })

                if traffic_recorder:
                    traffic_recorder.record_http(
                        "GET", url, status_code=200,
                        bytes_received=100
                    )

                (base / "pigeon-website-audit.json").write_text(
                    json.dumps({"findings": []})
                )

            def fake_ssl(domain, port):
                (base / "pigeon-ssl-report.json").write_text(
                    json.dumps({
                        "connection_successful": True,
                        "certificate_verified": True,
                        "days_until_expiry": 90,
                    })
                )

            def fake_subprocess(*args, **kwargs):
                port_path = Path(args[0][args[0].index("--output") + 1])
                port_path.write_text(json.dumps({"results": []}))

                class Result:
                    returncode = 0
                    stderr = ""

                return Result()

            with (
                patch.object(pst, "BASE_DIR", base),
                patch.object(pst, "dns_query", side_effect=fake_dns_query),
                patch.object(pst, "audit_website", side_effect=fake_website),
                patch.object(pst, "inspect_ssl", side_effect=fake_ssl),
                patch.object(pst.subprocess, "run", side_effect=fake_subprocess),
            ):
                result = pst.unified_assessment(
                    "example.com", ["--authorized"]
                )

            self.assertEqual(result, 0)

            report = json.loads(
                (base / "pigeon-assessment.json").read_text()
            )

            traffic = report["modules"]["traffic"]
            dns_events = [
                event for event in traffic["events"]
                if event["type"] == "DNS"
            ]

            self.assertEqual(len(dns_events), 1)
            self.assertEqual(dns_events[0]["hostname"], "example.com")
            self.assertEqual(
                dns_events[0]["addresses"],
                ["192.0.2.10", "2001:db8::10"],
            )

            self.assertEqual(
                sum(1 for domain, _ in dns_calls if domain == "example.com"),
                len(pst.DNS_TYPES),
            )
            self.assertIn(("_dmarc.example.com", "TXT"), dns_calls)

            self.assertEqual(traffic["summary"]["event_types"]["DNS"], 1)
            self.assertEqual(traffic["summary"]["event_types"]["HTTP"], 1)
            self.assertFalse(traffic["payload_capture"])


if __name__ == "__main__":
    unittest.main()
