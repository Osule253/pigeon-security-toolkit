import unittest

from pst_modules.modules.traffic import (
    TrafficRecorder,
    redact_headers,
    sanitize_url,
)


class TestTrafficAnalyzer(unittest.TestCase):

    def setUp(self):
        self.recorder = TrafficRecorder()

    def test_dns_records_only_valid_addresses(self):
        event = self.recorder.record_dns(
            "example.test",
            ["192.0.2.10", "invalid", "2001:db8::1"]
        )
        self.assertEqual(
            event["addresses"],
            ["192.0.2.10", "2001:db8::1"]
        )

    def test_connection_metadata(self):
        event = self.recorder.record_connection(
            "192.0.2.10",
            443,
            bytes_sent=200,
            bytes_received=500,
            duration_ms=35
        )
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["bytes_received"], 500)

    def test_invalid_destination_rejected(self):
        with self.assertRaises(ValueError):
            self.recorder.record_connection("invalid", 443)

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            self.recorder.record_connection("192.0.2.10", 70000)

    def test_http_metadata(self):
        event = self.recorder.record_http(
            "GET",
            "https://example.test/index",
            status_code=200,
            duration_ms=40,
            bytes_received=1200
        )
        self.assertEqual(event["method"], "GET")
        self.assertEqual(event["status_code"], 200)
        self.assertEqual(event["bytes_received"], 1200)

    def test_sensitive_headers_redacted(self):
        headers = redact_headers({
            "Authorization": "Bearer secret",
            "Cookie": "session=secret",
            "Content-Type": "application/json"
        })
        self.assertEqual(headers["Authorization"], "[REDACTED]")
        self.assertEqual(headers["Cookie"], "[REDACTED]")
        self.assertEqual(
            headers["Content-Type"],
            "application/json"
        )

    def test_url_credentials_and_query_removed(self):
        safe = sanitize_url(
            "https://user:password@example.test/page?token=secret#section"
        )
        self.assertEqual(safe, "https://example.test/page")
        self.assertNotIn("password", safe)
        self.assertNotIn("secret", safe)

    def test_summary_totals(self):
        self.recorder.record_connection(
            "192.0.2.10", 443,
            bytes_sent=100,
            bytes_received=200
        )
        self.recorder.record_http(
            "GET",
            "https://example.test/",
            status_code=200,
            bytes_received=300
        )

        summary = self.recorder.summary()
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["bytes_sent"], 100)
        self.assertEqual(summary["bytes_received"], 500)

    def test_export_marks_payload_capture_disabled(self):
        report = self.recorder.export()
        self.assertFalse(report["payload_capture"])
        self.assertEqual(
            report["capture_scope"],
            "PST_REPORTED_TRAFFIC_METADATA"
        )

    def test_negative_bytes_rejected(self):
        with self.assertRaises(ValueError):
            self.recorder.record_http(
                "GET", "https://example.test", bytes_received=-1
            )


    def test_export_preserves_http_event_metadata(self):
        self.recorder.record_http(
            "GET",
            "https://example.test/page?token=secret",
            status_code=200,
            duration_ms=25,
            bytes_received=128,
            headers={"Authorization": "Bearer secret"},
        )

        report = self.recorder.export()
        event = report["events"][0]

        self.assertEqual(event["type"], "HTTP")
        self.assertEqual(event["url"], "https://example.test/page")
        self.assertEqual(event["status_code"], 200)
        self.assertEqual(event["bytes_received"], 128)
        self.assertEqual(event["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(report["summary"]["event_count"], 1)
        self.assertEqual(report["summary"]["http_statuses"], {"200": 1})
        self.assertEqual(report["summary"]["bytes_received"], 128)

    def test_export_summary_matches_multiple_events(self):
        self.recorder.record_dns("example.test", ["192.0.2.10"])
        self.recorder.record_connection(
            "192.0.2.10", 443, bytes_sent=50, bytes_received=75
        )
        self.recorder.record_http(
            "GET", "https://example.test/",
            status_code=200, bytes_received=100,
        )

        report = self.recorder.export()

        self.assertEqual(report["summary"]["event_count"], 3)
        self.assertEqual(report["summary"]["event_types"]["DNS"], 1)
        self.assertEqual(report["summary"]["event_types"]["CONNECTION"], 1)
        self.assertEqual(report["summary"]["event_types"]["HTTP"], 1)
        self.assertEqual(report["summary"]["bytes_sent"], 50)
        self.assertEqual(report["summary"]["bytes_received"], 175)
        self.assertFalse(report["payload_capture"])


if __name__ == "__main__":
    unittest.main()
