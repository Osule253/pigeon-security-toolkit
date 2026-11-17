import io
import unittest
from email.message import Message
from unittest.mock import patch

import pst
from pst_modules.modules.traffic import TrafficRecorder


class FakeResponse:
    def __init__(self):
        self.code = 200
        self.headers = Message()
        self.headers["Content-Type"] = "text/html"
        self.headers["Content-Security-Policy"] = "default-src 'self'"
        self.headers["Set-Cookie"] = "session=secret-value"
        self.headers["X-API-Key"] = "private-key-value"
        self.closed = False

    def geturl(self):
        return "https://example.com/final?token=private#section"

    def read(self, size):
        return b"<html><body>Test page</body></html>"

    def close(self):
        self.closed = True


class WebsiteTrafficIntegrationTests(unittest.TestCase):

    @patch("pst.urllib.request.urlopen")
    def test_website_audit_records_http_metadata(self, mock_urlopen):
        response = FakeResponse()
        mock_urlopen.return_value = response
        recorder = TrafficRecorder()
        capture = {}

        with patch.object(pst, "BASE_DIR", __import__("pathlib").Path("/tmp")):
            with patch("sys.stdout", new_callable=io.StringIO):
                pst.audit_website(
                    "https://example.com",
                    response_capture=capture,
                    traffic_recorder=recorder,
                )

        mock_urlopen.assert_called_once()
        self.assertTrue(response.closed)
        self.assertEqual(len(recorder.events), 1)

        event = recorder.events[0]
        self.assertEqual(event["type"], "HTTP")
        self.assertEqual(event["method"], "GET")
        self.assertEqual(event["status_code"], 200)
        self.assertEqual(event["bytes_received"], len(b"<html><body>Test page</body></html>"))
        self.assertGreaterEqual(event["duration_ms"], 0)

        self.assertEqual(
            event["url"],
            "https://example.com/final",
        )
        self.assertEqual(event["headers"]["Set-Cookie"], "[REDACTED]")
        self.assertEqual(event["headers"]["X-API-Key"], "[REDACTED]")
        self.assertNotIn("private", str(event))
        self.assertNotIn("secret-value", str(event))

        self.assertEqual(capture["http_status"], 200)
        self.assertIn("Test page", capture["body"])

    @patch("pst.urllib.request.urlopen")
    def test_website_audit_without_recorder_still_works(self, mock_urlopen):
        response = FakeResponse()
        mock_urlopen.return_value = response

        with patch.object(pst, "BASE_DIR", __import__("pathlib").Path("/tmp")):
            with patch("sys.stdout", new_callable=io.StringIO):
                pst.audit_website("https://example.com")

        mock_urlopen.assert_called_once()
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
