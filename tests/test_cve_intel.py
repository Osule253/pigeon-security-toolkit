import json
import unittest
from unittest.mock import patch

from pst_modules.modules.cve_intel import build_cpe, lookup_cves


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class TestCVEIntel(unittest.TestCase):

    def test_supported_cpe_generation(self):
        self.assertEqual(
            build_cpe("OpenSSH", "9.6"),
            "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"
        )

    def test_unsupported_product_rejected(self):
        self.assertIsNone(build_cpe("Unknown", "1.0"))

    def test_invalid_version_rejected(self):
        self.assertIsNone(build_cpe("OpenSSH", "*"))

    def test_lookup_unavailable_is_safe(self):
        with patch(
            "pst_modules.modules.cve_intel.urllib.request.urlopen",
            side_effect=OSError("Network unavailable")
        ):
            result = lookup_cves("OpenSSH", "9.6")

        self.assertEqual(result["status"], "LOOKUP_UNAVAILABLE")
        self.assertFalse(result["exploitation_attempted"])

    def test_cve_match_is_not_confirmed_vulnerability(self):
        payload = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-12345",
                    "descriptions": [{
                        "lang": "en",
                        "value": "Example test vulnerability."
                    }],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH"
                            }
                        }]
                    }
                }
            }]
        }

        with patch(
            "pst_modules.modules.cve_intel.urllib.request.urlopen",
            return_value=FakeResponse(payload)
        ):
            result = lookup_cves("OpenSSH", "9.6")

        self.assertEqual(result["status"], "POTENTIAL_CVE_MATCH")
        self.assertEqual(result["matches"][0]["id"], "CVE-2025-12345")
        self.assertEqual(result["matches"][0]["cvss_score"], 8.1)
        self.assertFalse(result["exploitation_attempted"])


    def test_nvd_match_status_is_review_required(self):
        from pigeon_portscan import assess_exploitability

        result = assess_exploitability(
            22, "SSH", True, "SSH-2.0-OpenSSH_9.6", None
        )

        self.assertEqual(result["status"], "UNDETERMINED")
        self.assertFalse(result["exploitation_attempted"])

    def test_nvd_lookup_result_structure(self):
        result = lookup_cves("UnknownService", "1.0")

        self.assertIn("matches", result)
        self.assertIn("exploitation_attempted", result)
        self.assertFalse(result["exploitation_attempted"])



if __name__ == "__main__":
    unittest.main()
