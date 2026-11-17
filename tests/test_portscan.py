import unittest

from pigeon_portscan import assess_exploitability


class TestPortExploitability(unittest.TestCase):

    def test_unknown_service_is_undetermined(self):
        result = assess_exploitability(12345, "UNKNOWN", False)
        self.assertEqual(result["status"], "UNDETERMINED")
        self.assertFalse(result["exploitation_attempted"])

    def test_ssh_is_not_automatically_vulnerable(self):
        result = assess_exploitability(22, "SSH", True)
        self.assertEqual(result["status"], "UNDETERMINED")
        self.assertEqual(result["confidence"], "LOW")

    def test_database_exposure_is_flagged_not_confirmed(self):
        result = assess_exploitability(3306, "MYSQL", True)
        self.assertEqual(result["status"], "EXPOSURE_CONCERN")
        self.assertFalse(result["cve_matches"])

    def test_telnet_exposure_is_flagged(self):
        result = assess_exploitability(23, "TELNET", True)
        self.assertEqual(result["status"], "EXPOSURE_CONCERN")

    def test_banner_is_recorded_as_evidence(self):
        result = assess_exploitability(
            22, "SSH", True, banner="SSH-2.0-OpenSSH_9.0"
        )
        self.assertIn("A service response banner was observed.", result["evidence"])
        self.assertEqual(result["status"], "UNDETERMINED")

    def test_tls_metadata_is_recorded(self):
        result = assess_exploitability(
            443, "HTTPS", True,
            tls={"version": "TLSv1.3", "cipher": "EXAMPLE"}
        )
        self.assertEqual(result["tls_version"], "TLSv1.3")
        self.assertFalse(result["exploitation_attempted"])


if __name__ == "__main__":
    unittest.main()
