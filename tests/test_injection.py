import unittest

from pst_modules.modules.injection import inspect_input_surface


class InjectionAssessmentTests(unittest.TestCase):

    def test_detects_url_parameters(self):
        result = inspect_input_surface(
            "https://example.com/search?q=test&id=4"
        )
        self.assertEqual(
            result["parameters_found"],
            ["id", "q"]
        )

    def test_detects_html_forms(self):
        result = inspect_input_surface(
            "https://example.com/",
            '<form action="/search"><input name="q"></form>'
        )
        self.assertEqual(result["forms_found"], 1)

    def test_detects_sql_error_disclosure(self):
        result = inspect_input_surface(
            "https://example.com/",
            "SQL syntax error near MySQL"
        )
        self.assertTrue(any(
            item["category"] == "SQL_ERROR_DISCLOSURE"
            for item in result["findings"]
        ))

    def test_detects_sensitive_path_disclosure(self):
        result = inspect_input_surface(
            "https://example.com/",
            "root:x:0:0:root:/root:/bin/bash"
        )
        self.assertTrue(any(
            item["category"] == "FILE_PATH_DISCLOSURE"
            for item in result["findings"]
        ))

    def test_sends_no_network_requests(self):
        result = inspect_input_surface("https://example.com/")
        self.assertEqual(result["requests_sent"], 0)
        self.assertFalse(result["active_probing"])

    def test_finding_structure(self):
        result = inspect_input_surface(
            "https://example.com/?id=1"
        )
        finding = result["findings"][0]

        for field in (
            "id", "timestamp", "module", "severity",
            "confidence", "status", "issue",
            "detail", "evidence", "recommendation"
        ):
            self.assertIn(field, finding)


if __name__ == "__main__":
    unittest.main()
