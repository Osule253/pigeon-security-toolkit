"""Non-invasive web input and injection indicator checks."""

import re
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit


SQL_ERROR_PATTERNS = (
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"PostgreSQL.*ERROR",
    r"SQLite/JDBCDriver",
    r"SQLSTATE\[[0-9A-Z]+\]",
    r"Microsoft SQL Server.*Error",
    r"ORA-\d{5}",
)

ERROR_PATTERNS = {
    "SQL_ERROR_DISCLOSURE": SQL_ERROR_PATTERNS,
    "FILE_PATH_DISCLOSURE": (
        r"/etc/passwd",
        r"root:x:0:0:",
        r"boot\.ini",
        r"win\.ini",
    ),
    "COMMAND_ERROR_DISCLOSURE": (
        r"/bin/(?:sh|bash)",
        r"uid=\d+.*gid=\d+",
        r"command not found",
    ),
}


def _finding(category, issue, detail, evidence, recommendation):
    return {
        "id": "PST-F-" + uuid.uuid4().hex[:12].upper(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": "injection",
        "category": category,
        "severity": "INFO",
        "confidence": "LOW",
        "status": "indicator_only",
        "issue": issue,
        "detail": detail,
        "evidence": evidence[:300],
        "recommendation": recommendation,
    }


def inspect_input_surface(url, body="", content_type=""):
    """
    Inspect an already-obtained response.
    Does not send requests or execute supplied input.
    """
    findings = []
    parsed = urlsplit(url)

    parameters = [
        name for name, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True
        )
    ]

    if parameters:
        findings.append(_finding(
            "INPUT_SURFACE",
            "URL parameters detected",
            "The URL exposes query parameters that may process user input.",
            ", ".join(sorted(set(parameters))),
            "Validate inputs server-side and use parameterized database queries."
        ))

    html_forms = re.findall(
        r"<form\b[^>]*>.*?</form>",
        body,
        flags=re.IGNORECASE | re.DOTALL
    )

    if html_forms:
        findings.append(_finding(
            "INPUT_SURFACE",
            "HTML forms detected",
            "Forms provide input surfaces that should receive security review.",
            f"{len(html_forms)} form(s) detected",
            "Apply server-side validation, output encoding, CSRF protection and appropriate authorization."
        ))

    for category, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, body, flags=re.IGNORECASE)

            if match:
                findings.append(_finding(
                    category,
                    "Potential backend error or sensitive path disclosure",
                    "The response contains an error signature associated with sensitive implementation details. This does not prove an exploitable injection vulnerability.",
                    match.group(0),
                    "Disable verbose production errors and review server-side input handling and logging."
                ))
                break

    return {
        "module": "injection",
        "status": "completed",
        "requests_sent": 0,
        "active_probing": False,
        "parameters_found": sorted(set(parameters)),
        "forms_found": len(html_forms),
        "findings": findings,
        "limitations": [
            "No attack payloads were sent.",
            "No commands or files were executed or accessed.",
            "SQLi, XSS, LFI, RFI and command injection are not confirmed by passive indicators.",
            "Authorization testing and controlled validation require separate assessment."
        ],
    }
