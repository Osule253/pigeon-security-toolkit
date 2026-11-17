"""Non-invasive CVE intelligence lookup using the NVD API."""

import json
import urllib.parse
import urllib.request
import urllib.error


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CPE_PRODUCTS = {
    "OpenSSH": ("a", "openbsd", "openssh"),
    "vsFTPd": ("a", "vsftpd", "vsftpd"),
    "ProFTPD": ("a", "proftpd", "proftpd"),
    "Exim": ("a", "exim", "exim"),
}


def build_cpe(product, version):
    """Build a CPE candidate only for explicitly supported products."""
    if product not in CPE_PRODUCTS or not version:
        return None

    if any(char in version for char in "*?\\:"):
        return None

    part, vendor, name = CPE_PRODUCTS[product]

    return (
        f"cpe:2.3:{part}:{vendor}:{name}:"
        f"{version}:*:*:*:*:*:*:*"
    )


def lookup_cves(product, version, timeout=8):
    """Retrieve potential CVE matches. Never performs exploitation."""

    result = {
        "status": "UNDETERMINED",
        "product": product,
        "version": version,
        "cpe": None,
        "matches": [],
        "error": None,
        "exploitation_attempted": False,
        "source": NVD_API,
    }

    cpe = build_cpe(product, version)

    if not cpe:
        result["error"] = "Unsupported product or invalid version."
        return result

    result["cpe"] = cpe

    params = urllib.parse.urlencode({
        "cpeName": cpe,
        "resultsPerPage": 20,
    })

    request = urllib.request.Request(
        f"{NVD_API}?{params}",
        headers={
            "User-Agent": "PigeonSecurityToolkit/1.0",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))

        for entry in data.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            descriptions = cve.get("descriptions", [])

            description = next(
                (
                    item.get("value", "")
                    for item in descriptions
                    if item.get("lang") == "en"
                ),
                "",
            )

            score = None
            severity = None
            metrics = cve.get("metrics", {})

            for metric_name in (
                "cvssMetricV40",
                "cvssMetricV31",
                "cvssMetricV30",
                "cvssMetricV2",
            ):
                entries = metrics.get(metric_name, [])
                if entries:
                    cvss = entries[0].get("cvssData", {})
                    score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity") or entries[0].get(
                        "baseSeverity"
                    )
                    break

            result["matches"].append({
                "id": cve.get("id"),
                "description": description[:1200],
                "cvss_score": score,
                "severity": severity,
                "url": (
                    f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}"
                    if cve.get("id") else None
                ),
            })

        result["status"] = (
            "POTENTIAL_CVE_MATCH"
            if result["matches"]
            else "NO_MATCH_RETURNED"
        )

    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result["error"] = str(exc)
        result["status"] = "LOOKUP_UNAVAILABLE"

    except (ValueError, KeyError, TypeError) as exc:
        result["error"] = str(exc)
        result["status"] = "LOOKUP_UNAVAILABLE"

    return result
