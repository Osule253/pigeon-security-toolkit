#!/usr/bin/env python3

import sys
import uuid
import ssl
import re
import json
import socket
import hashlib
import subprocess
import urllib.request
import urllib.parse
import urllib.error
import time
from pst_modules.modules.traffic import TrafficRecorder

from pathlib import Path
from datetime import datetime, timezone

VERSION = "1.9.1"
BASE_DIR = Path(__file__).resolve().parent
DNS_RESOLVER = "https://cloudflare-dns.com/dns-query"

DNS_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "NS": 2,
    "TXT": 16,
    "CNAME": 5,
    "CAA": 257
}


def banner():
    print("=" * 58)
    print("             PIGEON SECURITY TOOLKIT")
    print(f"                    PST {VERSION}")
    print("             SECURE. INSPECT. DEFEND.")
    print("       Pigeon Techies | pigeontechies.com")
    print("=" * 58)


def help_menu():
    banner()
    print("""
AVAILABLE COMMANDS

  hash FILE
      Calculate SHA-256 file hash.

  dns DOMAIN
      Inspect public DNS records.

  audit URL
      Audit website security headers and cookies.

  scan TARGET [OPTIONS]
      Run Pigeon PortScan.

  assess DOMAIN --authorized [--ports PORTS]
      Run unified defensive security assessment.

  history
      Display previous scans.

  show SCAN_ID
      Display a saved scan.

  compare OLD_ID NEW_ID
      Compare two saved scans.

  --version
      Display toolkit version.

  --help
      Display this help menu.

  ssl DOMAIN [PORT]
      Inspect SSL/TLS certificates and encryption.

EXAMPLES

  python pst.py hash document.pdf
  python pst.py dns example.com
  python pst.py audit https://example.com
  python pst.py ssl example.com
  python pst.py history
""")


def calculate_sha256(file_path):
    path = Path(file_path).expanduser()

    if not path.exists():
        print(f"ERROR: File not found: {path}")
        sys.exit(1)

    if not path.is_file():
        print("ERROR: The supplied path is not a file.")
        sys.exit(1)

    digest = hashlib.sha256()

    try:
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)

        print("\nSHA-256 FILE HASH")
        print("-" * 58)
        print(f"File:   {path}")
        print(f"SHA256: {digest.hexdigest()}")
        print("-" * 58)
        print("Hash calculation completed.")

    except OSError as error:
        print(f"ERROR: Could not read file: {error}")
        sys.exit(1)


def validate_domain(domain):
    domain = domain.strip().rstrip(".")

    if not domain or "://" in domain or "/" in domain:
        raise ValueError("Enter a domain without a URL or path.")

    try:
        domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid domain name.")

    if len(domain) > 253:
        raise ValueError("Domain name is too long.")

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("Enter a fully qualified domain.")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
        ):
            raise ValueError("Invalid domain name.")

    return domain


def dns_query(domain, record_type):
    params = urllib.parse.urlencode({
        "name": domain,
        "type": record_type
    })

    request = urllib.request.Request(
        f"{DNS_RESOLVER}?{params}",
        headers={
            "Accept": "application/dns-json",
            "User-Agent": "PigeonSecurityToolkit/1.7.0"
        }
    )

    context = ssl.create_default_context()

    with urllib.request.urlopen(
        request,
        timeout=10,
        context=context
    ) as response:
        return json.loads(response.read().decode("utf-8"))


def inspect_dns(domain):
    try:
        domain = validate_domain(domain)
    except ValueError as error:
        print(f"ERROR: {error}")
        sys.exit(2)

    print("\nPIGEON DNS INSPECTOR")
    print("-" * 58)
    print(f"Domain: {domain}")
    print("Resolver: Cloudflare DNS over HTTPS")
    print("-" * 58)

    for record_type, record_number in DNS_TYPES.items():
        print(f"\n[{record_type} RECORDS]")

        try:
            result = dns_query(domain, record_type)
            status = result.get("Status", -1)

            if status == 3:
                print("Domain does not exist (NXDOMAIN).")
                break

            if status != 0:
                print(f"DNS response status: {status}")
                continue

            answers = result.get("Answer", [])
            matching = [
                answer for answer in answers
                if answer.get("type") == record_number
            ]

            if not matching:
                print("No records returned.")
                continue

            for answer in matching:
                print(f"  Value: {answer.get('data', '')}")
                print(f"  TTL:   {answer.get('TTL', 'Unknown')} seconds")

        except urllib.error.HTTPError as error:
            print(f"HTTP error: {error.code}")
        except urllib.error.URLError as error:
            print(f"Network error: {error.reason}")
        except (TimeoutError, socket.timeout):
            print("DNS request timed out.")
        except (ValueError, json.JSONDecodeError):
            print("Could not interpret DNS response.")
        except Exception as error:
            print(f"Inspection error: {error}")

    print("\n" + "-" * 58)
    print("DNS inspection completed.")


def validate_url(url):
    url = url.strip()

    if not url:
        raise ValueError("Enter a website URL.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urllib.parse.urlsplit(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing login credentials are not supported.")

    try:
        parsed.hostname.encode("idna")
        parsed.port
    except (UnicodeError, ValueError):
        raise ValueError("Invalid hostname or port.")

    return url


def add_finding(
    findings,
    severity,
    issue,
    detail,
    module="website",
    recommendation=""
):
    severity = str(severity).strip().upper()

    allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    if severity not in allowed:
        raise ValueError(f"Invalid finding severity: {severity}")

    if not str(issue).strip():
        raise ValueError("Finding issue cannot be empty.")

    finding = {
        "id": "PST-F-" + uuid.uuid4().hex[:12].upper(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": str(module).strip() or "website",
        "severity": severity,
        "issue": str(issue).strip(),
        "detail": str(detail),
        "recommendation": str(recommendation)
    }

    findings.append(finding)
    return finding


def normalize_assessment_findings(findings):
    allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    counts = {level: 0 for level in allowed}
    used_ids = set()

    for item in findings:
        original_id = str(item.get("id", "")).strip()

        valid_id = (
            len(original_id) == 18
            and original_id.startswith("PST-F-")
            and all(c in "0123456789ABCDEF" for c in original_id[6:])
        )

        if not valid_id or original_id in used_ids:
            original_id = "PST-F-" + uuid.uuid4().hex[:12].upper()

        while original_id in used_ids:
            original_id = "PST-F-" + uuid.uuid4().hex[:12].upper()

        item["id"] = original_id
        used_ids.add(original_id)

        original_level = str(item.get("severity", "INFO")).strip().upper()

        if original_level not in allowed:
            item["original_severity"] = original_level
            level = "INFO"
        else:
            level = original_level

        item["severity"] = level
        item.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        item.setdefault("module", "assessment")
        item.setdefault("issue", "Unspecified security finding")
        item.setdefault("detail", "")
        item.setdefault("recommendation", "")

        item["module"] = str(item["module"]).strip() or "assessment"
        item["issue"] = str(item["issue"]).strip() or "Unspecified security finding"

        counts[level] += 1

    return counts


def inspect_cookies(headers, findings):
    cookies = headers.get_all("Set-Cookie") or []

    print("\n[COOKIE SECURITY]")

    if not cookies:
        print("No Set-Cookie headers were returned.")
        return

    for index, cookie in enumerate(cookies, 1):
        parts = [part.strip() for part in cookie.split(";")]
        name = parts[0].split("=", 1)[0]
        flags = {part.lower() for part in parts[1:]}

        secure = any(flag == "secure" for flag in flags)
        httponly = any(flag == "httponly" for flag in flags)
        samesite = any(flag.startswith("samesite=") for flag in flags)

        print(f"Cookie {index}: {name}")
        print(f"  Secure:   {'Yes' if secure else 'No'}")
        print(f"  HttpOnly: {'Yes' if httponly else 'No'}")
        print(f"  SameSite: {'Yes' if samesite else 'No'}")

        if not secure:
            add_finding(
                findings, "MEDIUM",
                f"Cookie {name} missing Secure",
                "The cookie does not explicitly require HTTPS."
            )

        if not httponly:
            add_finding(
                findings, "LOW",
                f"Cookie {name} missing HttpOnly",
                "JavaScript may be able to access this cookie."
            )

        if not samesite:
            add_finding(
                findings, "LOW",
                f"Cookie {name} missing SameSite",
                "Cross-site cookie behavior is not explicitly restricted."
            )

        if any(flag == "samesite=none" for flag in flags) and not secure:
            add_finding(
                findings, "HIGH",
                f"Cookie {name} uses SameSite=None without Secure",
                "Modern browsers require Secure for SameSite=None cookies."
            )


def audit_website(raw_url, response_capture=None, traffic_recorder=None):
    try:
        url = validate_url(raw_url)
    except ValueError as error:
        print(f"ERROR: {error}")
        sys.exit(2)

    print("\nPIGEON WEBSITE SECURITY AUDITOR")
    print("-" * 58)
    print(f"Target: {url}")
    print("Method: Single HTTP GET request")
    print("-" * 58)

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PigeonSecurityToolkit/1.7.0",
            "Accept": "text/html,application/xhtml+xml,*/*"
        },
        method="GET"
    )

    request_started = time.perf_counter()
    try:
        try:
            response = urllib.request.urlopen(
                request,
                timeout=12,
                context=ssl.create_default_context()
            )
        except urllib.error.HTTPError as error:
            response = error

        status = response.code
        final_url = response.geturl()
        headers = response.headers

        # Read only a small response sample for passive inspection.
        body_sample = response.read(4096)

        if response_capture is not None:
            response_capture["final_url"] = final_url
            response_capture["http_status"] = status
            response_capture["content_type"] = headers.get("Content-Type", "")
            response_capture["body"] = body_sample.decode(
                "utf-8", errors="replace"
            )

        if traffic_recorder is not None:
            duration_ms = (time.perf_counter() - request_started) * 1000
            traffic_recorder.record_http(
                method="GET",
                url=final_url,
                status_code=status,
                duration_ms=round(duration_ms, 2),
                bytes_received=len(body_sample),
                headers=headers,
            )

        response.close()

    except urllib.error.URLError as error:
        print(f"CONNECTION ERROR: {error.reason}")
        return
    except (TimeoutError, socket.timeout):
        print("ERROR: Website request timed out.")
        return
    except ssl.SSLError as error:
        print(f"TLS ERROR: {error}")
        return
    except Exception as error:
        print(f"AUDIT ERROR: {error}")
        return

    findings = []

    print(f"HTTP status: {status}")
    print(f"Final URL:   {final_url}")

    final_scheme = urllib.parse.urlsplit(final_url).scheme.lower()
    original_scheme = urllib.parse.urlsplit(url).scheme.lower()

    print("\n[TRANSPORT SECURITY]")

    if final_scheme == "https":
        print("HTTPS: Active")
    else:
        print("HTTPS: Not active")
        add_finding(
            findings, "HIGH",
            "Website is not using HTTPS",
            "The final page URL uses unencrypted HTTP."
        )

    if original_scheme == "http" and final_scheme == "https":
        print("HTTP redirect: HTTPS destination reached")
    elif original_scheme == "http":
        print("HTTP redirect: HTTPS redirect not observed")

    if status >= 500:
        add_finding(
            findings, "MEDIUM",
            "Server returned an error response",
            f"HTTP status {status} was returned."
        )

    print("\n[SECURITY HEADERS]")

    checks = [
        (
            "Content-Security-Policy",
            "MEDIUM",
            "A Content Security Policy was not returned."
        ),
        (
            "X-Content-Type-Options",
            "LOW",
            "Consider setting X-Content-Type-Options: nosniff."
        ),
        (
            "Referrer-Policy",
            "LOW",
            "A Referrer-Policy header was not returned."
        ),
        (
            "Permissions-Policy",
            "LOW",
            "A Permissions-Policy header was not returned."
        )
    ]

    for header, severity, message in checks:
        value = headers.get(header)

        if value:
            print(f"{header}: PRESENT")
        else:
            print(f"{header}: MISSING")
            add_finding(findings, severity, f"Missing {header}", message)

    csp = headers.get("Content-Security-Policy", "")
    x_frame = headers.get("X-Frame-Options", "")

    if x_frame:
        print(f"X-Frame-Options: {x_frame}")
    elif "frame-ancestors" in csp.lower():
        print("Frame protection: CSP frame-ancestors present")
    else:
        print("Frame protection: NOT DETECTED")
        add_finding(
            findings, "MEDIUM",
            "Frame protection not detected",
            "Consider X-Frame-Options or CSP frame-ancestors."
        )

    if final_scheme == "https":
        hsts = headers.get("Strict-Transport-Security")

        if hsts:
            print(f"HSTS: PRESENT ({hsts})")
            if not re.search(r"max-age=(?!0\\b)\\d+", hsts, re.I):
                add_finding(
                    findings, "MEDIUM",
                    "HSTS max-age may be missing or zero",
                    "Review the Strict-Transport-Security max-age directive."
                )
        else:
            print("HSTS: MISSING")
            add_finding(
                findings, "MEDIUM",
                "Missing Strict-Transport-Security",
                "Consider enabling HSTS after confirming HTTPS works."
            )
    else:
        print("HSTS: Not assessed because final URL is not HTTPS.")

    print("\n[INFORMATION DISCLOSURE]")

    server = headers.get("Server")
    powered = headers.get("X-Powered-By")

    if server:
        print(f"Server: {server}")
        add_finding(
            findings, "INFO",
            "Server header disclosed",
            f"Server header: {server}"
        )
    else:
        print("Server: Not disclosed")

    if powered:
        print(f"X-Powered-By: {powered}")
        add_finding(
            findings, "LOW",
            "Technology disclosure",
            f"X-Powered-By: {powered}"
        )
    else:
        print("X-Powered-By: Not disclosed")

    inspect_cookies(headers, findings)

    counts = {
        level: sum(
            1 for finding in findings
            if finding["severity"] == level
        )
        for level in ("HIGH", "MEDIUM", "LOW", "INFO")
    }

    print("\n[AUDIT FINDINGS]")
    print("-" * 58)

    if not findings:
        print("No findings from the checks performed.")
    else:
        for finding in findings:
            print(
                f"[{finding['severity']}] "
                f"{finding['issue']}"
            )
            print(f"  {finding['detail']}")

    print("\nSUMMARY")
    for level, count in counts.items():
        print(f"{level:<10} {count}")

    report = {
        "tool": "Pigeon Security Toolkit",
        "version": VERSION,
        "audit_time": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "final_url": final_url,
        "http_status": status,
        "findings": findings,
        "summary": counts
    }

    report_path = BASE_DIR / "pigeon-website-audit.json"

    try:
        report_path.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8"
        )
        print(f"\nJSON report saved: {report_path.name}")
    except OSError as error:
        print(f"Could not save report: {error}")

    print("\nAudit completed.")
    print("Findings are configuration indicators, not proof of vulnerabilities.")



def save_ssl_report(report):
    report_path = BASE_DIR / "pigeon-ssl-report.json"

    try:
        report_path.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8"
        )
        print(f"\nJSON report saved: {report_path.name}")
    except OSError as error:
        print(f"Could not save SSL report: {error}")


def format_certificate_name(name):
    parts = []

    for group in name or ():
        for key, value in group:
            parts.append(f"{key}={value}")

    return ", ".join(parts) if parts else "Not available"


def inspect_ssl(raw_domain, raw_port="443"):
    try:
        domain = validate_domain(raw_domain)
        port = int(raw_port)

        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

    except ValueError as error:
        print(f"ERROR: {error}")
        sys.exit(2)

    print("\nPIGEON SSL/TLS INSPECTOR")
    print("-" * 58)
    print(f"Domain: {domain}")
    print(f"Port:   {port}")
    print("Certificate verification: ENABLED")
    print("-" * 58)

    report = {
        "tool": "Pigeon Security Toolkit",
        "version": VERSION,
        "inspection_time": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "port": port,
        "certificate_verified": False,
        "connection_successful": False
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, port),
            timeout=10
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=domain
            ) as tls_socket:

                certificate = tls_socket.getpeercert()
                certificate_der = tls_socket.getpeercert(
                    binary_form=True
                )

                if not certificate or not certificate_der:
                    raise ssl.SSLError(
                        "Server did not provide a readable certificate."
                    )

                tls_version = tls_socket.version()
                cipher = tls_socket.cipher()

                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")

                expiry_timestamp = (
                    ssl.cert_time_to_seconds(not_after)
                    if not_after else None
                )

                days_remaining = (
                    int((expiry_timestamp - __import__("time").time()) / 86400)
                    if expiry_timestamp is not None else None
                )

                sans = [
                    value
                    for kind, value in certificate.get(
                        "subjectAltName", []
                    )
                    if kind == "DNS"
                ]

                fingerprint = hashlib.sha256(
                    certificate_der
                ).hexdigest()

                subject = format_certificate_name(
                    certificate.get("subject")
                )

                issuer = format_certificate_name(
                    certificate.get("issuer")
                )

                report.update({
                    "connection_successful": True,
                    "certificate_verified": True,
                    "hostname_verified": True,
                    "tls_version": tls_version,
                    "cipher": {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2]
                    } if cipher else None,
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "days_until_expiry": days_remaining,
                    "subject_alternative_names": sans,
                    "sha256_fingerprint": fingerprint
                })

                print("[CONNECTION]")
                print("Connection: SUCCESS")
                print("Certificate chain: VERIFIED")
                print("Hostname: VERIFIED")

                print("\n[TLS INFORMATION]")
                print(f"TLS version: {tls_version}")

                if cipher:
                    print(f"Cipher:      {cipher[0]}")
                    print(f"Cipher bits: {cipher[2]}")

                print("\n[CERTIFICATE INFORMATION]")
                print(f"Subject: {subject}")
                print(f"Issuer:  {issuer}")
                print(f"Valid from:  {not_before or 'Unknown'}")
                print(f"Valid until: {not_after or 'Unknown'}")

                if days_remaining is not None:
                    print(f"Days until expiry: {days_remaining}")

                    if days_remaining < 0:
                        print("WARNING: Certificate has expired.")
                    elif days_remaining <= 30:
                        print("WARNING: Certificate expires within 30 days.")
                    else:
                        print("Certificate expiry: OK")

                print("\n[SUBJECT ALTERNATIVE NAMES]")

                if sans:
                    for name in sans:
                        print(f"  {name}")
                else:
                    print("No DNS SAN entries returned.")

                print("\n[CERTIFICATE FINGERPRINT]")
                print(f"SHA-256: {fingerprint}")

    except ssl.SSLCertVerificationError as error:
        message = f"Certificate verification failed: {error}"
        report["error"] = message
        print("\n[VERIFICATION FAILED]")
        print(message)

    except (socket.timeout, TimeoutError):
        message = "Connection timed out."
        report["error"] = message
        print(f"\nERROR: {message}")

    except socket.gaierror as error:
        message = f"DNS resolution failed: {error}"
        report["error"] = message
        print(f"\nERROR: {message}")

    except ConnectionRefusedError:
        message = "Connection refused by the server."
        report["error"] = message
        print(f"\nERROR: {message}")

    except (ssl.SSLError, OSError) as error:
        message = str(error)
        report["error"] = message
        print(f"\nTLS/CONNECTION ERROR: {message}")

    except Exception as error:
        message = str(error)
        report["error"] = message
        print(f"\nINSPECTION ERROR: {message}")

    save_ssl_report(report)
    print("\nSSL/TLS inspection completed.")




def unified_assessment(raw_domain, options):
    import contextlib
    import io
    import json
    import subprocess
    import sys
    from pst_modules.modules.injection import inspect_input_surface

    if "--authorized" not in options:
        print("Permission required. Use --authorized only on systems you own or have permission to assess.")
        return 2

    domain = validate_domain(raw_domain)
    if not domain:
        print("Invalid domain.")
        return 2

    ports = "22,80,443,8080,8443"
    if "--ports" in options:
        try:
            ports = options[options.index("--ports") + 1]
        except IndexError:
            print("Missing port list.")
            return 2

    findings = []
    observations = []
    traffic_recorder = TrafficRecorder()

    report = {
        "tool": "Pigeon Security Toolkit",
        "version": VERSION,
        "target": domain,
        "assessment_type": "authorized",
        "modules": {},
        "findings": findings,
        "service_observations": observations
    }

    print("\nPIGEON SECURITY TOOLKIT")
    print("UNIFIED SECURITY ASSESSMENT 1.9.1")
    print("=" * 55)
    print("Target:", domain)

    # DNS
    print("\n[1/5] DNS and email security inspection")

    dns = {}
    try:
        for record_type in DNS_TYPES:
            result = dns_query(domain, record_type)
            answers = result.get("Answer", []) if isinstance(result, dict) else []
            dns[record_type] = answers

        # Record DNS metadata from the answers already retrieved.
        resolved_addresses = []
        for record_type in ("A", "AAAA"):
            for answer in dns.get(record_type, []):
                address = answer.get("data", "")
                if address:
                    resolved_addresses.append(address)

        traffic_recorder.record_dns(domain, resolved_addresses)

        dns["status"] = "completed"
        report["modules"]["dns"] = dns

        txt_records = [
            str(item.get("data", "")).strip('"')
            for item in dns.get("TXT", [])
        ]

        spf_records = [
            item for item in txt_records
            if item.lower().startswith("v=spf1")
        ]

        dmarc_result = dns_query("_dmarc." + domain, "TXT")
        dmarc_answers = (
            dmarc_result.get("Answer", [])
            if isinstance(dmarc_result, dict) else []
        )
        dmarc_records = [
            str(item.get("data", "")).strip('"')
            for item in dmarc_answers
            if str(item.get("data", "")).strip('"').lower().startswith("v=dmarc1")
        ]

        email_security = {
            "spf": {
                "records_found": len(spf_records),
                "records": spf_records
            },
            "dmarc": {
                "records_found": len(dmarc_records),
                "records": dmarc_records
            },
            "caa": {
                "records_found": len(dns.get("CAA", [])),
                "records": dns.get("CAA", [])
            }
        }

        email_security["status"] = "completed"
        report["modules"]["email_security"] = email_security

        if not spf_records:
            findings.append({
                "module": "dns",
                "severity": "MEDIUM",
                "issue": "SPF record not detected",
                "detail": "No SPF TXT record was found at the domain.",
                "recommendation": "Publish an SPF policy containing all legitimate sending services."
            })
        elif len(spf_records) > 1:
            findings.append({
                "module": "dns",
                "severity": "MEDIUM",
                "issue": "Multiple SPF records detected",
                "detail": "Multiple SPF policies can cause SPF evaluation errors.",
                "recommendation": "Combine authorized senders into one SPF record."
            })
        elif "+all" in spf_records[0].lower():
            findings.append({
                "module": "dns",
                "severity": "HIGH",
                "issue": "Permissive SPF policy",
                "detail": "The SPF record contains +all.",
                "recommendation": "Replace the permissive policy after validating legitimate mail senders."
            })
        elif "~all" in spf_records[0].lower():
            findings.append({
                "module": "dns",
                "severity": "INFO",
                "issue": "SPF softfail policy",
                "detail": "The SPF record ends with a softfail mechanism.",
                "recommendation": "Consider -all after confirming all legitimate senders are included."
            })

        if not dmarc_records:
            findings.append({
                "module": "dns",
                "severity": "MEDIUM",
                "issue": "DMARC record not detected",
                "detail": "No DMARC TXT record was found at _dmarc." + domain,
                "recommendation": "Publish a DMARC policy, starting with p=none and monitoring reports."
            })
        else:
            dmarc = dmarc_records[0].lower()
            if "p=none" in dmarc:
                findings.append({
                    "module": "dns",
                    "severity": "INFO",
                    "issue": "DMARC monitoring policy",
                    "detail": "DMARC is present with p=none.",
                    "recommendation": "Review reports and consider quarantine or reject when legitimate mail is validated."
                })

        if not dns.get("CAA"):
            findings.append({
                "module": "dns",
                "severity": "INFO",
                "issue": "CAA records not detected",
                "detail": "No CAA record was returned.",
                "recommendation": "Consider restricting certificate issuance to your chosen certificate authorities."
            })

        print("DNS and email security inspection completed.")

    except Exception as exc:
        report["modules"]["dns"] = {"error": str(exc)}
        report["modules"]["email_security"] = {"error": str(exc)}
        print("DNS inspection error:", exc)

    # Website
    print("\n[2/5] Website security audit")

    website_path = BASE_DIR / "pigeon-website-audit.json"
    website_response = {}

    try:
        if website_path.exists():
            website_path.unlink()

        with contextlib.redirect_stdout(io.StringIO()):
            audit_website(
                "https://" + domain,
                response_capture=website_response,
                traffic_recorder=traffic_recorder,
            )

        if website_path.exists():
            website = json.loads(website_path.read_text())
            website["status"] = "completed"
            report["modules"]["website"] = website

            # Passive injection and input-surface inspection.
            content_type = website_response.get("content_type", "")
            if "html" in content_type.lower():
                injection = inspect_input_surface(
                    website_response.get("final_url", "https://" + domain),
                    website_response.get("body", ""),
                    content_type
                )
                report["modules"]["injection"] = injection
                findings.extend(injection.get("findings", []))
                print("Passive injection inspection completed.")
            else:
                report["modules"]["injection"] = {
                    "status": "not_assessed",
                    "reason": "The website response was not identified as HTML.",
                    "requests_sent": 0,
                    "active_probing": False
                }

            recommendations = {
                "Missing Content-Security-Policy":
                    "Start with Content-Security-Policy-Report-Only, review required resources, then enforce a tested policy.",
                "Missing X-Content-Type-Options":
                    "Set X-Content-Type-Options: nosniff.",
                "Missing Referrer-Policy":
                    "Consider Referrer-Policy: strict-origin-when-cross-origin.",
                "Missing Permissions-Policy":
                    "Define a Permissions-Policy appropriate to the browser features your website uses.",
                "Frame protection not detected":
                    "Set CSP frame-ancestors or X-Frame-Options to prevent unauthorized framing.",
                "Missing Strict-Transport-Security":
                    "After confirming HTTPS works across the domain, configure an appropriate HSTS policy."
            }

            for item in website.get("findings", []):
                issue = item.get("issue", "Website finding")
                severity = str(item.get("severity", "INFO")).upper()

                findings.append({
                    "module": "website",
                    "severity": severity,
                    "issue": issue,
                    "detail": item.get("detail", ""),
                    "recommendation": recommendations.get(
                        issue, "Review the evidence and verify the configuration."
                    )
                })

            print("Website audit completed.")
        else:
            report["modules"]["website"] = {
                "error": "Website audit report was not created."
            }
            report["modules"]["injection"] = {"status": "not_assessed"}

    except Exception as exc:
        report["modules"]["website"] = {"error": str(exc)}
        report["modules"]["injection"] = {"status": "not_assessed"}
        print("Website audit error:", exc)

    # SSL
    print("\n[4/5] SSL/TLS inspection")

    ssl_path = BASE_DIR / "pigeon-ssl-report.json"

    try:
        if ssl_path.exists():
            ssl_path.unlink()

        with contextlib.redirect_stdout(io.StringIO()):
            inspect_ssl(domain, "443")

        if ssl_path.exists():
            ssl = json.loads(ssl_path.read_text())
            ssl["status"] = "completed"
            report["modules"]["ssl"] = ssl

            if not ssl.get("connection_successful", False):
                findings.append({
                    "module": "ssl",
                    "severity": "HIGH",
                    "issue": "HTTPS connection unsuccessful",
                    "detail": ssl.get("error") or "A TLS connection could not be established.",
                    "recommendation": "Check HTTPS availability and server configuration."
                })
            elif not ssl.get("certificate_verified", False):
                findings.append({
                    "module": "ssl",
                    "severity": "HIGH",
                    "issue": "Certificate verification unsuccessful",
                    "detail": ssl.get("error") or "Certificate verification failed.",
                    "recommendation": "Check certificate validity, hostname and certificate chain."
                })

            days = ssl.get("days_until_expiry")

            if isinstance(days, (int, float)):
                if days < 0:
                    findings.append({
                        "module": "ssl",
                        "severity": "HIGH",
                        "issue": "SSL certificate expired",
                        "detail": f"Certificate expired {-days} days ago.",
                        "recommendation": "Renew and deploy a valid certificate."
                    })
                elif days <= 30:
                    findings.append({
                        "module": "ssl",
                        "severity": "MEDIUM",
                        "issue": "SSL certificate expires soon",
                        "detail": f"Certificate expires in {days} days.",
                        "recommendation": "Renew the certificate before expiry."
                    })

            print("SSL/TLS inspection completed.")
        else:
            report["modules"]["ssl"] = {
                "error": "SSL report was not created."
            }

    except Exception as exc:
        report["modules"]["ssl"] = {"error": str(exc)}
        print("SSL inspection error:", exc)

    # Port inspection
    print("\n[5/5] Authorized port inspection")

    port_path = BASE_DIR / "pigeon-assessment-ports.json"
    html_path = BASE_DIR / "pigeon-assessment-ports.html"
    scanner = BASE_DIR / "pigeon_portscan.py"

    try:
        if not scanner.exists():
            raise FileNotFoundError("pigeon_portscan.py was not found.")

        result = subprocess.run([
            sys.executable, str(scanner), domain,
            "--ports", ports,
            "--authorized",
            "--timeout", "1.5",
            "--workers", "4",
            "--output", str(port_path),
            "--html", str(html_path)
        ], capture_output=True, text=True, timeout=180)

        if port_path.exists():
            port_report = json.loads(port_path.read_text())
            port_report["status"] = "completed" if result.returncode == 0 else "partial"
            report["modules"]["portscan"] = port_report

            # Cloudflare edge detection based on observed HTTP evidence.
            website_text = json.dumps(report["modules"].get("website", {})).lower()
            cloudflare_detected = (
                "cloudflare" in website_text
                or "cloudflare" in str(port_report.get("company", "")).lower()
            )

            report["modules"]["portscan"]["cloudflare_edge_detected"] = cloudflare_detected

            for item in port_report.get("results", []):
                if item.get("state") != "OPEN":
                    continue

                port = item.get("port")
                service = item.get("service", "unknown")

                observation = {
                    "port": port,
                    "service": service,
                    "state": "OPEN",
                    "service_verified": item.get("service_verified", False),
                    "response_ms": item.get("response_ms"),
                    "assessment_scope": (
                        "Cloudflare-facing edge observation; origin exposure not established."
                        if cloudflare_detected else
                        "Observed at the resolved target address; origin ownership not independently established."
                    )
                }
                observations.append(observation)

                # Standard web ports are observations, not automatic vulnerabilities.
                if port in (80, 443):
                    continue

                # Nonstandard web ports need review, not automatic vulnerability labels.
                if port in (8080, 8443) and service in ("HTTP", "HTTPS"):
                    findings.append({
                        "module": "portscan",
                        "severity": "INFO",
                        "issue": f"Nonstandard web service observed on port {port}",
                        "detail": (
                            "A web service responded through the Cloudflare-facing edge."
                            if cloudflare_detected else
                            "A web service responded on a nonstandard port. Its purpose and exposure should be reviewed."
                        ),
                        "recommendation": "Confirm whether this service is required and restrict access if it is administrative or internal."
                    })
                    continue

                risk = item.get("risk") or {}
                level = str(risk.get("level", "INFO")).upper()

                findings.append({
                    "module": "portscan",
                    "severity": level,
                    "issue": f"Open {service} port {port}",
                    "detail": risk.get("reason", "An open service was detected."),
                    "recommendation": risk.get("action", "Review whether public exposure is necessary.")
                })

            report["modules"]["portscan"]["scope_note"] = (
                "Cloudflare may proxy traffic. Results describe the resolved edge address, not necessarily the origin server."
                if cloudflare_detected else
                "Port results describe the resolved address and do not independently establish origin-server exposure."
            )

            print("Port inspection completed.")
            if cloudflare_detected:
                print("Cloudflare edge indicators detected; origin exposure is not confirmed.")
        else:
            report["modules"]["portscan"] = {
                "error": result.stderr[-1500:] or "Port scan report was not created.",
                "return_code": result.returncode
            }
            print("Port scan did not produce a report.")

    except Exception as exc:
        report["modules"]["portscan"] = {"error": str(exc)}
        print("Port inspection error:", exc)

    report["modules"]["traffic"] = traffic_recorder.export()

    report["summary"] = build_assessment_summary(
        report["modules"], findings, observations
    )
    counts = report["summary"]["severity_counts"]

    output = BASE_DIR / "pigeon-assessment.json"
    output.write_text(json.dumps(report, indent=4))

    print("\n" + "=" * 55)
    print("PST 1.9.1 ASSESSMENT COMPLETE")
    print("Overall assessment status:", report["summary"]["overall_status"])
    print("Modules completed:", report["summary"]["modules_completed"])
    print("Modules failed:", report["summary"]["modules_failed"])
    print("Modules partial:", report["summary"]["modules_partial"])
    print("Modules not assessed:", report["summary"]["modules_not_assessed"])
    print("Security findings:", len(findings))
    print("Service observations:", len(observations))
    print("Severity counts:", counts)
    print("Security conclusion:", report["summary"]["security_conclusion"])
    print("Report:", output)
    print("Note: Results are defensive indicators, not proof of exploitable vulnerabilities.")

    return 0

def run_script(filename, arguments):
    script_path = BASE_DIR / filename

    if not script_path.is_file():
        print(f"ERROR: Required file not found: {filename}")
        sys.exit(1)

    result = subprocess.run(
        [sys.executable, str(script_path), *arguments],
        cwd=str(BASE_DIR)
    )

    sys.exit(result.returncode)



def run_menu_command(arguments):
    print("\n" + "=" * 58)
    subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), *arguments],
        cwd=str(BASE_DIR)
    )
    input("\nPress Enter to return to the menu...")


def interactive_menu():
    while True:
        print()
        banner()
        print("""
                         MAIN MENU

  [1] DNS Intelligence
  [2] Website Security Audit
  [3] SSL/TLS Inspector
  [4] File Integrity (SHA-256)
  [5] Authorized Port Scanner
  [6] Scan History
  [7] View Saved Scan
  [8] Compare Security Reports
  [9] Unified Security Assessment

  [0] Exit

----------------------------------------------------------
""")
        try:
            choice = input("PST > ").strip()

            if not choice:
                continue

            if choice == "0":
                print("Pigeon Security Toolkit closed.")
                return

            elif choice == "1":
                value = input("Enter domain: ").strip()
                if value:
                    run_menu_command(["dns", value])

            elif choice == "2":
                value = input("Enter website URL: ").strip()
                if value:
                    run_menu_command(["audit", value])

            elif choice == "3":
                domain = input("Enter domain: ").strip()
                if domain:
                    port = input("Port [443]: ").strip() or "443"
                    run_menu_command(["ssl", domain, port])

            elif choice == "4":
                value = input("Enter file path: ").strip()
                if value:
                    run_menu_command(["hash", value])

            elif choice == "5":
                print("Only scan systems you own or have permission to assess.")
                confirm = input('Type "I HAVE PERMISSION": ').strip()
                if confirm == "I HAVE PERMISSION":
                    target = input("Enter target: ").strip()
                    if target:
                        run_menu_command([
                            "scan", target, "--authorized"
                        ])
                else:
                    print("Scan cancelled.")

            elif choice == "6":
                run_menu_command(["history"])

            elif choice == "7":
                scan_id = input("Enter scan ID: ").strip()
                if scan_id:
                    run_menu_command(["show", scan_id])

            elif choice == "8":
                old_id = input("Old scan ID: ").strip()
                new_id = input("New scan ID: ").strip()
                if old_id and new_id:
                    run_menu_command(["compare", old_id, new_id])

            elif choice == "9":
                print("Only assess systems you own or have permission to assess.")
                confirm = input('Type "I HAVE PERMISSION": ').strip()
                if confirm == "I HAVE PERMISSION":
                    domain = input("Enter domain: ").strip()
                    if domain:
                        ports = input(
                            "Ports [22,80,443,8080,8443]: "
                        ).strip() or "22,80,443,8080,8443"
                        run_menu_command([
                            "assess", domain, "--authorized",
                            "--ports", ports
                        ])
                else:
                    print("Assessment cancelled.")

            else:
                print("Invalid selection.")

        except (KeyboardInterrupt, EOFError):
            print("\nPigeon Security Toolkit closed.")
            return



def build_assessment_summary(modules, findings, observations=None):
    """Build a truthful summary of assessment coverage and findings."""
    module_status = {}
    completed = 0
    failed = 0
    partial = 0
    not_assessed = 0

    for name, data in modules.items():
        if not isinstance(data, dict) or not data:
            status = "not_assessed"
        elif data.get("error"):
            status = "failed"
        elif data.get("status") in ("completed", "partial", "not_assessed"):
            status = data["status"]
        else:
            status = "not_assessed"

        module_status[name] = status

        if status == "completed":
            completed += 1
        elif status == "failed":
            failed += 1
        elif status == "partial":
            partial += 1
        else:
            not_assessed += 1

    severity_counts = normalize_assessment_findings(findings)

    if failed or not_assessed:
        overall_status = "incomplete"
    elif partial:
        overall_status = "partially_completed"
    else:
        overall_status = "completed"

    return {
        "overall_status": overall_status,
        "module_status": module_status,
        "modules_completed": completed,
        "modules_failed": failed,
        "modules_partial": partial,
        "modules_not_assessed": not_assessed,
        "total_modules": len(modules),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "service_observations": len(observations or []),
        "security_conclusion": (
            "Findings were detected; review their evidence and severity."
            if findings else
            "No findings were recorded. This does not establish that the target is secure."
        )
    }


def main():
    args = sys.argv[1:]

    if not args:
        interactive_menu()
        return

    command = args[0].lower()
    remaining = args[1:]

    if command in ("--help", "-h", "help"):
        help_menu()

    elif command in ("--version", "-v", "version"):
        banner()
        print(f"Version: {VERSION}")

    elif command == "hash":
        if len(remaining) != 1:
            print("Usage: python pst.py hash FILE")
            sys.exit(2)
        calculate_sha256(remaining[0])

    elif command == "dns":
        if len(remaining) != 1:
            print("Usage: python pst.py dns DOMAIN")
            sys.exit(2)
        inspect_dns(remaining[0])

    elif command == "audit":
        if len(remaining) != 1:
            print("Usage: python pst.py audit URL")
            sys.exit(2)
        audit_website(remaining[0])

    elif command == "ssl":
        if len(remaining) not in (1, 2):
            print("Usage: python pst.py ssl DOMAIN [PORT]")
            sys.exit(2)
        inspect_ssl(
            remaining[0],
            remaining[1] if len(remaining) == 2 else "443"
        )

    elif command == "assess":
        if not remaining:
            print("Usage: python pst.py assess DOMAIN --authorized [--ports PORTS]")
            sys.exit(2)
        sys.exit(unified_assessment(remaining[0], remaining[1:]))

    elif command == "scan":
        if not remaining:
            print("ERROR: Please provide a target.")
            sys.exit(2)
        run_script("pigeon_portscan.py", remaining)

    elif command == "history":
        run_script("pigeon_history.py", ["list", *remaining])

    elif command == "show":
        if len(remaining) != 1:
            print("Usage: python pst.py show SCAN_ID")
            sys.exit(2)
        run_script("pigeon_history.py", ["show", remaining[0]])

    elif command == "compare":
        if len(remaining) != 2:
            print("Usage: python pst.py compare OLD_ID NEW_ID")
            sys.exit(2)
        run_script("pigeon_history.py", ["compare", *remaining])

    else:
        print(f"Unknown command: {command}")
        print("Run 'python pst.py --help' for available commands.")
        sys.exit(2)


if __name__ == "__main__":
    main()
