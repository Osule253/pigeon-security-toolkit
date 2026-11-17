#!/usr/bin/env python3
"""
PIGEON SECURITY TOOLKIT
PIGEON PORTSCAN 1.2.0
SECURE. INSPECT. DEFEND.
Pigeon Techies | pigeontechies.com
"""

import argparse
import concurrent.futures
import datetime
import html
import json
import os
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

VERSION = "1.2.0"
HISTORY_FILE = "pigeon_scan_history.jsonl"

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443,
    445, 465, 587, 993, 995, 1433, 3306,
    3389, 5432, 5900, 6379, 8000, 8080,
    8443, 8888, 9200
]

SERVICE_HINTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP-SUBMISSION", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC",
    6379: "REDIS", 8000: "HTTP-ALT", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 8888: "HTTP-ALT", 9200: "ELASTICSEARCH"
}


def timestamp():
    return datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(timespec="seconds")


def resolve_target(target):
    try:
        results = socket.getaddrinfo(
            target, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        addresses = sorted(set(item[4][0] for item in results))
        if not addresses:
            raise OSError("No IP addresses found")
        return addresses
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed: {exc}")


def parse_ports(value):
    ports = set()

    try:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue

            if "-" in part:
                start, end = map(int, part.split("-", 1))
                if start > end:
                    raise ValueError
                if end - start > 1023:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))

        if not ports:
            raise ValueError

        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError

        if len(ports) > 1024:
            raise ValueError("Maximum 1024 ports per scan")

        return sorted(ports)

    except ValueError:
        raise argparse.ArgumentTypeError(
            "Invalid ports. Example: 22,80,443 or 1-100"
        )


def recv_text(sock, limit=1200):
    try:
        data = sock.recv(limit)
        return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError):
        return ""


def fingerprint_service(sock, port, target):
    """
    Performs limited, non-destructive protocol identification.
    Returns a fingerprint only when a recognizable response is received.
    """
    result = {
        "service": "UNKNOWN",
        "verified": False,
        "banner": None,
        "protocol_detail": None,
        "tls": None
    }

    try:
        sock.settimeout(1.5)

        # TLS services: perform a TLS handshake, then a simple HTTP HEAD.
        if port in (443, 465, 993, 995, 8443):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with context.wrap_socket(
                sock, server_hostname=target
            ) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()

                result["tls"] = {
                    "version": tls_sock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "certificate_subject": str(cert.get("subject", "")),
                    "certificate_expiry": cert.get("notAfter")
                }

                if port in (443, 8443):
                    request = (
                        f"HEAD / HTTP/1.0\r\n"
                        f"Host: {target}\r\n"
                        f"User-Agent: PigeonPortScan/1.2\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    tls_sock.sendall(request.encode())
                    response = recv_text(tls_sock)
                    first_line = response.splitlines()[0] if response else ""

                    if first_line.startswith("HTTP/"):
                        result.update({
                            "service": "HTTPS",
                            "verified": True,
                            "banner": first_line,
                            "protocol_detail": "TLS + HTTP response"
                        })
                    else:
                        result.update({
                            "service": "TLS",
                            "verified": True,
                            "protocol_detail": "TLS handshake completed"
                        })

                elif port == 465:
                    result.update({
                        "service": "SMTPS",
                        "verified": True,
                        "protocol_detail": "TLS handshake completed"
                    })
                elif port == 993:
                    result.update({
                        "service": "IMAPS",
                        "verified": True,
                        "protocol_detail": "TLS handshake completed"
                    })
                elif port == 995:
                    result.update({
                        "service": "POP3S",
                        "verified": True,
                        "protocol_detail": "TLS handshake completed"
                    })

            return result

        # SSH, FTP, SMTP, POP3 and IMAP commonly send greetings.
        if port in (21, 22, 25, 110, 143, 587):
            banner = recv_text(sock)

            if banner:
                first_line = banner.splitlines()[0][:300]

                if first_line.startswith("SSH-"):
                    service = "SSH"
                elif port == 21 and (
                    first_line.startswith("220")
                ):
                    service = "FTP"
                elif port in (25, 587) and first_line.startswith("220"):
                    service = "SMTP"
                elif port == 110 and first_line.startswith("+OK"):
                    service = "POP3"
                elif port == 143 and first_line.startswith("*"):
                    service = "IMAP"
                else:
                    service = None

                if service:
                    result.update({
                        "service": service,
                        "verified": True,
                        "banner": first_line,
                        "protocol_detail": "Recognized server greeting"
                    })

            return result

        # HTTP services.
        if port in (80, 8000, 8080, 8888):
            request = (
                f"HEAD / HTTP/1.0\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: PigeonPortScan/1.2\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            response = recv_text(sock)
            first_line = response.splitlines()[0] if response else ""

            if first_line.startswith("HTTP/"):
                result.update({
                    "service": "HTTP",
                    "verified": True,
                    "banner": first_line,
                    "protocol_detail": "HTTP response received"
                })

            return result

        # MySQL sends a handshake packet immediately after connection.
        if port == 3306:
            data = sock.recv(256)
            if len(data) >= 5:
                result.update({
                    "service": "MYSQL",
                    "verified": True,
                    "protocol_detail": "MySQL handshake packet received"
                })
            return result

    except (OSError, ssl.SSLError, ValueError):
        pass

    return result


def risk_assessment(port, service, verified):
    """
    Heuristic exposure guidance, not a vulnerability determination.
    """
    if port == 23 or service == "TELNET":
        return {
            "level": "HIGH",
            "reason": "Telnet is an insecure remote administration protocol.",
            "action": "Disable Telnet and use SSH where remote access is needed."
        }

    if port == 21 or service == "FTP":
        return {
            "level": "HIGH",
            "reason": "Traditional FTP may transmit credentials and data without encryption.",
            "action": "Prefer SFTP or FTPS; disable anonymous access if enabled."
        }

    if port in (3306, 5432, 1433, 6379, 9200):
        return {
            "level": "HIGH",
            "reason": "A database or data service appears reachable.",
            "action": "Restrict access to trusted hosts and require strong authentication."
        }

    if port in (445, 3389, 5900):
        return {
            "level": "HIGH",
            "reason": "A remote access or file-sharing service appears reachable.",
            "action": "Restrict exposure using firewall rules, VPN and strong authentication."
        }

    if port == 22 or service == "SSH":
        return {
            "level": "MEDIUM",
            "reason": "SSH provides remote administration and should be tightly controlled.",
            "action": "Use key-based authentication, disable unused accounts and restrict access."
        }

    if port in (80, 8000, 8080, 8888) or service == "HTTP":
        return {
            "level": "MEDIUM",
            "reason": "Unencrypted HTTP may expose traffic in transit.",
            "action": "Use HTTPS and redirect HTTP traffic where appropriate."
        }

    if port in (443, 8443) or service in ("HTTPS", "TLS"):
        return {
            "level": "LOW",
            "reason": "An encrypted service responded; this does not establish that its configuration is secure.",
            "action": "Review certificate validity, TLS configuration and application security."
        }

    if verified:
        return {
            "level": "INFO",
            "reason": "A service response was identified; exposure alone does not prove a vulnerability.",
            "action": "Confirm that this service is required and restrict access where possible."
        }

    return {
        "level": "INFO",
        "reason": "The port is open, but the service could not be identified.",
        "action": "Verify whether the port is expected and investigate it using authorized methods."
    }




def identify_service_version(service, banner):
    """Extract product/version only from explicit, recognizable banners."""
    import re

    result = {
        "product": None,
        "version": None,
        "version_source": None
    }

    if not banner:
        return result

    patterns = {
        "SSH": [
            (r"OpenSSH[_ ]([0-9][A-Za-z0-9._p-]*)", "OpenSSH"),
        ],
        "FTP": [
            (r"vsFTPd\s+([0-9][A-Za-z0-9._-]*)", "vsFTPd"),
            (r"ProFTPD\s+([0-9][A-Za-z0-9._-]*)", "ProFTPD"),
        ],
        "SMTP": [
            (r"Exim\s+([0-9][A-Za-z0-9._-]*)", "Exim"),
        ],
    }

    for pattern, product in patterns.get(service, []):
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            result.update({
                "product": product,
                "version": match.group(1),
                "version_source": "service_banner"
            })
            break

    return result

def assess_exploitability(port, service, verified, banner=None, tls=None):
    """
    Conservative, non-invasive exploitability assessment.
    Does not execute exploits or infer vulnerabilities from open ports alone.
    """
    result = {
        "status": "UNDETERMINED",
        "confidence": "LOW",
        "evidence": [],
        "cve_matches": [],
        "exploitation_attempted": False,
        "reason": "An open port or service identification alone cannot confirm a vulnerability.",
        "recommendation": "Identify the exact product and version, review vendor advisories, and validate safely."
    }

    if not verified:
        result["evidence"].append("Service identity has not been verified.")
        return result

    result["evidence"].append(f"Recognized service: {service}")

    if banner:
        result["evidence"].append("A service response banner was observed.")
        result["banner"] = str(banner)[:300]

    if tls:
        result["evidence"].append("TLS handshake metadata was observed.")
        result["tls_version"] = tls.get("version")
        result["tls_cipher"] = tls.get("cipher")

    result["reason"] = (
        "The service was identified, but no exact software product/version "
        "has yet been verified against vulnerability intelligence."
    )
    result["recommendation"] = (
        "Obtain reliable product/version evidence and compare it with vendor "
        "security advisories or a trusted CVE database."
    )

    if service in ("TELNET", "FTP"):
        result["status"] = "EXPOSURE_CONCERN"
        result["confidence"] = "MEDIUM"
        result["reason"] = (
            "The identified protocol may expose credentials or traffic "
            "without modern transport encryption."
        )
        result["recommendation"] = (
            "Disable the service if unnecessary. Prefer SSH, SFTP or properly "
            "configured encrypted alternatives."
        )

    elif service in ("MYSQL", "POSTGRESQL", "MSSQL", "REDIS", "ELASTICSEARCH"):
        result["status"] = "EXPOSURE_CONCERN"
        result["confidence"] = "MEDIUM"
        result["reason"] = (
            "A database or data service is reachable. Reachability does not "
            "prove weak authentication or unauthorized data access."
        )
        result["recommendation"] = (
            "Restrict network access, verify authentication and authorization, "
            "and check the installed version against vendor advisories."
        )

    elif service in ("SMB", "RDP", "VNC"):
        result["status"] = "EXPOSURE_CONCERN"
        result["confidence"] = "MEDIUM"
        result["reason"] = (
            "A remote access or file-sharing service is reachable and may "
            "increase attack surface."
        )
        result["recommendation"] = (
            "Restrict access to trusted networks or VPN and verify patch level "
            "and authentication controls."
        )

    return result

def inspect_port(ip, port, timeout, target):
    start = time.perf_counter()
    item = {
        "port": port,
        "state": "UNKNOWN",
        "service": SERVICE_HINTS.get(port, "UNKNOWN"),
        "service_verified": False,
        "banner": None,
        "protocol_detail": None,
        "tls": None,
        "product": None,
        "version": None,
        "version_source": None,
        "response_ms": None,
        "risk": None,
        "error": None
    }

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            item["state"] = "OPEN"
            item["response_ms"] = round(
                (time.perf_counter() - start) * 1000, 2
            )

            fingerprint = fingerprint_service(sock, port, target)

            if fingerprint["verified"]:
                item["service"] = fingerprint["service"]
                item["service_verified"] = True

            item["banner"] = fingerprint["banner"]
            item["protocol_detail"] = fingerprint["protocol_detail"]
            item["tls"] = fingerprint["tls"]
            version_info = identify_service_version(
                item["service"], item["banner"]
            )
            item.update(version_info)

    except ConnectionRefusedError:
        item["state"] = "CLOSED"
    except socket.timeout:
        item["state"] = "FILTERED_OR_NO_RESPONSE"
    except OSError as exc:
        if getattr(exc, "errno", None) in (101, 113, 110):
            item["state"] = "UNREACHABLE"
        else:
            item["state"] = "ERROR"
            item["error"] = str(exc)[:200]

    if item["state"] == "OPEN":
        item["risk"] = risk_assessment(
            port, item["service"], item["service_verified"]
        )
        item["exploitability"] = assess_exploitability(
            port,
            item["service"],
            item["service_verified"],
            item["banner"],
            item["tls"]
        )
    else:
        item["exploitability"] = {
            "status": "NOT_APPLICABLE",
            "confidence": "NONE",
            "evidence": [],
            "cve_matches": [],
            "exploitation_attempted": False,
            "reason": "The port was not observed open."
        }

    if item["response_ms"] is None and item["state"] in ("CLOSED", "ERROR"):
        item["response_ms"] = round(
            (time.perf_counter() - start) * 1000, 2
        )

    return item


def build_report(target, ip, ports, results, started, ended):
    counts = {
        state: sum(1 for item in results if item["state"] == state)
        for state in (
            "OPEN", "CLOSED", "FILTERED_OR_NO_RESPONSE",
            "UNREACHABLE", "ERROR"
        )
    }

    return {
        "tool": "Pigeon PortScan",
        "version": VERSION,
        "company": "Pigeon Techies",
        "website": "https://pigeontechies.com",
        "scan_type": "TCP_CONNECT_WITH_SAFE_FINGERPRINTING",
        "target": target,
        "selected_ip": ip,
        "ports_requested": ports,
        "started_at": started,
        "finished_at": ended,
        "summary": counts,
        "results": results,
        "notice": (
            "Risk levels are defensive heuristics, not proof of vulnerabilities. "
            "Only scan systems you own or are authorized to assess."
        )
    }


def save_json(report, filename):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)


def save_html(report, filename):
    rows = []

    for item in report["results"]:
        risk = item.get("risk") or {}
        exploit = item.get("exploitability") or {}
        evidence = "; ".join(exploit.get("evidence", []))
        cve = item.get("cve_intelligence") or {}
        cve_ids = ", ".join(
            match.get("id", "")
            for match in cve.get("matches", [])
        )
        cve_display = (
            cve_ids if cve_ids
            else cve.get("status", "NOT_CHECKED")
        )

        rows.append(
            "<tr>"
            f"<td>{item['port']}</td>"
            f"<td>{html.escape(item['state'])}</td>"
            f"<td>{html.escape(item['service'])}</td>"
            f"<td>{'Yes' if item['service_verified'] else 'No'}</td>"
            f"<td>{html.escape(str(item['response_ms']))} ms</td>"
            f"<td>{html.escape(str(risk.get('level', '-')))}</td>"
            f"<td>{html.escape(str(exploit.get('status', 'NOT_ASSESSED')))}</td>"
            f"<td>{html.escape(str(exploit.get('confidence', '-')))}</td>"
            f"<td>{html.escape(evidence)}</td>"
            f"<td>{html.escape(str(risk.get('reason', '-')))}</td>"
            f"<td>{html.escape(str(exploit.get('recommendation', risk.get('action', '-'))))}</td>"
            f"<td>{html.escape(cve_display)}</td>"
            "</tr>"
        )

    summary = report["summary"]

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pigeon PortScan Report</title>
<style>
body {{ background:#f4f4f4; color:#171717; font-family:Arial,sans-serif;
       margin:20px; }}
main {{ max-width:1200px; margin:auto; background:white; padding:20px;
        border:1px solid #ccc; }}
h1 {{ letter-spacing:1px; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; }}
th,td {{ border:1px solid #ddd; padding:9px; text-align:left; }}
th {{ background:#222; color:white; }}
.notice {{ background:#eee; padding:12px; margin-top:18px; }}
@media print {{ body {{ background:white; margin:0; }}
main {{ border:0; }} }}
</style>
</head>
<body><main>
<h1>PIGEON PORTSCAN {VERSION}</h1>
<p><b>PIGEON TECHIES</b> | SECURE. INSPECT. DEFEND.</p>
<p>Target: {html.escape(report['target'])}</p>
<p>Selected IP: {html.escape(report['selected_ip'])}</p>
<p>Started: {html.escape(report['started_at'])}</p>
<p>Finished: {html.escape(report['finished_at'])}</p>
<p>Open: {summary['OPEN']} |
Closed: {summary['CLOSED']} |
No response: {summary['FILTERED_OR_NO_RESPONSE']} |
Unreachable: {summary['UNREACHABLE']} |
Errors: {summary['ERROR']}</p>
<table>
<thead><tr>
<th>Port</th><th>State</th><th>Service</th><th>Verified</th>
<th>Response</th><th>Exposure risk</th><th>Exploitability</th>
<th>Confidence</th><th>Evidence</th><th>Reason</th><th>Recommended action</th><th>CVE intelligence</th>
</tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<div class="notice">{html.escape(report['notice'])}</div>
<p>Pigeon Techies | https://pigeontechies.com</p>
</main></body></html>"""

    with open(filename, "w", encoding="utf-8") as file:
        file.write(page)


def save_history(report):
    with open(HISTORY_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(report, ensure_ascii=False) + "\n")


def print_report(report):
    print("\n" + "=" * 65)
    print("PIGEON PORTSCAN 1.2.0")
    print("=" * 65)

    for item in report["results"]:
        if item["state"] != "OPEN":
            continue

        verified = "VERIFIED" if item["service_verified"] else "HINT ONLY"
        risk = item["risk"] or {}
        exploit = item.get("exploitability") or {}
        print(
            f"{item['port']:5}  {item['service']:<16} "
            f"OPEN  {verified:<10} "
            f"{item['response_ms']} ms  "
            f"RISK: {risk.get('level', '-')}  "
            f"EXPLOITABILITY: {exploit.get('status', 'NOT_ASSESSED')}"
        )
        cve = item.get("cve_intelligence") or {}
        if cve:
            print(f"       CVE intelligence: {cve.get('status')}")
            for match in cve.get("matches", []):
                print(
                    f"       {match.get('id')} | "
                    f"CVSS: {match.get('cvss_score')} | "
                    f"{match.get('severity')}"
                )

        if exploit:
            print(
                f"       Exploitability confidence: "
                f"{exploit.get('confidence', '-')}"
            )
            print(
                f"       Exploitability reason: "
                f"{exploit.get('reason', '-')}"
            )

        if item["banner"]:
            print(f"       Response: {item['banner'][:150]}")

        if item["tls"]:
            print(
                f"       TLS: {item['tls'].get('version')} | "
                f"Cipher: {item['tls'].get('cipher')}"
            )

        if risk:
            print(f"       Why: {risk['reason']}")
            print(f"       Action: {risk['action']}")

    print("\nSUMMARY")
    for state, count in report["summary"].items():
        print(f"{state:<28} {count}")

    print("\nRisk assessments are guidance, not proof of vulnerabilities.")


def main():
    parser = argparse.ArgumentParser(
        description="Pigeon PortScan 1.2 - authorized TCP inspection"
    )
    parser.add_argument("target", help="IP address or hostname")
    parser.add_argument(
        "--ports", type=parse_ports,
        default=DEFAULT_PORTS,
        help="Ports: 22,80,443 or range 1-100"
    )
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--cve-check", action="store_true", help="Enable optional NVD CVE intelligence lookups")
    parser.add_argument("--output", default="pigeon-scan.json")
    parser.add_argument("--html", default="pigeon-report.html")
    parser.add_argument(
        "--authorized", action="store_true",
        help="Confirm you have permission to scan this target"
    )

    args = parser.parse_args()

    if not args.authorized:
        print("Permission confirmation required.")
        print("Only scan systems you own or have explicit authorization to assess.")
        print("Rerun with --authorized after confirming permission.")
        return 2

    if not 0.2 <= args.timeout <= 5:
        parser.error("Timeout must be between 0.2 and 5 seconds.")

    if not 1 <= args.workers <= 32:
        parser.error("Workers must be between 1 and 32.")

    try:
        addresses = resolve_target(args.target)
    except ValueError as exc:
        print(f"Target error: {exc}")
        return 1

    selected_ip = addresses[0]
    started = timestamp()

    print("=" * 60)
    print("PIGEON SECURITY TOOLKIT")
    print(f"PIGEON PORTSCAN {VERSION}")
    print("SECURE. INSPECT. DEFEND.")
    print("Pigeon Techies | pigeontechies.com")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"Selected IP: {selected_ip}")
    print(f"Ports: {len(args.ports)}")
    print(f"Timeout: {args.timeout}s")
    print(f"Workers: {args.workers}")
    print("\nStarting authorized TCP inspection...\n")

    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:
        futures = {
            executor.submit(
                inspect_port, selected_ip, port, args.timeout, args.target
            ): port
            for port in args.ports
        }

        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({
                    "port": futures[future],
                    "state": "ERROR",
                    "service": "UNKNOWN",
                    "service_verified": False,
                    "banner": None,
                    "protocol_detail": None,
                    "tls": None,
                    "response_ms": None,
                    "risk": None,
                    "error": str(exc)[:200]
                })


    if args.cve_check:
        from pst_modules.modules.cve_intel import lookup_cves

        print("\nOptional NVD CVE intelligence enabled.")
        lookup_cache = {}

        for item in results:
            if item.get("state") != "OPEN":
                continue

            product = item.get("product")
            version = item.get("version")

            if not product or not version:
                continue

            cache_key = (product, version)

            if cache_key not in lookup_cache:
                print(f"Checking NVD: {product} {version}")
                lookup_cache[cache_key] = lookup_cves(product, version)

            cve_result = lookup_cache[cache_key]
            item["cve_intelligence"] = cve_result

            exploit = item.setdefault("exploitability", {})
            exploit["cve_matches"] = [
                match.get("id")
                for match in cve_result.get("matches", [])
                if match.get("id")
            ]

            if cve_result["status"] == "POTENTIAL_CVE_MATCH":
                exploit["status"] = "POTENTIAL_CVE_MATCH"
                exploit["confidence"] = "REVIEW_REQUIRED"
                exploit["reason"] = (
                    "NVD returned potential product/version CVE matches. "
                    "Applicability must be independently verified."
                )
                exploit["recommendation"] = (
                    "Review each CVE, vendor advisory and installed "
                    "package version. Do not treat a database match "
                    "as proof of exploitability."
                )

    results.sort(key=lambda item: item["port"])
    report = build_report(
        args.target, selected_ip, args.ports,
        results, started, timestamp()
    )

    print_report(report)

    try:
        save_json(report, args.output)
        save_html(report, args.html)
        save_history(report)
    except OSError as exc:
        print(f"\nCould not save reports: {exc}")
        return 1

    print(f"\nJSON report saved: {args.output}")
    print(f"HTML report saved: {args.html}")
    print(f"History appended: {HISTORY_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
