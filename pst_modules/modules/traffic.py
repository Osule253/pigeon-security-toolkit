"""Privacy-conscious traffic metadata collection for PST."""

import ipaddress
import time
from collections import Counter
from urllib.parse import urlsplit, urlunsplit


SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
}


def redact_headers(headers):
    """Remove sensitive header values."""
    safe = {}

    for name, value in (headers or {}).items():
        if name.lower() in SENSITIVE_HEADERS:
            safe[name] = "[REDACTED]"
        else:
            safe[name] = str(value)[:500]

    return safe


def sanitize_url(url):
    """Remove URL credentials, query parameters and fragments."""
    try:
        parts = urlsplit(url)

        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"

        if parts.port:
            host = f"{host}:{parts.port}"

        return urlunsplit((
            parts.scheme,
            host,
            parts.path,
            "",
            "",
        ))
    except (TypeError, ValueError):
        return "[INVALID_URL]"


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


class TrafficRecorder:
    """Collect metadata for traffic explicitly reported by PST."""

    def __init__(self):
        self.events = []

    def record_dns(self, hostname, addresses):
        safe_addresses = []

        for address in addresses or []:
            parsed = valid_ip(address)
            if parsed:
                safe_addresses.append(parsed)

        event = {
            "type": "DNS",
            "hostname": str(hostname)[:253],
            "addresses": sorted(set(safe_addresses)),
            "timestamp": time.time(),
        }

        self.events.append(event)
        return event

    def record_connection(
        self,
        destination_ip,
        destination_port,
        protocol="TCP",
        source_ip=None,
        bytes_sent=0,
        bytes_received=0,
        duration_ms=None,
    ):
        destination = valid_ip(destination_ip)
        source = valid_ip(source_ip) if source_ip else None

        if not destination:
            raise ValueError("Invalid destination IP address.")

        if not isinstance(destination_port, int) or not 1 <= destination_port <= 65535:
            raise ValueError("Invalid destination port.")

        if bytes_sent < 0 or bytes_received < 0:
            raise ValueError("Byte counts cannot be negative.")

        if duration_ms is not None and duration_ms < 0:
            raise ValueError("Duration cannot be negative.")

        event = {
            "type": "CONNECTION",
            "source_ip": source,
            "destination_ip": destination,
            "destination_port": destination_port,
            "protocol": str(protocol).upper()[:16],
            "bytes_sent": int(bytes_sent),
            "bytes_received": int(bytes_received),
            "duration_ms": duration_ms,
            "timestamp": time.time(),
        }

        self.events.append(event)
        return event

    def record_http(
        self,
        method,
        url,
        status_code=None,
        duration_ms=None,
        bytes_received=0,
        headers=None,
    ):
        if bytes_received < 0:
            raise ValueError("Received byte count cannot be negative.")

        if duration_ms is not None and duration_ms < 0:
            raise ValueError("Duration cannot be negative.")

        if status_code is not None:
            if not isinstance(status_code, int) or not 100 <= status_code <= 599:
                raise ValueError("Invalid HTTP status code.")

        event = {
            "type": "HTTP",
            "method": str(method).upper()[:16],
            "url": sanitize_url(url),
            "status_code": status_code,
            "duration_ms": duration_ms,
            "bytes_received": int(bytes_received),
            "headers": redact_headers(headers),
            "timestamp": time.time(),
        }

        self.events.append(event)
        return event

    def summary(self):
        event_types = Counter(
            event["type"] for event in self.events
        )

        http_statuses = Counter(
            str(event["status_code"])
            for event in self.events
            if event["type"] == "HTTP"
            and event["status_code"] is not None
        )

        return {
            "event_count": len(self.events),
            "event_types": dict(event_types),
            "http_statuses": dict(http_statuses),
            "bytes_sent": sum(
                event.get("bytes_sent", 0)
                for event in self.events
            ),
            "bytes_received": sum(
                event.get("bytes_received", 0)
                for event in self.events
            ),
        }

    def export(self):
        return {
            "tool": "Pigeon Traffic Analyzer",
            "version": "1.0.0",
            "status": "completed",
            "capture_scope": "PST_REPORTED_TRAFFIC_METADATA",
            "payload_capture": False,
            "events": list(self.events),
            "summary": self.summary(),
        }
