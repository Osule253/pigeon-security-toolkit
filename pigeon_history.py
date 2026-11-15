#!/usr/bin/env python3

import argparse
import json
import os
import sys
from datetime import datetime

VERSION = "1.3.1"
HISTORY_FILE = "pigeon_scan_history.jsonl"


def load_history():
    scans = []

    if not os.path.exists(HISTORY_FILE):
        return scans

    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                scans.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"Warning: Skipping damaged history line {line_number}")

    # Preserve chronological order so scan IDs remain permanent.
    return scans


def get_scan(scans, number):
    if number < 1 or number > len(scans):
        raise ValueError(
            f"Scan #{number} does not exist. Available scans: {len(scans)}"
        )
    return scans[number - 1]


def show_header():
    print("=" * 60)
    print("PIGEON SECURITY TOOLKIT")
    print(f"PIGEON HISTORY {VERSION}")
    print("SECURE. INSPECT. DEFEND.")
    print("Pigeon Techies | pigeontechies.com")
    print("=" * 60)


def list_scans(scans):
    if not scans:
        print("No scan history found.")
        return

    print(f"\n{'ID':<5}{'DATE':<27}{'TARGET':<24}{'OPEN':<8}")
    print("-" * 65)

    # Display newest first while retaining permanent chronological IDs.
    for index in range(len(scans) - 1, -1, -1):
        scan = scans[index]
        scan_id = index + 1
        date = scan.get("finished_at", "Unknown")
        target = scan.get("target", "Unknown")
        opened = scan.get("summary", {}).get("OPEN", 0)

        print(f"{scan_id:<5}{date[:25]:<27}{target[:22]:<24}{opened:<8}")

    print("\nUse: python pigeon_history.py show ID")
    print("Compare: python pigeon_history.py compare OLD_ID NEW_ID")


def show_scan(scan, number):
    print(f"\nSCAN #{number}")
    print(f"Target: {scan.get('target', 'Unknown')}")
    print(f"IP: {scan.get('selected_ip', 'Unknown')}")
    print(f"Version: {scan.get('version', 'Unknown')}")
    print(f"Started: {scan.get('started_at', 'Unknown')}")
    print(f"Finished: {scan.get('finished_at', 'Unknown')}")

    summary = scan.get("summary", {})
    print("\nSUMMARY")

    for key, value in summary.items():
        print(f"{key:<28} {value}")

    print("\nPORT RESULTS")
    print("-" * 65)

    for item in scan.get("results", []):
        risk = item.get("risk") or {}
        print(
            f"{item.get('port', '?'):<7}"
            f"{item.get('state', '?'):<25}"
            f"{item.get('service', '?'):<17}"
            f"{risk.get('level', '-')}"
        )

    print("\nNote: Risk levels are defensive guidance, not proof of vulnerabilities.")


def compare_scans(old, new, old_id, new_id):
    old_target = old.get("target")
    new_target = new.get("target")

    print(f"\nCOMPARISON: SCAN #{old_id} -> SCAN #{new_id}")
    print(f"Old target: {old_target}")
    print(f"New target: {new_target}")

    if old_target != new_target:
        print("WARNING: These scans have different target names.")

    old_ports = {
        item["port"]: item
        for item in old.get("results", [])
        if "port" in item
    }

    new_ports = {
        item["port"]: item
        for item in new.get("results", [])
        if "port" in item
    }

    common = set(old_ports) & set(new_ports)
    newly_open = []
    newly_closed = []
    still_open = []
    other_changes = []

    for port in sorted(common):
        before = old_ports[port].get("state")
        after = new_ports[port].get("state")

        if before != "OPEN" and after == "OPEN":
            newly_open.append(port)
        elif before == "OPEN" and after != "OPEN":
            newly_closed.append(port)
        elif before == "OPEN" and after == "OPEN":
            still_open.append(port)
        elif before != after:
            other_changes.append((port, before, after))

    only_old = sorted(set(old_ports) - set(new_ports))
    only_new = sorted(set(new_ports) - set(old_ports))

    print("\nCHANGES")
    print(f"Newly open ports:  {newly_open or 'None'}")
    print(f"Newly closed ports: {newly_closed or 'None'}")
    print(f"Still open ports:   {still_open or 'None'}")

    if other_changes:
        print("\nOther state changes:")
        for port, before, after in other_changes:
            print(f"Port {port}: {before} -> {after}")

    if only_old or only_new:
        print("\nCOMPARISON LIMITATIONS")
        if only_old:
            print(f"Only in old scan: {only_old}")
        if only_new:
            print(f"Only in new scan: {only_new}")
        print("Ports not scanned in both runs are excluded from change detection.")

    comparison = {
        "tool": "Pigeon History",
        "version": VERSION,
        "old_scan_id": old_id,
        "new_scan_id": new_id,
        "old_target": old_target,
        "new_target": new_target,
        "newly_open": newly_open,
        "newly_closed": newly_closed,
        "still_open": still_open,
        "other_changes": [
            {"port": p, "before": b, "after": a}
            for p, b, a in other_changes
        ],
        "only_in_old_scan": only_old,
        "only_in_new_scan": only_new,
        "compared_at": datetime.now().astimezone().isoformat()
    }

    return comparison


def main():
    parser = argparse.ArgumentParser(
        description="Pigeon PortScan history viewer"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List saved scans")

    show_parser = sub.add_parser("show", help="View a saved scan")
    show_parser.add_argument("id", type=int)

    compare_parser = sub.add_parser("compare", help="Compare two scans")
    compare_parser.add_argument("old_id", type=int)
    compare_parser.add_argument("new_id", type=int)
    compare_parser.add_argument(
        "--output", default="pigeon-comparison.json"
    )

    args = parser.parse_args()

    show_header()
    scans = load_history()

    try:
        if args.command == "list":
            list_scans(scans)

        elif args.command == "show":
            scan = get_scan(scans, args.id)
            show_scan(scan, args.id)

        elif args.command == "compare":
            old = get_scan(scans, args.old_id)
            new = get_scan(scans, args.new_id)

            comparison = compare_scans(
                old, new, args.old_id, args.new_id
            )

            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(comparison, f, indent=2)

            print(f"\nComparison report saved: {args.output}")

    except (ValueError, OSError) as exc:
        print(f"\nError: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
