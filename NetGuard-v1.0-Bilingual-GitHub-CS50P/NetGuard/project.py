"""NetGuard: a small, permission-focused TCP monitoring project for CS50P.

Only RFC 1918 private IPv4 addresses and IPv4 loopback are accepted.
The program checks explicitly selected TCP ports; it does not discover hosts,
perform vulnerability testing, or attempt authentication.
"""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import socket
import sys


VERSION = "1.0.0"
MAX_PORTS = 20
DEFAULT_PORTS = "22,80,443"
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)


def validate_host(host):
    """Return a permitted IPv4 address as text or raise ValueError.

    NetGuard intentionally limits targets to loopback and RFC 1918 IPv4.
    """
    try:
        address = ipaddress.ip_address(host.strip())
    except (ValueError, AttributeError) as exc:
        raise ValueError("Enter a valid IPv4 address (not a hostname).") from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 addresses are supported.")
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise ValueError("Only private IPv4 or loopback targets are allowed.")
    return str(address)


def parse_ports(raw):
    """Parse comma-separated TCP ports, preserving order and removing duplicates."""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Supply one or more TCP ports, such as 22,80,443.")

    ports = []
    for item in raw.split(","):
        item = item.strip()
        if not item or not item.isascii() or not item.isdecimal():
            raise ValueError("Port values must be whole numbers separated by commas.")
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError("TCP ports must be between 1 and 65535.")
        if port not in ports:
            ports.append(port)
        if len(ports) > MAX_PORTS:
            raise ValueError(f"Choose no more than {MAX_PORTS} distinct ports per scan.")
    return ports


def check_port(host, port, timeout=0.5):
    """Return True on successful TCP connection; otherwise return False.

    False means no connection was established. It does not prove a port is
    closed: filtering, host downtime, and network errors can look identical.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def scan_target(host, ports, checker=None):
    """Scan an explicitly named private/loopback host and selected ports."""
    host = validate_host(host)
    ports = parse_ports(",".join(str(port) for port in ports))
    if checker is None:
        checker = check_port

    results = []
    for port in ports:
        status = "open" if checker(host, port) else "no_connection"
        results.append({"port": port, "status": status})

    return {
        "application": "NetGuard",
        "version": VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": host,
        "results": results,
    }


def compare_reports(before, after):
    """Compare only ports present in both reports for the same target."""
    if before.get("target") != after.get("target"):
        raise ValueError("Reports must have the same target IP address.")

    def statuses(report):
        output = {}
        for entry in report["results"]:
            port, status = entry["port"], entry["status"]
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError("Report contains an invalid port.")
            if status not in ("open", "no_connection") or port in output:
                raise ValueError("Report has an invalid or duplicate port result.")
            output[port] = status
        return output

    old = statuses(before)
    new = statuses(after)
    shared = old.keys() & new.keys()
    return {
        "target": before["target"],
        "newly_open": sorted(p for p in shared if old[p] != "open" and new[p] == "open"),
        "no_longer_connectable": sorted(
            p for p in shared if old[p] == "open" and new[p] != "open"
        ),
        "unchanged": sorted(p for p in shared if old[p] == new[p]),
        "only_in_before": sorted(old.keys() - new.keys()),
        "only_in_after": sorted(new.keys() - old.keys()),
    }


def save_report(report, filename):
    """Save a JSON report and return the resulting Path."""
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
        file.write("\n")
    return path


def load_report(filename):
    """Load a NetGuard report, checking the fields used in comparisons."""
    with Path(filename).open("r", encoding="utf-8") as file:
        report = json.load(file)
    if not isinstance(report, dict) or report.get("application") != "NetGuard":
        raise ValueError("Not a NetGuard report.")
    validate_host(report.get("target", ""))
    if not isinstance(report.get("results"), list):
        raise ValueError("Report must contain a results list.")
    return report


def print_scan(report):
    print(f"\nNetGuard {VERSION} | {report['target']} | {report['timestamp_utc']}")
    print("PORT     TCP RESULT")
    print("--------------------------")
    for result in report["results"]:
        print(f"{result['port']:<8} {result['status']}")
    print("\nNote: 'no_connection' is not proof that a port is closed.")


def print_comparison(comparison):
    print(f"\nComparison for {comparison['target']}")
    for key in (
        "newly_open", "no_longer_connectable", "unchanged",
        "only_in_before", "only_in_after",
    ):
        values = ", ".join(str(port) for port in comparison[key]) or "none"
        print(f"{key.replace('_', ' ').title()}: {values}")


def run_scan(host, ports, output):
    report = scan_target(host, parse_ports(ports))
    print_scan(report)
    if not output:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        output = f"reports/netguard-{stamp}.json"
    path = save_report(report, output)
    print(f"Saved report: {path}")


def interactive_menu():
    print("\nNETGUARD | Authorized local-network TCP monitoring")
    print("1. Check selected TCP ports")
    print("2. Compare saved JSON reports")
    print("3. Exit")
    while True:
        try:
            choice = input("\nSelect [1-3]: ").strip()
            if choice == "1":
                host = input("Private/loopback IPv4: ")
                ports = input(f"TCP ports [{DEFAULT_PORTS}]: ").strip() or DEFAULT_PORTS
                run_scan(host, ports, output=None)
            elif choice == "2":
                before = input("Earlier report path: ").strip()
                after = input("Later report path: ").strip()
                print_comparison(compare_reports(load_report(before), load_report(after)))
            elif choice == "3":
                print("Goodbye!")
                return
            else:
                print("Please choose 1, 2, or 3.")
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            return


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Monitor selected TCP ports on authorized private/loopback IPv4 hosts."
    )
    parser.add_argument("--version", action="version", version=f"NetGuard {VERSION}")
    commands = parser.add_subparsers(dest="command")
    scan = commands.add_parser("scan", help="Check selected TCP ports and save JSON")
    scan.add_argument("--host", required=True, help="Private/loopback IPv4 address")
    scan.add_argument("--ports", default=DEFAULT_PORTS, help="Comma-separated ports (up to 20)")
    scan.add_argument("--output", help="JSON output path (default: reports/)")
    compare = commands.add_parser("compare", help="Compare two NetGuard JSON reports")
    compare.add_argument("--before", required=True, help="Path to earlier report")
    compare.add_argument("--after", required=True, help="Path to newer report")
    args = parser.parse_args(argv)
    if args.command is None:
        interactive_menu()
        return
    try:
        if args.command == "scan":
            run_scan(args.host, args.ports, args.output)
        elif args.command == "compare":
            print_comparison(compare_reports(load_report(args.before), load_report(args.after)))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
