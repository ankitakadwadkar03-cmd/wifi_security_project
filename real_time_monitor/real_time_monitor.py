"""Main real-time controller for the WiFi security analyzer.

Module 6 for WiFi Real-Time Security and Signal Analyzer.

Runs:
    scanner/wifi_scanner.py
    packet_capture/packet_sniffer.py
    security_report_generator.py
    evil_twin_detector.py

Then reads:
    security_reports/security_report.csv

Writes:
    security_reports/live_alerts.log
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCAN_CSV = Path("scan_results/wifi_scan_results.csv")
DEFAULT_PACKET_CSV = Path("packet_logs/wifi_packets.csv")
DEFAULT_REPORT_CSV = Path("security_reports/final_security_report.csv")
DEFAULT_ALERT_LOG = Path("security_reports/live_alerts.log")
DEFAULT_INTERVAL_SECONDS = 5
DEFAULT_SCANNER_INTERFACE = "wlan0"
DEFAULT_PACKET_INTERFACE = "wlan0mon"
DEFAULT_SCAN_TIMEOUT_SECONDS = 12
DEFAULT_PACKET_TIMEOUT_SECONDS = 10

REQUIRED_COLUMNS = [
    "SSID",
    "BSSID",
    "Encryption",
    "Total_Packets",
    "Deauth_Count",
    "Unknown_MAC_Count",
    "Suspicious_Score",
    "Risk_Level",
    "Attack_Type",
]

RISK_LEVELS = ["SAFE", "LOW RISK", "WARNING", "DANGER"]
ATTACK_TYPES = ["NORMAL", "SUSPICIOUS", "ROGUE_AP", "EVIL_TWIN"]


def load_report(report_csv: str | Path = DEFAULT_REPORT_CSV) -> list[dict[str, str]]:
    """Load the final security report without crashing on missing or empty files."""

    path = Path(report_csv)
    if not path.exists():
        print(f"[WARNING] Security report not found: {path}")
        return []

    if path.stat().st_size == 0:
        print(f"[WARNING] Security report is empty: {path}")
        return []

    try:
        with path.open("r", newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            if reader.fieldnames is None:
                print(f"[WARNING] Security report has no headers: {path}")
                return []

            rows = []
            for row in reader:
                rows.append(_normalize_report_row(row))
            return rows
    except Exception as exc:
        print(f"[WARNING] Could not read security report {path}: {exc}")
        return []


def calculate_summary(report_rows: list[dict[str, str]]) -> dict[str, Any]:
    """Calculate live counts and overall security status."""

    summary: dict[str, Any] = {
        "total_networks": len(report_rows),
        "risk_counts": {risk: 0 for risk in RISK_LEVELS},
        "attack_counts": {attack: 0 for attack in ATTACK_TYPES},
        "overall_status": "SAFE",
    }

    for row in report_rows:
        risk_level = _normalize_choice(row.get("Risk_Level"), RISK_LEVELS, "SAFE")
        attack_type = _normalize_choice(row.get("Attack_Type"), ATTACK_TYPES, "NORMAL")
        summary["risk_counts"][risk_level] += 1
        summary["attack_counts"][attack_type] += 1

    if summary["attack_counts"]["EVIL_TWIN"] > 0 or summary["risk_counts"]["DANGER"] > 0:
        summary["overall_status"] = "CRITICAL"
    elif summary["attack_counts"]["ROGUE_AP"] > 0 or summary["attack_counts"]["SUSPICIOUS"] > 0:
        summary["overall_status"] = "WARNING"

    return summary


def generate_alerts(report_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Create alert events for suspicious, rogue AP, and evil twin rows."""

    alerts: list[dict[str, str]] = []
    for row in report_rows:
        attack_type = _normalize_choice(row.get("Attack_Type"), ATTACK_TYPES, "NORMAL")
        if attack_type == "NORMAL":
            continue

        alerts.append(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ssid": row.get("SSID", "Unknown_Device"),
                "bssid": row.get("BSSID", "Unknown"),
                "attack_type": attack_type,
                "risk_level": _normalize_choice(row.get("Risk_Level"), RISK_LEVELS, "SAFE"),
            }
        )

    return alerts


def write_alert_log(alerts: list[dict[str, str]], log_path: str | Path = DEFAULT_ALERT_LOG) -> None:
    """Append current alerts to the live alert log."""

    if not alerts:
        return

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as log_file:
        for alert in alerts:
            log_file.write(
                "{timestamp} | SSID={ssid} | BSSID={bssid} | Attack_Type={attack_type} | Risk_Level={risk_level}\n".format(
                    **alert
                )
            )


def display_monitor(
    report_rows: list[dict[str, str]],
    summary: dict[str, Any],
    alerts: list[dict[str, str]],
    report_csv: str | Path = DEFAULT_REPORT_CSV,
    pipeline_status: list[str] | None = None,
) -> None:
    """Render the live terminal dashboard."""

    print("\033c", end="")
    print("WiFi Real-Time Security and Signal Analyzer - Real-Time Monitor")
    print(f"Report CSV: {Path(report_csv)}")
    print(f"Last update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Overall Status: {summary['overall_status']}")
    print()

    if pipeline_status:
        print("Pipeline Status")
        for status in pipeline_status:
            print(status)
        print()

    print("Live Summary")
    print(f"Total networks      : {summary['total_networks']}")
    print(f"SAFE networks       : {summary['risk_counts']['SAFE']}")
    print(f"LOW RISK networks   : {summary['risk_counts']['LOW RISK']}")
    print(f"WARNING networks    : {summary['risk_counts']['WARNING']}")
    print(f"DANGER networks     : {summary['risk_counts']['DANGER']}")
    print(f"NORMAL networks     : {summary['attack_counts']['NORMAL']}")
    print(f"SUSPICIOUS networks : {summary['attack_counts']['SUSPICIOUS']}")
    print(f"ROGUE_AP networks   : {summary['attack_counts']['ROGUE_AP']}")
    print(f"EVIL_TWIN networks  : {summary['attack_counts']['EVIL_TWIN']}")
    print()

    print("Attack Type Chart")
    for attack_type in ATTACK_TYPES:
        count = summary["attack_counts"][attack_type]
        print(f"{attack_type.ljust(10)} | {'#' * count} {count}")
    print()

    print("Alerts")
    if not alerts:
        print("No active alerts.")
    else:
        for alert in alerts:
            if alert["attack_type"] == "ROGUE_AP":
                print(f"[ROGUE ALERT] {alert['ssid']} {alert['bssid']}")
            elif alert["attack_type"] == "EVIL_TWIN":
                print(f"[EVIL TWIN ALERT] {alert['ssid']} {alert['bssid']}")
            elif alert["attack_type"] == "SUSPICIOUS":
                print(f"[SUSPICIOUS ALERT] {alert['ssid']} {alert['bssid']}")
    print()

    _print_network_table(report_rows)


def monitor_loop(
    scan_csv: str | Path = DEFAULT_SCAN_CSV,
    packet_csv: str | Path = DEFAULT_PACKET_CSV,
    report_csv: str | Path = DEFAULT_REPORT_CSV,
    interval: int = DEFAULT_INTERVAL_SECONDS,
    once: bool = False,
    log_path: str | Path = DEFAULT_ALERT_LOG,
    scanner_interface: str = DEFAULT_SCANNER_INTERFACE,
    packet_interface: str = DEFAULT_PACKET_INTERFACE,
    scan_timeout: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
    packet_timeout: int = DEFAULT_PACKET_TIMEOUT_SECONDS,
    scanner_no_monitor_setup: bool = False,
) -> None:
    """Run the complete real-time workflow once or continuously."""

    while True:
        pipeline_status = run_realtime_pipeline(
            scan_csv=scan_csv,
            packet_csv=packet_csv,
            report_csv=report_csv,
            scanner_interface=scanner_interface,
            packet_interface=packet_interface,
            scan_timeout=scan_timeout,
            packet_timeout=packet_timeout,
            scanner_no_monitor_setup=scanner_no_monitor_setup,
        )
        report_rows = load_report(report_csv)
        summary = calculate_summary(report_rows)
        alerts = generate_alerts(report_rows)
        write_alert_log(alerts, log_path)
        display_monitor(report_rows, summary, alerts, report_csv, pipeline_status)

        if once:
            return

        time.sleep(interval)


def run_realtime_pipeline(
    scan_csv: str | Path,
    packet_csv: str | Path,
    report_csv: str | Path,
    scanner_interface: str,
    packet_interface: str,
    scan_timeout: int,
    packet_timeout: int,
    scanner_no_monitor_setup: bool,
) -> list[str]:
    """Run Modules 1, 2, 4, and 5 in order and return user-facing status lines."""

    statuses: list[str] = []
    scan_path = PROJECT_ROOT / Path(scan_csv)
    packet_path = PROJECT_ROOT / Path(packet_csv)
    report_path = PROJECT_ROOT / Path(report_csv)

    _delete_if_exists(scan_path)
    _delete_if_exists(packet_path)
    _delete_if_exists(report_path)

    scanner_command = [
        sys.executable,
        str(PROJECT_ROOT / "scanner" / "wifi_scanner.py"),
        "--interface",
        scanner_interface,
        "--output",
        str(scan_csv),
    ]
    if scanner_no_monitor_setup:
        scanner_command.append("--no-monitor-setup")

    statuses.append(
        _run_module_command(
            module_name="Module 1",
            command=scanner_command,
            timeout=scan_timeout,
            expected_output=scan_path,
            timeout_is_success=True,
        )
    )

    statuses.append(
        _run_module_command(
            module_name="Module 2",
            command=[
                sys.executable,
                str(PROJECT_ROOT / "packet_capture" / "packet_sniffer.py"),
                "--interface",
                packet_interface,
                "--output",
                str(packet_csv),
            ],
            timeout=packet_timeout,
            expected_output=packet_path,
            timeout_is_success=True,
        )
    )

    statuses.append(
        _run_module_command(
            module_name="Module 4",
            command=[
                sys.executable,
                str(PROJECT_ROOT / "report_generator" / "security_report_generator.py"),
                "--scan-csv",
                str(scan_csv),
                "--packet-csv",
                str(packet_csv),
                "--report-csv",
                str(report_csv),
            ],
            timeout=max(10, scan_timeout),
            expected_output=report_path,
            timeout_is_success=False,
        )
    )

    statuses.append(
        _run_module_command(
            module_name="Module 5",
            command=[
                sys.executable,
                str(PROJECT_ROOT / "evil_twin_detection" / "evil_twin_detector.py"),
                "--scan-csv",
                str(scan_csv),
                "--packet-csv",
                str(packet_csv),
                "--report-csv",
                str(report_csv),
            ],
            timeout=max(10, packet_timeout),
            expected_output=report_path,
            timeout_is_success=False,
        )
    )

    return statuses


def _run_module_command(
    module_name: str,
    command: list[str],
    timeout: int,
    expected_output: Path,
    timeout_is_success: bool,
) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        if timeout_is_success and _has_fresh_output(expected_output):
            return f"[OK] {module_name} completed"
        return f"[WARNING] {module_name} timed out after {timeout}s: {_compact_output(exc.stderr or exc.stdout)}"
    except Exception as exc:
        return f"[WARNING] {module_name} failed to start: {exc}"

    if result.returncode == 0 and _has_fresh_output(expected_output):
        return f"[OK] {module_name} completed"
    if result.returncode == 0:
        return f"[WARNING] {module_name} finished but did not produce {expected_output.name}"

    output = _compact_output(result.stderr or result.stdout)
    return f"[WARNING] {module_name} failed with exit code {result.returncode}: {output}"


def _delete_if_exists(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except Exception as exc:
        print(f"[WARNING] Could not remove old file {path}: {exc}")


def _has_fresh_output(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def _compact_output(output: object) -> str:
    text = str(output or "").strip()
    if not text:
        return "no output"
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:240]


def _normalize_report_row(row: dict[str, str]) -> dict[str, str]:
    normalized = {}
    for column in REQUIRED_COLUMNS:
        normalized[column] = _clean_text(row.get(column), _default_for_column(column))
    return normalized


def _default_for_column(column: str) -> str:
    return {
        "SSID": "Unknown_Device",
        "BSSID": "Unknown",
        "Encryption": "Unknown",
        "Total_Packets": "0",
        "Deauth_Count": "0",
        "Unknown_MAC_Count": "0",
        "Suspicious_Score": "100",
        "Risk_Level": "SAFE",
        "Attack_Type": "NORMAL",
    }.get(column, "Unknown")


def _normalize_choice(value: str | None, allowed_values: list[str], default: str) -> str:
    cleaned = _clean_text(value, default).upper().replace("-", " ")
    cleaned = " ".join(cleaned.split())
    if cleaned in allowed_values:
        return cleaned
    return default


def _clean_text(value: object, default: str) -> str:
    cleaned = str(value).strip()
    if not cleaned or cleaned.lower() in {"nan", "none", "null"}:
        return default
    return cleaned


def _print_network_table(report_rows: list[dict[str, str]]) -> None:
    headers = ["SSID", "BSSID", "Risk_Level", "Attack_Type", "Score"]
    rows = [
        [
            row["SSID"],
            row["BSSID"],
            row["Risk_Level"],
            row["Attack_Type"],
            row["Suspicious_Score"],
        ]
        for row in report_rows
    ]

    widths = [
        max(len(header), *(len(row[index]) for row in rows)) if rows else len(header)
        for index, header in enumerate(headers)
    ]

    print(_separator(widths))
    print("| " + " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)) + " |")
    print(_separator(widths))

    if not rows:
        message = "No report rows available yet."
        table_width = sum(widths) + (3 * (len(headers) - 1))
        print("| " + message.ljust(table_width) + " |")
    else:
        for row in rows:
            print("| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |")

    print(_separator(widths))


def _separator(widths: list[int]) -> str:
    return "+-" + "-+-".join("-" * width for width in widths) + "-+"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Real-time final WiFi security monitor.")
    parser.add_argument(
        "--report-csv",
        default=str(DEFAULT_REPORT_CSV),
        help="Final security report CSV generated by Module 4 and Module 5.",
    )
    parser.add_argument("--scan-csv", default=str(DEFAULT_SCAN_CSV), help="Fresh Module 1 scan CSV path.")
    parser.add_argument("--packet-csv", default=str(DEFAULT_PACKET_CSV), help="Fresh Module 2 packet CSV path.")
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Refresh interval in seconds.",
    )
    parser.add_argument("--once", action="store_true", help="Run one monitoring cycle and exit.")
    parser.add_argument("--scanner-interface", default=DEFAULT_SCANNER_INTERFACE, help="Adapter for Module 1.")
    parser.add_argument("--packet-interface", default=DEFAULT_PACKET_INTERFACE, help="Monitor interface for Module 2.")
    parser.add_argument(
        "--scanner-no-monitor-setup",
        action="store_true",
        help="Pass --no-monitor-setup to Module 1 when the scanner interface is already in monitor mode.",
    )
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help="Seconds to let Module 1 run each cycle.",
    )
    parser.add_argument(
        "--packet-timeout",
        type=int,
        default=DEFAULT_PACKET_TIMEOUT_SECONDS,
        help="Seconds to let Module 2 capture packets each cycle.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if args.interval < 1:
        print("[WARNING] Interval must be at least 1 second. Using 1 second.")
        args.interval = 1

    try:
        monitor_loop(
            scan_csv=args.scan_csv,
            packet_csv=args.packet_csv,
            report_csv=args.report_csv,
            interval=args.interval,
            once=args.once,
            scanner_interface=args.scanner_interface,
            packet_interface=args.packet_interface,
            scan_timeout=max(1, args.scan_timeout),
            packet_timeout=max(1, args.packet_timeout),
            scanner_no_monitor_setup=args.scanner_no_monitor_setup,
        )
    except KeyboardInterrupt:
        print("\nReal-time monitor stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

