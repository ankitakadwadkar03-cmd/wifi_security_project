"""Real-time terminal security dashboard for WiFi monitoring modules."""

from __future__ import annotations

import argparse
import csv
import signal
import sys
import time
from pathlib import Path
from typing import Any

from security_score import assign_security_score
from threat_detector import NetworkThreatSummary, detect_threats


DEFAULT_SCAN_CSV = Path("scan_results/wifi_scan_results.csv")
DEFAULT_PACKET_CSV = Path("packet_logs/wifi_packets.csv")
DEFAULT_REPORT_CSV = Path("security_reports/security_report.csv")
DEFAULT_REFRESH_SECONDS = 5


class SecurityDashboard:
    """Read module CSV outputs, detect threats, display and save reports."""

    def __init__(
        self,
        scan_csv: str | Path,
        packet_csv: str | Path,
        report_csv: str | Path,
        refresh_seconds: int,
        deauth_threshold: int,
        unknown_mac_threshold: int,
    ) -> None:
        self.scan_csv = Path(scan_csv)
        self.packet_csv = Path(packet_csv)
        self.report_csv = Path(report_csv)
        self.refresh_seconds = refresh_seconds
        self.deauth_threshold = deauth_threshold
        self.unknown_mac_threshold = unknown_mac_threshold
        self.stop_requested = False

    def run(self) -> None:
        while not self.stop_requested:
            summaries = detect_threats(
                scan_csv_path=self.scan_csv,
                packet_csv_path=self.packet_csv,
                deauth_threshold=self.deauth_threshold,
                unknown_mac_threshold=self.unknown_mac_threshold,
            )
            self._save_report(summaries)
            self._print_dashboard(summaries)
            self._sleep_until_next_refresh()

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_requested = True

    def _sleep_until_next_refresh(self) -> None:
        for _ in range(self.refresh_seconds):
            if self.stop_requested:
                return
            time.sleep(1)

    def _save_report(self, summaries: list[NetworkThreatSummary]) -> None:
        self.report_csv.parent.mkdir(parents=True, exist_ok=True)

        with self.report_csv.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=[
                    "SSID",
                    "BSSID",
                    "Encryption",
                    "Packet Count",
                    "Threat Detected",
                    "Security Level",
                    "Deauthentication Count",
                    "Unknown MAC Packet Count",
                    "Suspicious Packet Count",
                ],
            )
            writer.writeheader()

            for summary in summaries:
                writer.writerow(
                    {
                        "SSID": summary.ssid,
                        "BSSID": summary.bssid,
                        "Encryption": summary.encryption,
                        "Packet Count": summary.packet_count,
                        "Threat Detected": summary.threat_detected,
                        "Security Level": assign_security_score(summary),
                        "Deauthentication Count": summary.deauth_count,
                        "Unknown MAC Packet Count": summary.unknown_mac_count,
                        "Suspicious Packet Count": summary.suspicious_packet_count,
                    }
                )

    def _print_dashboard(self, summaries: list[NetworkThreatSummary]) -> None:
        headers = ["SSID","Device Type", "Encryption", "Packet Count", "Threat Detected", "Security Level"]
        rows = [
            [
                summary.ssid,
                "Unknown Device" if summary.ssid == "Unknown_Device" else "Access Point",
                summary.encryption,
                str(summary.packet_count),
                summary.threat_detected,
                assign_security_score(summary),
            ]
            for summary in summaries
        ]

        widths = [
            max(len(header), *(len(row[index]) for row in rows)) if rows else len(header)
            for index, header in enumerate(headers)
        ]

        print("\033c", end="")
        print("WiFi Real-Time Security and Signal Analyzer - Security Dashboard")
        print(f"Scan CSV: {self.scan_csv}")
        print(f"Packet CSV: {self.packet_csv}")
        print(f"Report CSV: {self.report_csv}")
        print(f"Last update: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(self._separator(widths))
        print("| " + " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)) + " |")
        print(self._separator(widths))

        if not rows:
            message = "No CSV data found yet. Start Module 1 and Module 2 to populate the dashboard."
            table_width = sum(widths) + (3 * (len(headers) - 1))
            print("| " + message.ljust(table_width) + " |")
        else:
            for row in rows:
                print("| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |")

        print(self._separator(widths))

    @staticmethod
    def _separator(widths: list[int]) -> str:
        return "+-" + "-+-".join("-" * width for width in widths) + "-+"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Real-time WiFi security dashboard")
    parser.add_argument("--scan-csv", default=str(DEFAULT_SCAN_CSV), help="Module 1 scan CSV path.")
    parser.add_argument("--packet-csv", default=str(DEFAULT_PACKET_CSV), help="Module 2 packet CSV path.")
    parser.add_argument("--report-csv", default=str(DEFAULT_REPORT_CSV), help="Security report CSV output path.")
    parser.add_argument("--refresh", type=int, default=DEFAULT_REFRESH_SECONDS, help="Refresh interval in seconds.")
    parser.add_argument("--deauth-threshold", type=int, default=10, help="Deauth packet threshold for DANGER.")
    parser.add_argument(
        "--unknown-mac-threshold",
        type=int,
        default=50,
        help="Repeated unknown MAC packet threshold for DANGER.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if args.refresh < 1:
        print("Refresh interval must be at least 1 second.", file=sys.stderr)
        return 1

    dashboard = SecurityDashboard(
        scan_csv=args.scan_csv,
        packet_csv=args.packet_csv,
        report_csv=args.report_csv,
        refresh_seconds=args.refresh,
        deauth_threshold=args.deauth_threshold,
        unknown_mac_threshold=args.unknown_mac_threshold,
    )

    signal.signal(signal.SIGINT, dashboard.request_stop)
    signal.signal(signal.SIGTERM, dashboard.request_stop)

    try:
        dashboard.run()
    except PermissionError:
        print("Permission denied while reading CSV files or writing security report.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected dashboard error: {exc}", file=sys.stderr)
        return 1

    print("\nSecurity dashboard stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
