"""Final consolidated security report generator.

Module 4 for WiFi Real-Time Security and Signal Analyzer.

Reads:
    scan_results/wifi_scan_results.csv
    packet_logs/wifi_packets.csv

Writes:
    security_reports/security_report.csv
"""

from __future__ import annotations

import argparse
import sys
import csv
from pathlib import Path

DEFAULT_SCAN_CSV = Path("scan_results/wifi_scan_results.csv")
DEFAULT_PACKET_CSV = Path("packet_logs/wifi_packets.csv")
DEFAULT_REPORT_CSV = Path("security_reports/final_security_report.csv")

REPORT_COLUMNS = [
    "SSID",
    "BSSID",
    "Encryption",
    "Total_Packets",
    "Deauth_Count",
    "Unknown_MAC_Count",
    "Suspicious_Score",
    "Risk_Level",
]

SCAN_COLUMNS = ["SSID", "BSSID", "Encryption"]
PACKET_COLUMNS = ["BSSID", "Packet Type", "Source MAC", "Destination MAC"]


def load_scan_data(scan_csv_path: str | Path = DEFAULT_SCAN_CSV) -> list[dict[str, str]] | None:
    """Load Module 1 WiFi scan data with graceful column handling."""

    path = Path(scan_csv_path)
    if not path.exists():
        print(f"[WARNING] Scan CSV missing: {path}")
        return None

    try:
        scan_rows = _read_csv(path)
    except Exception as exc:
        print(f"[WARNING] Could not read scan CSV {path}: {exc}")
        return None

    return _ensure_columns(scan_rows, SCAN_COLUMNS)


def load_packet_data(packet_csv_path: str | Path = DEFAULT_PACKET_CSV) -> list[dict[str, str]] | None:
    """Load Module 2 packet log data with graceful column handling."""

    path = Path(packet_csv_path)
    if not path.exists():
        print(f"[WARNING] Packet CSV missing: {path}")
        return None

    try:
        packet_rows = _read_csv(path)
    except Exception as exc:
        print(f"[WARNING] Could not read packet CSV {path}: {exc}")
        return None

    return _ensure_columns(packet_rows, PACKET_COLUMNS)


def compute_metrics(
    scan_data: list[dict[str, str]],
    packet_data: list[dict[str, str]],
    unknown_mac_threshold: int = 50,
) -> list[dict[str, object]]:
    """Combine scan and packet data into per-network security metrics."""

    normalized_scan = _normalize_scan_data(scan_data)
    normalized_packets = _normalize_packet_data(packet_data)

    if not normalized_scan and not normalized_packets:
        return []

    known_bssids = set(normalized_scan.keys())
    source_counts: dict[str, int] = {}

    for packet in normalized_packets:
        source_mac = packet["Source MAC"]
        if source_mac not in {"Unknown", "Broadcast"}:
            source_counts[source_mac] = source_counts.get(source_mac, 0) + 1

    unknown_flooding_macs = {
        mac for mac, count in source_counts.items() if mac not in known_bssids and count >= unknown_mac_threshold
    }

    packets_by_bssid: dict[str, list[dict[str, str]]] = {}
    for packet in normalized_packets:
        resolved_bssid = _resolve_packet_bssid(packet, known_bssids)
        packet["Resolved_BSSID"] = resolved_bssid
        packets_by_bssid.setdefault(resolved_bssid, []).append(packet)

    metric_rows: list[dict[str, object]] = []

    # The network report must contain only access points detected
    # by the WiFi scanner. Packet-only MAC addresses are clients
    # or broadcast devices and do not have an SSID.
    all_bssids = set(normalized_scan.keys())

    for bssid in sorted(all_bssids):
        if not bssid or bssid == "Unknown":
            ssid = "Unknown_Device"
            encryption = "Unknown"
        else:
            network = normalized_scan.get(bssid, {})
            ssid = network.get("SSID", "Unknown_Device")
            encryption = network.get("Encryption", "Unknown")

        network_packets = packets_by_bssid.get(bssid, [])
        total_packets = len(network_packets)
        deauth_count = sum(1 for packet in network_packets if packet["Packet Type"].lower() == "deauthentication")
        unknown_mac_count = sum(1 for packet in network_packets if packet["Source MAC"] in unknown_flooding_macs)
        suspicious_behavior = _has_suspicious_packet_behavior(
            total_packets=total_packets,
            deauth_count=deauth_count,
            unknown_mac_count=unknown_mac_count,
        )

        score = calculate_security_score(
            encryption=encryption,
            deauth_count=deauth_count,
            unknown_mac_count=unknown_mac_count,
            suspicious_behavior=suspicious_behavior,
        )

        metric_rows.append(
            {
                "SSID": ssid,
                "BSSID": bssid,
                "Encryption": encryption,
                "Total_Packets": total_packets,
                "Deauth_Count": deauth_count,
                "Unknown_MAC_Count": unknown_mac_count,
                "Suspicious_Score": score,
                "Risk_Level": classify_risk_level(score),
            }
        )

    return metric_rows


def calculate_security_score(
    encryption: str,
    deauth_count: int,
    unknown_mac_count: int,
    suspicious_behavior: bool,
) -> int:
    """Calculate final 0-100 security score using Module 4 scoring rules."""

    score = 100
    normalized_encryption = str(encryption).strip().lower()

    if deauth_count > 0:
        score -= 30
    if unknown_mac_count > 0:
        score -= 25
    if suspicious_behavior:
        score -= 15
    if normalized_encryption in {"open", "wep"}:
        score -= 20

    return max(0, min(100, score))


def classify_risk_level(score: int) -> str:
    """Convert numeric score into SAFE, LOW RISK, WARNING, or DANGER."""

    if score >= 80:
        return "SAFE"
    if score >= 60:
        return "LOW RISK"
    if score >= 40:
        return "WARNING"
    return "DANGER"


def generate_security_report(
    scan_csv_path: str | Path = DEFAULT_SCAN_CSV,
    packet_csv_path: str | Path = DEFAULT_PACKET_CSV,
    report_csv_path: str | Path = DEFAULT_REPORT_CSV,
    unknown_mac_threshold: int = 50,
) -> list[dict[str, object]] | None:
    """Generate and save the final consolidated security report."""

    scan_df = load_scan_data(scan_csv_path)
    packet_df = load_packet_data(packet_csv_path)

    if scan_df is None or packet_df is None:
        print("[WARNING] Required input CSV file is missing or unreadable. Report generation stopped safely.")
        return None

    report_rows = compute_metrics(
        scan_data=scan_df,
        packet_data=packet_df,
        unknown_mac_threshold=unknown_mac_threshold,
    )

    output_path = Path(report_csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_report_csv(output_path, report_rows)

    print(f"[OK] Security report saved to: {output_path}")
    _print_report_table(report_rows)
    return report_rows


def _read_csv(path: Path) -> list[dict[str, str]]:
    if path.stat().st_size == 0:
        return []

    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return [dict(row) for row in csv.DictReader(csv_file)]


def _write_report_csv(path: Path, report_rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=REPORT_COLUMNS)
        writer.writeheader()
        writer.writerows(report_rows)


def _ensure_columns(rows: list[dict[str, str]], required_columns: list[str]) -> list[dict[str, str]]:
    if not rows:
        return []

    available_columns = set().union(*(row.keys() for row in rows))
    for column in required_columns:
        if column not in available_columns:
            print(f"[WARNING] Missing column '{column}'. Filling with Unknown.")
            break

    safe_rows: list[dict[str, str]] = []
    for row in rows:
        safe_rows.append({column: row.get(column) or "Unknown" for column in required_columns})
    return safe_rows


def _normalize_scan_data(scan_rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}

    for row in scan_rows:
        bssid = _normalize_mac(row.get("BSSID"))
        if bssid == "Unknown":
            continue

        normalized[bssid] = {
            "SSID": _clean_text(row.get("SSID"), "Unknown_Device"),
            "BSSID": bssid,
            "Encryption": _clean_text(row.get("Encryption"), "Unknown"),
        }

    return normalized


def _normalize_packet_data(packet_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []

    for row in packet_rows:
        normalized.append(
            {
                "BSSID": _normalize_mac(row.get("BSSID")),
                "Packet Type": _clean_text(row.get("Packet Type"), "Unknown"),
                "Source MAC": _normalize_mac(row.get("Source MAC")),
                "Destination MAC": _normalize_mac(row.get("Destination MAC")),
            }
        )

    return normalized


def _resolve_packet_bssid(row: dict[str, str], known_bssids: set[str]) -> str:
    bssid = row.get("BSSID", "Unknown")
    source_mac = row.get("Source MAC", "Unknown")
    destination_mac = row.get("Destination MAC", "Unknown")

    if bssid not in {"Unknown", "Broadcast"}:
        return bssid
    if source_mac in known_bssids:
        return source_mac
    if destination_mac in known_bssids:
        return destination_mac
    return "Unknown"


def _has_suspicious_packet_behavior(total_packets: int, deauth_count: int, unknown_mac_count: int) -> bool:
    return deauth_count > 0 or unknown_mac_count > 0 or total_packets >= 1000


def _normalize_mac(mac_address: object) -> str:
    cleaned = str(mac_address).strip()
    if not cleaned or cleaned.lower() in {"nan", "none", "unknown"}:
        return "Unknown"
    if cleaned.lower() == "ff:ff:ff:ff:ff:ff":
        return "Broadcast"
    return cleaned.upper()


def _clean_text(value: object, default: str) -> str:
    cleaned = str(value).strip()
    if not cleaned or cleaned.lower() in {"nan", "none"}:
        return default
    return cleaned


def _print_report_table(report_rows: list[dict[str, object]]) -> None:
    headers = ["SSID", "BSSID", "Encryption", "Packets", "Score", "Risk Level"]
    rows = [
        [
            str(row["SSID"]),
            str(row["BSSID"]),
            str(row["Encryption"]),
            str(row["Total_Packets"]),
            str(row["Suspicious_Score"]),
            str(row["Risk_Level"]),
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
        message = "No scan or packet data available. Empty report generated with headers."
        table_width = sum(widths) + (3 * (len(headers) - 1))
        print("| " + message.ljust(table_width) + " |")
    else:
        for row in rows:
            print("| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |")

    print(_separator(widths))


def _separator(widths: list[int]) -> str:
    return "+-" + "-+-".join("-" * width for width in widths) + "-+"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate consolidated WiFi security report.")
    parser.add_argument("--scan-csv", default=str(DEFAULT_SCAN_CSV), help="Module 1 scan CSV path.")
    parser.add_argument("--packet-csv", default=str(DEFAULT_PACKET_CSV), help="Module 2 packet CSV path.")
    parser.add_argument("--report-csv", default=str(DEFAULT_REPORT_CSV), help="Output security report CSV path.")
    parser.add_argument(
        "--unknown-mac-threshold",
        type=int,
        default=50,
        help="Packets from an unknown source MAC before it is treated as flooding.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    report_rows = generate_security_report(
        scan_csv_path=args.scan_csv,
        packet_csv_path=args.packet_csv,
        report_csv_path=args.report_csv,
        unknown_mac_threshold=args.unknown_mac_threshold,
    )
    return 0 if report_rows is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
