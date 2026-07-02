"""Rogue AP and Evil Twin detector.

Module 5 for WiFi Real-Time Security and Signal Analyzer.

Reads:
    scan_results/wifi_scan_results.csv
    packet_logs/wifi_packets.csv
    security_reports/final_security_report.csv

Updates:
    security_reports/final_security_report.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


DEFAULT_SCAN_CSV = Path("scan_results/wifi_scan_results.csv")
DEFAULT_PACKET_CSV = Path("packet_logs/wifi_packets.csv")
DEFAULT_REPORT_CSV = Path("security_reports/final_security_report.csv")

ATTACK_NORMAL = "NORMAL"
ATTACK_ROGUE_AP = "ROGUE_AP"
ATTACK_EVIL_TWIN = "EVIL_TWIN"
ATTACK_SUSPICIOUS = "SUSPICIOUS"

REPORT_BASE_COLUMNS = [
    "SSID",
    "BSSID",
    "Encryption",
    "Total_Packets",
    "Deauth_Count",
    "Unknown_MAC_Count",
    "Suspicious_Score",
    "Risk_Level",
]


def load_scan_data(scan_csv_path: str | Path = DEFAULT_SCAN_CSV) -> list[dict[str, str]] | None:
    """Load Module 1 scan CSV."""

    path = Path(scan_csv_path)
    if not path.exists():
        print(f"[WARNING] Scan CSV missing: {path}")
        return None

    return _read_csv_with_required_columns(path, ["SSID", "BSSID", "Encryption"])


def load_packet_data(packet_csv_path: str | Path = DEFAULT_PACKET_CSV) -> list[dict[str, str]] | None:
    """Load Module 2 packet CSV."""

    path = Path(packet_csv_path)
    if not path.exists():
        print(f"[WARNING] Packet CSV missing: {path}")
        return None

    return _read_csv_with_required_columns(path, ["BSSID", "Packet Type", "Source MAC", "Destination MAC"])


def detect_rogue_ap(
    scan_rows: list[dict[str, str]],
    packet_rows: list[dict[str, str]],
) -> set[str]:
    """Return BSSIDs seen in packet logs but absent from scan results."""

    scanned_bssids = {_normalize_mac(row.get("BSSID")) for row in scan_rows}
    scanned_bssids.discard("Unknown")
    scanned_bssids.discard("Broadcast")

    packet_bssids: set[str] = set()
    for row in packet_rows:
        bssid = _normalize_mac(row.get("BSSID"))
        if bssid not in {"Unknown", "Broadcast"}:
            packet_bssids.add(bssid)

    return {bssid for bssid in packet_bssids - scanned_bssids if bssid not in {"Unknown", "Broadcast"}}

def detect_evil_twin(report_rows: list[dict[str, str]]) -> set[str]:
    """Return BSSIDs that look like evil twins inside same-SSID groups."""

    rows_by_ssid: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in report_rows:
        ssid = _clean_text(row.get("SSID"), "Unknown_Device")
        bssid = _normalize_mac(row.get("BSSID"))
        if ssid != "Unknown_Device" and bssid not in {"Unknown", "Broadcast"}:
            rows_by_ssid[ssid].append(row)

    evil_twin_bssids: set[str] = set()

    for ssid, rows in rows_by_ssid.items():
        unique_bssids = {_normalize_mac(row.get("BSSID")) for row in rows}
        if len(unique_bssids) < 2:
            continue

        encryptions = {_clean_text(row.get("Encryption"), "Unknown").upper() for row in rows}
        packet_counts = [_to_int(row.get("Total_Packets")) for row in rows]
        scores = [_to_int(row.get("Suspicious_Score"), default=100) for row in rows]
        median_packets = _median(packet_counts)
        average_score = sum(scores) / len(scores) if scores else 100

        ssid_alerted = False
        for row in rows:
            bssid = _normalize_mac(row.get("BSSID"))
            encryption_differs = len(encryptions) > 1
            significantly_higher_packets = _to_int(row.get("Total_Packets")) >= max(50, median_packets * 2)
            abnormal_score = abs(_to_int(row.get("Suspicious_Score"), default=100) - average_score) >= 20
            risky_level = _clean_text(row.get("Risk_Level"), "SAFE").upper() in {"WARNING", "DANGER"}

            if encryption_differs or significantly_higher_packets or abnormal_score or risky_level:
                evil_twin_bssids.add(bssid)
                if not ssid_alerted:
                    print(f"[EVIL TWIN DETECTED] {ssid}")
                    ssid_alerted = True

    return evil_twin_bssids


def classify_attack(
    report_row: dict[str, str],
    rogue_bssids: set[str],
    evil_twin_bssids: set[str],
) -> str:
    """Classify one network as NORMAL, ROGUE_AP, EVIL_TWIN, or SUSPICIOUS."""

    bssid = _normalize_mac(report_row.get("BSSID"))

    if bssid in rogue_bssids:
        return ATTACK_ROGUE_AP
    if bssid in evil_twin_bssids:
        return ATTACK_EVIL_TWIN
    if _has_packet_anomalies(report_row):
        return ATTACK_SUSPICIOUS
    return ATTACK_NORMAL


def update_security_report(
    scan_csv_path: str | Path = DEFAULT_SCAN_CSV,
    packet_csv_path: str | Path = DEFAULT_PACKET_CSV,
    report_csv_path: str | Path = DEFAULT_REPORT_CSV,
) -> list[dict[str, str]] | None:
    """Append/update Attack_Type in Module 4 security report."""

    scan_rows = load_scan_data(scan_csv_path)
    packet_rows = load_packet_data(packet_csv_path)
    report_path = Path(report_csv_path)

    if scan_rows is None or packet_rows is None:
        print("[WARNING] Required scan or packet CSV is missing. Evil Twin detection stopped safely.")
        return None
    if not report_path.exists():
        print(f"[WARNING] Security report missing: {report_path}")
        return None

    report_rows = _read_csv_with_required_columns(report_path, REPORT_BASE_COLUMNS)
    rogue_bssids = detect_rogue_ap(scan_rows, packet_rows)
    report_rows = _add_missing_rogue_rows(report_rows, packet_rows, rogue_bssids)
    evil_twin_bssids = detect_evil_twin(report_rows)

    for bssid in sorted(rogue_bssids):
        print(f"[ROGUE AP DETECTED] {bssid}")

    updated_rows: list[dict[str, str]] = []
    for row in report_rows:
        updated_row = dict(row)
        updated_row["Attack_Type"] = classify_attack(updated_row, rogue_bssids, evil_twin_bssids)
        updated_rows.append(updated_row)

    fieldnames = _merge_fieldnames(report_rows, REPORT_BASE_COLUMNS + ["Attack_Type"])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(updated_rows)

    print(f"[OK] Updated security report with Attack_Type: {report_path}")
    _print_attack_summary(updated_rows)
    return updated_rows


def _read_csv_with_required_columns(path: Path, required_columns: list[str]) -> list[dict[str, str]]:
    if path.stat().st_size == 0:
        return [{column: "" for column in required_columns}]

    with path.open("r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        rows = [dict(row) for row in reader]

    if not rows:
        return []

    available_columns = set().union(*(row.keys() for row in rows))
    for column in required_columns:
        if column not in available_columns:
            print(f"[WARNING] Missing column '{column}' in {path}. Filling with Unknown.")

    normalized_rows: list[dict[str, str]] = []
    for row in rows:
        safe_row = dict(row)
        for column in required_columns:
            safe_row[column] = safe_row.get(column) or "Unknown"
        normalized_rows.append(safe_row)

    return normalized_rows


def _add_missing_rogue_rows(
    report_rows: list[dict[str, str]],
    packet_rows: list[dict[str, str]],
    rogue_bssids: set[str],
) -> list[dict[str, str]]:
    existing_report_bssids = {_normalize_mac(row.get("BSSID")) for row in report_rows}
    rows_by_bssid: dict[str, list[dict[str, str]]] = defaultdict(list)

    for packet in packet_rows:
        bssid = _normalize_mac(packet.get("BSSID"))
        if bssid in rogue_bssids:
            rows_by_bssid[bssid].append(packet)

    updated_rows = list(report_rows)
    for bssid in sorted(rogue_bssids - existing_report_bssids):
        packets = rows_by_bssid.get(bssid, [])
        deauth_count = sum(1 for packet in packets if _clean_text(packet.get("Packet Type"), "").lower() == "deauthentication")
        total_packets = len(packets)
        suspicious_score = 40 if deauth_count else 60
        updated_rows.append(
            {
                "SSID": "Unknown_Device",
                "BSSID": bssid,
                "Encryption": "Unknown",
                "Total_Packets": str(total_packets),
                "Deauth_Count": str(deauth_count),
                "Unknown_MAC_Count": "0",
                "Suspicious_Score": str(suspicious_score),
                "Risk_Level": "WARNING" if suspicious_score >= 40 else "DANGER",
            }
        )

    return updated_rows


def _has_packet_anomalies(row: dict[str, str]) -> bool:
    risk_level = _clean_text(row.get("Risk_Level"), "SAFE").upper()
    score = _to_int(row.get("Suspicious_Score"), default=100)
    total_packets = _to_int(row.get("Total_Packets"))
    deauth_count = _to_int(row.get("Deauth_Count"))
    unknown_mac_count = _to_int(row.get("Unknown_MAC_Count"))

    return (
        risk_level in {"LOW RISK", "WARNING", "DANGER"}
        or score < 80
        or total_packets >= 1000
        or deauth_count > 0
        or unknown_mac_count > 0
    )


def _merge_fieldnames(rows: list[dict[str, str]], preferred: list[str]) -> list[str]:
    fieldnames = list(preferred)
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    return fieldnames


def _print_attack_summary(rows: list[dict[str, str]]) -> None:
    headers = ["SSID", "BSSID", "Attack_Type"]
    table_rows = [[row.get("SSID", ""), row.get("BSSID", ""), row.get("Attack_Type", "")] for row in rows]
    widths = [
        max(len(header), *(len(table_row[index]) for table_row in table_rows)) if table_rows else len(header)
        for index, header in enumerate(headers)
    ]

    print(_separator(widths))
    print("| " + " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)) + " |")
    print(_separator(widths))
    for table_row in table_rows:
        print("| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(table_row)) + " |")
    print(_separator(widths))


def _median(values: list[int]) -> float:
    if not values:
        return 0.0

    sorted_values = sorted(values)
    middle = len(sorted_values) // 2
    if len(sorted_values) % 2:
        return float(sorted_values[middle])
    return (sorted_values[middle - 1] + sorted_values[middle]) / 2


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _normalize_mac(mac_address: object) -> str:
    cleaned = str(mac_address).strip()
    if not cleaned or cleaned.lower() in {"nan", "none", "unknown"}:
        return "Unknown"
    if cleaned.lower() in {"broadcast", "ff:ff:ff:ff:ff:ff"}:
        return "Broadcast"
    return cleaned.upper()


def _clean_text(value: object, default: str) -> str:
    cleaned = str(value).strip()
    if not cleaned or cleaned.lower() in {"nan", "none"}:
        return default
    return cleaned


def _separator(widths: list[int]) -> str:
    return "+-" + "-+-".join("-" * width for width in widths) + "-+"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect rogue AP and evil twin attacks.")
    parser.add_argument("--scan-csv", default=str(DEFAULT_SCAN_CSV), help="Module 1 scan CSV path.")
    parser.add_argument("--packet-csv", default=str(DEFAULT_PACKET_CSV), help="Module 2 packet CSV path.")
    parser.add_argument("--report-csv", default=str(DEFAULT_REPORT_CSV), help="Security report CSV path to update.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    updated_rows = update_security_report(
        scan_csv_path=args.scan_csv,
        packet_csv_path=args.packet_csv,
        report_csv_path=args.report_csv,
    )
    return 0 if updated_rows is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
