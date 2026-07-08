import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


DEFAULT_SCAN_CSV = Path("scan_results/wifi_scan_results.csv")
DEFAULT_TRUSTED_CSV = Path("trusted_baseline/trusted_networks.csv")
DEFAULT_OUTPUT_CSV = Path("security_reports/trusted_baseline_report.csv")
DEFAULT_OUTPUT_JSON = Path("security_reports/trusted_baseline_report.json")


WEAK_ENCRYPTION_VALUES = {"OPEN", "WEP"}


def normalize_text(value):
    return str(value).strip()


def normalize_key(value):
    return normalize_text(value).lower()


def normalize_mac(value):
    mac = normalize_text(value).upper()

    if not mac or mac in {"NAN", "NONE", "UNKNOWN"}:
        return "UNKNOWN"

    return mac


def read_csv_rows(path):
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def write_csv_report(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "SSID",
        "BSSID",
        "Channel",
        "Signal",
        "Encryption",
        "Baseline_Status",
        "Threat_Type",
        "Severity",
        "Confidence",
        "Trusted_BSSID",
        "Location",
        "Owner",
        "Evidence",
        "Recommended_Action",
        "Scan_Time",
    ]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_json_report(path, rows, summary):
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summary,
        "findings": rows,
    }

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def build_trusted_indexes(trusted_rows):
    trusted_by_bssid = {}
    trusted_by_ssid = defaultdict(dict)

    for row in trusted_rows:
        ssid = normalize_text(row.get("SSID", ""))
        bssid = normalize_mac(row.get("BSSID", ""))

        if not ssid or bssid == "UNKNOWN":
            continue

        ssid_key = normalize_key(ssid)

        trusted_record = {
            "SSID": ssid,
            "BSSID": bssid,
            "Location": normalize_text(row.get("Location", "")),
            "Owner": normalize_text(row.get("Owner", "")),
            "Notes": normalize_text(row.get("Notes", "")),
        }

        trusted_by_bssid[bssid] = trusted_record
        trusted_by_ssid[ssid_key][bssid] = trusted_record

    return trusted_by_bssid, trusted_by_ssid


def build_scan_ssid_index(scan_rows):
    scan_bssids_by_ssid = defaultdict(set)

    for row in scan_rows:
        ssid = normalize_text(row.get("SSID", ""))
        bssid = normalize_mac(row.get("BSSID", ""))

        if ssid and bssid != "UNKNOWN":
            scan_bssids_by_ssid[normalize_key(ssid)].add(bssid)

    return scan_bssids_by_ssid


def classify_network(row, trusted_by_bssid, trusted_by_ssid, scan_bssids_by_ssid):
    ssid = normalize_text(row.get("SSID", ""))
    ssid_key = normalize_key(ssid)
    bssid = normalize_mac(row.get("BSSID", ""))
    channel = normalize_text(row.get("Channel", ""))
    signal = normalize_text(row.get("Signal", ""))
    encryption = normalize_text(row.get("Encryption", "Unknown"))
    encryption_key = encryption.upper()

    trusted_records_for_ssid = trusted_by_ssid.get(ssid_key, {})
    trusted_bssids_for_ssid = sorted(trusted_records_for_ssid.keys())
    duplicate_ssid_seen = len(scan_bssids_by_ssid.get(ssid_key, set())) > 1

    evidence = []
    recommended_action = []
    trusted_bssid_display = ", ".join(trusted_bssids_for_ssid)

    baseline_status = "UNTRUSTED"
    threat_type = "UNTRUSTED_NETWORK"
    severity = "MEDIUM"
    confidence = 50
    location = ""
    owner = ""

    exact_trusted_match = (
        bssid in trusted_by_bssid
        and normalize_key(trusted_by_bssid[bssid]["SSID"]) == ssid_key
    )

    if exact_trusted_match:
        trusted_record = trusted_by_bssid[bssid]

        baseline_status = "TRUSTED"
        threat_type = "NORMAL"
        severity = "LOW"
        confidence = 10
        location = trusted_record.get("Location", "")
        owner = trusted_record.get("Owner", "")

        evidence.append("SSID and BSSID match the trusted baseline.")
        recommended_action.append("No immediate action required.")

        if duplicate_ssid_seen:
            evidence.append(
                "Another BSSID with the same SSID was also seen in the current scan."
            )
            recommended_action.append(
                "Review duplicate SSID entries to rule out Evil Twin indicators."
            )

    elif trusted_records_for_ssid:
        baseline_status = "SSID_MATCH_BSSID_MISMATCH"
        threat_type = "POSSIBLE_EVIL_TWIN_INDICATOR"
        severity = "HIGH"
        confidence = 80

        evidence.append(
            "SSID matches a trusted network, but the detected BSSID is not in the trusted baseline."
        )
        evidence.append(f"Trusted BSSID(s) for this SSID: {trusted_bssid_display}")

        if duplicate_ssid_seen:
            confidence += 10
            evidence.append("Duplicate SSID observed with multiple BSSIDs in current scan.")

        recommended_action.append(
            "Verify physical router ownership and compare the router MAC/BSSID."
        )
        recommended_action.append(
            "Do not mark as confirmed attack until manually validated."
        )

    elif encryption_key in WEAK_ENCRYPTION_VALUES:
        baseline_status = "NOT_IN_BASELINE"
        threat_type = "WEAK_OR_OPEN_NETWORK"
        severity = "MEDIUM"
        confidence = 65

        evidence.append("Network is not present in trusted baseline.")
        evidence.append(f"Encryption type is {encryption}, which requires review.")
        recommended_action.append(
            "Avoid sensitive activity on open or weakly encrypted networks."
        )
        recommended_action.append(
            "Add to trusted baseline only if it is authorized and expected."
        )

    else:
        baseline_status = "NOT_IN_BASELINE"
        threat_type = "UNKNOWN_NETWORK"
        severity = "MEDIUM"
        confidence = 55

        evidence.append("SSID and BSSID are not present in trusted baseline.")
        recommended_action.append(
            "Verify whether this access point is authorized in the monitored area."
        )
        recommended_action.append(
            "Add it to trusted baseline if it is a legitimate network."
        )

    confidence = min(confidence, 95)

    return {
        "SSID": ssid,
        "BSSID": bssid,
        "Channel": channel,
        "Signal": signal,
        "Encryption": encryption,
        "Baseline_Status": baseline_status,
        "Threat_Type": threat_type,
        "Severity": severity,
        "Confidence": str(confidence),
        "Trusted_BSSID": trusted_bssid_display,
        "Location": location,
        "Owner": owner,
        "Evidence": " | ".join(evidence),
        "Recommended_Action": " | ".join(recommended_action),
        "Scan_Time": datetime.now().isoformat(timespec="seconds"),
    }


def build_summary(report_rows):
    summary = {
        "total_networks": len(report_rows),
        "trusted": 0,
        "possible_evil_twin_indicators": 0,
        "unknown_networks": 0,
        "weak_or_open_networks": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
    }

    for row in report_rows:
        threat_type = row["Threat_Type"]
        severity = row["Severity"]

        if row["Baseline_Status"] == "TRUSTED":
            summary["trusted"] += 1

        if threat_type == "POSSIBLE_EVIL_TWIN_INDICATOR":
            summary["possible_evil_twin_indicators"] += 1

        if threat_type == "UNKNOWN_NETWORK":
            summary["unknown_networks"] += 1

        if threat_type == "WEAK_OR_OPEN_NETWORK":
            summary["weak_or_open_networks"] += 1

        if severity == "HIGH":
            summary["high_severity"] += 1
        elif severity == "MEDIUM":
            summary["medium_severity"] += 1
        elif severity == "LOW":
            summary["low_severity"] += 1

    return summary


def print_summary(summary, output_csv, output_json):
    print("\nTrusted Baseline Check Completed")
    print("--------------------------------")
    print(f"Total Networks                 : {summary['total_networks']}")
    print(f"Trusted Networks               : {summary['trusted']}")
    print(f"Possible Evil Twin Indicators  : {summary['possible_evil_twin_indicators']}")
    print(f"Unknown Networks               : {summary['unknown_networks']}")
    print(f"Weak/Open Networks             : {summary['weak_or_open_networks']}")
    print(f"High Severity Findings         : {summary['high_severity']}")
    print(f"Medium Severity Findings       : {summary['medium_severity']}")
    print(f"Low Severity Findings          : {summary['low_severity']}")
    print(f"\n[OK] CSV report saved to  : {output_csv}")
    print(f"[OK] JSON report saved to : {output_json}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare WiFi scan results with trusted SSID/BSSID baseline."
    )

    parser.add_argument(
        "--scan-csv",
        default=str(DEFAULT_SCAN_CSV),
        help="Path to wifi_scan_results.csv",
    )

    parser.add_argument(
        "--trusted-csv",
        default=str(DEFAULT_TRUSTED_CSV),
        help="Path to trusted_networks.csv",
    )

    parser.add_argument(
        "--output-csv",
        default=str(DEFAULT_OUTPUT_CSV),
        help="Path to output CSV report",
    )

    parser.add_argument(
        "--output-json",
        default=str(DEFAULT_OUTPUT_JSON),
        help="Path to output JSON report",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    scan_csv = Path(args.scan_csv)
    trusted_csv = Path(args.trusted_csv)
    output_csv = Path(args.output_csv)
    output_json = Path(args.output_json)

    scan_rows = read_csv_rows(scan_csv)
    trusted_rows = read_csv_rows(trusted_csv)

    trusted_by_bssid, trusted_by_ssid = build_trusted_indexes(trusted_rows)
    scan_bssids_by_ssid = build_scan_ssid_index(scan_rows)

    report_rows = [
        classify_network(
            row,
            trusted_by_bssid,
            trusted_by_ssid,
            scan_bssids_by_ssid,
        )
        for row in scan_rows
    ]

    summary = build_summary(report_rows)

    write_csv_report(output_csv, report_rows)
    write_json_report(output_json, report_rows, summary)

    print_summary(summary, output_csv, output_json)


if __name__ == "__main__":
    main()
