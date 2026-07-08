import argparse
import csv
import json
from datetime import datetime
from pathlib import Path


DEFAULT_BASELINE_REPORT = Path("security_reports/trusted_baseline_report.csv")
DEFAULT_OUTPUT_JSON = Path("security_reports/evidence_center_report.json")
DEFAULT_OUTPUT_TXT = Path("security_reports/evidence_center_report.txt")


def read_csv_rows(path):
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def split_items(value):
    if not value:
        return []

    return [item.strip() for item in str(value).split("|") if item.strip()]


def calculate_priority(severity, confidence):
    try:
        confidence_value = int(confidence)
    except ValueError:
        confidence_value = 0

    severity = str(severity).upper()

    if severity == "HIGH" and confidence_value >= 80:
        return "Immediate Review"

    if severity == "HIGH":
        return "High Priority"

    if severity == "MEDIUM" and confidence_value >= 60:
        return "Moderate Review"

    if severity == "LOW":
        return "Informational"

    return "Review"


def build_evidence_finding(row):
    severity = row.get("Severity", "UNKNOWN")
    confidence = row.get("Confidence", "0")
    threat_type = row.get("Threat_Type", "UNKNOWN")

    evidence_items = split_items(row.get("Evidence", ""))
    action_items = split_items(row.get("Recommended_Action", ""))

    if not evidence_items:
        evidence_items.append("No detailed evidence available.")

    if not action_items:
        action_items.append("Manual review recommended.")

    return {
        "ssid": row.get("SSID", ""),
        "bssid": row.get("BSSID", ""),
        "baseline_status": row.get("Baseline_Status", ""),
        "threat_type": threat_type,
        "severity": severity,
        "confidence": confidence,
        "priority": calculate_priority(severity, confidence),
        "trusted_bssid": row.get("Trusted_BSSID", ""),
        "location": row.get("Location", ""),
        "owner": row.get("Owner", ""),
        "evidence": evidence_items,
        "recommended_actions": action_items,
        "analyst_note": build_analyst_note(row),
    }


def build_analyst_note(row):
    threat_type = row.get("Threat_Type", "")
    ssid = row.get("SSID", "")
    bssid = row.get("BSSID", "")
    trusted_bssid = row.get("Trusted_BSSID", "")

    if threat_type == "POSSIBLE_EVIL_TWIN_INDICATOR":
        return (
            f"The SSID '{ssid}' is present in the trusted baseline, but the detected "
            f"BSSID '{bssid}' does not match the trusted BSSID '{trusted_bssid}'. "
            "This should be treated as a possible Evil Twin indicator until manually verified."
        )

    if threat_type == "UNKNOWN_NETWORK":
        return (
            f"The network '{ssid}' with BSSID '{bssid}' is not present in the trusted "
            "baseline. It may be legitimate, but it should be reviewed before being trusted."
        )

    if threat_type == "WEAK_OR_OPEN_NETWORK":
        return (
            f"The network '{ssid}' requires review because it is either open or uses weak "
            "encryption. Users should avoid sensitive activity on this network."
        )

    if threat_type == "NORMAL":
        return (
            f"The network '{ssid}' matches the trusted baseline and is currently treated "
            "as normal."
        )

    return "Manual review recommended for this finding."


def build_summary(findings):
    summary = {
        "total_findings": len(findings),
        "immediate_review": 0,
        "high_priority": 0,
        "moderate_review": 0,
        "informational": 0,
        "possible_evil_twin_indicators": 0,
        "unknown_networks": 0,
        "trusted_networks": 0,
    }

    for finding in findings:
        priority = finding["priority"]
        threat_type = finding["threat_type"]

        if priority == "Immediate Review":
            summary["immediate_review"] += 1
        elif priority == "High Priority":
            summary["high_priority"] += 1
        elif priority == "Moderate Review":
            summary["moderate_review"] += 1
        elif priority == "Informational":
            summary["informational"] += 1

        if threat_type == "POSSIBLE_EVIL_TWIN_INDICATOR":
            summary["possible_evil_twin_indicators"] += 1
        elif threat_type == "UNKNOWN_NETWORK":
            summary["unknown_networks"] += 1
        elif threat_type == "NORMAL":
            summary["trusted_networks"] += 1

    return summary


def write_json_report(path, findings, summary):
    path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summary,
        "findings": findings,
    }

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)


def write_text_report(path, findings, summary):
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    lines.append("NetShield Evidence Center Report")
    lines.append("=" * 34)
    lines.append(f"Generated At: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 7)
    lines.append(f"Total Findings                 : {summary['total_findings']}")
    lines.append(f"Immediate Review               : {summary['immediate_review']}")
    lines.append(f"High Priority                  : {summary['high_priority']}")
    lines.append(f"Moderate Review                : {summary['moderate_review']}")
    lines.append(f"Informational                  : {summary['informational']}")
    lines.append(f"Possible Evil Twin Indicators  : {summary['possible_evil_twin_indicators']}")
    lines.append(f"Unknown Networks               : {summary['unknown_networks']}")
    lines.append(f"Trusted Networks               : {summary['trusted_networks']}")
    lines.append("")

    for index, finding in enumerate(findings, start=1):
        lines.append(f"Finding {index}")
        lines.append("-" * 20)
        lines.append(f"SSID             : {finding['ssid']}")
        lines.append(f"BSSID            : {finding['bssid']}")
        lines.append(f"Threat Type      : {finding['threat_type']}")
        lines.append(f"Severity         : {finding['severity']}")
        lines.append(f"Confidence       : {finding['confidence']}%")
        lines.append(f"Priority         : {finding['priority']}")
        lines.append(f"Trusted BSSID    : {finding['trusted_bssid'] or 'Not available'}")
        lines.append("")

        lines.append("Evidence:")
        for item in finding["evidence"]:
            lines.append(f"  - {item}")

        lines.append("")
        lines.append("Recommended Actions:")
        for item in finding["recommended_actions"]:
            lines.append(f"  - {item}")

        lines.append("")
        lines.append("Analyst Note:")
        lines.append(f"  {finding['analyst_note']}")
        lines.append("")

    with path.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines))


def print_summary(summary, output_json, output_txt):
    print("\nEvidence Center Report Generated")
    print("--------------------------------")
    print(f"Total Findings                : {summary['total_findings']}")
    print(f"Immediate Review              : {summary['immediate_review']}")
    print(f"High Priority                 : {summary['high_priority']}")
    print(f"Moderate Review               : {summary['moderate_review']}")
    print(f"Informational                 : {summary['informational']}")
    print(f"Possible Evil Twin Indicators : {summary['possible_evil_twin_indicators']}")
    print(f"Unknown Networks              : {summary['unknown_networks']}")
    print(f"Trusted Networks              : {summary['trusted_networks']}")
    print(f"\n[OK] JSON report saved to : {output_json}")
    print(f"[OK] Text report saved to : {output_txt}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate evidence-based investigation report from trusted baseline results."
    )

    parser.add_argument(
        "--baseline-report",
        default=str(DEFAULT_BASELINE_REPORT),
        help="Path to trusted_baseline_report.csv",
    )

    parser.add_argument(
        "--output-json",
        default=str(DEFAULT_OUTPUT_JSON),
        help="Path to output evidence center JSON report",
    )

    parser.add_argument(
        "--output-txt",
        default=str(DEFAULT_OUTPUT_TXT),
        help="Path to output evidence center text report",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    baseline_report = Path(args.baseline_report)
    output_json = Path(args.output_json)
    output_txt = Path(args.output_txt)

    baseline_rows = read_csv_rows(baseline_report)
    findings = [build_evidence_finding(row) for row in baseline_rows]
    summary = build_summary(findings)

    write_json_report(output_json, findings, summary)
    write_text_report(output_txt, findings, summary)

    print_summary(summary, output_json, output_txt)


if __name__ == "__main__":
    main()
