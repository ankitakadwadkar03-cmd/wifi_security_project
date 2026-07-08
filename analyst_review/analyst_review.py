import argparse
import csv
import json
from datetime import datetime
from pathlib import Path


DEFAULT_EVIDENCE_JSON = Path("security_reports/evidence_center_report.json")
DEFAULT_DECISIONS_CSV = Path("analyst_review/analyst_decisions.csv")
DEFAULT_OUTPUT_JSON = Path("security_reports/analyst_review_report.json")
DEFAULT_OUTPUT_TXT = Path("security_reports/analyst_review_report.txt")


VALID_DECISIONS = {
    "TRUSTED",
    "FALSE_POSITIVE",
    "UNDER_INVESTIGATION",
    "BLOCKED",
    "PENDING_REVIEW",
}


def normalize_text(value):
    return str(value).strip()


def normalize_key(value):
    return normalize_text(value).upper()


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def read_decisions_csv(path):
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def build_decision_indexes(decision_rows):
    exact_index = {}
    bssid_index = {}

    for row in decision_rows:
        ssid = normalize_key(row.get("SSID", ""))
        bssid = normalize_key(row.get("BSSID", ""))
        threat_type = normalize_key(row.get("Threat_Type", ""))
        decision = normalize_key(row.get("Decision", "PENDING_REVIEW"))

        if decision not in VALID_DECISIONS:
            decision = "PENDING_REVIEW"

        decision_record = {
            "decision": decision,
            "analyst": normalize_text(row.get("Analyst", "")) or "Unassigned",
            "analyst_note": normalize_text(row.get("Analyst_Note", "")),
        }

        exact_index[(ssid, bssid, threat_type)] = decision_record
        bssid_index[(ssid, bssid)] = decision_record

    return exact_index, bssid_index


def find_decision(finding, exact_index, bssid_index):
    ssid = normalize_key(finding.get("ssid", ""))
    bssid = normalize_key(finding.get("bssid", ""))
    threat_type = normalize_key(finding.get("threat_type", ""))

    exact_key = (ssid, bssid, threat_type)
    bssid_key = (ssid, bssid)

    if exact_key in exact_index:
        return exact_index[exact_key]

    if bssid_key in bssid_index:
        return bssid_index[bssid_key]

    return {
        "decision": "PENDING_REVIEW",
        "analyst": "Unassigned",
        "analyst_note": "No analyst decision recorded yet.",
    }


def calculate_final_status(decision, original_priority):
    if decision == "TRUSTED":
        return "CLOSED_TRUSTED"

    if decision == "FALSE_POSITIVE":
        return "CLOSED_FALSE_POSITIVE"

    if decision == "UNDER_INVESTIGATION":
        return "ACTIVE_INVESTIGATION"

    if decision == "BLOCKED":
        return "MITIGATED_BLOCKED"

    if original_priority == "Immediate Review":
        return "PENDING_IMMEDIATE_REVIEW"

    return "PENDING_REVIEW"


def calculate_adjusted_priority(decision, original_priority):
    if decision in {"TRUSTED", "FALSE_POSITIVE"}:
        return "Low"

    if decision == "BLOCKED":
        return "Mitigated"

    if decision == "UNDER_INVESTIGATION":
        return original_priority

    return original_priority


def review_finding(finding, exact_index, bssid_index):
    decision_record = find_decision(finding, exact_index, bssid_index)

    decision = decision_record["decision"]
    original_priority = finding.get("priority", "Review")

    reviewed = dict(finding)
    reviewed["analyst_decision"] = decision
    reviewed["analyst"] = decision_record["analyst"]
    reviewed["analyst_note"] = decision_record["analyst_note"]
    reviewed["final_status"] = calculate_final_status(decision, original_priority)
    reviewed["adjusted_priority"] = calculate_adjusted_priority(decision, original_priority)
    reviewed["reviewed_at"] = datetime.now().isoformat(timespec="seconds")

    return reviewed


def build_summary(reviewed_findings):
    summary = {
        "total_findings": len(reviewed_findings),
        "trusted": 0,
        "false_positive": 0,
        "under_investigation": 0,
        "blocked": 0,
        "pending_review": 0,
        "active_investigations": 0,
        "pending_immediate_review": 0,
    }

    for finding in reviewed_findings:
        decision = finding.get("analyst_decision", "")
        final_status = finding.get("final_status", "")

        if decision == "TRUSTED":
            summary["trusted"] += 1
        elif decision == "FALSE_POSITIVE":
            summary["false_positive"] += 1
        elif decision == "UNDER_INVESTIGATION":
            summary["under_investigation"] += 1
        elif decision == "BLOCKED":
            summary["blocked"] += 1
        elif decision == "PENDING_REVIEW":
            summary["pending_review"] += 1

        if final_status == "ACTIVE_INVESTIGATION":
            summary["active_investigations"] += 1

        if final_status == "PENDING_IMMEDIATE_REVIEW":
            summary["pending_immediate_review"] += 1

    return summary


def write_json_report(path, reviewed_findings, summary):
    path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summary,
        "reviewed_findings": reviewed_findings,
    }

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)


def write_text_report(path, reviewed_findings, summary):
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    lines.append("NetShield Analyst Review Report")
    lines.append("=" * 34)
    lines.append(f"Generated At: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 7)
    lines.append(f"Total Findings             : {summary['total_findings']}")
    lines.append(f"Trusted                    : {summary['trusted']}")
    lines.append(f"False Positive             : {summary['false_positive']}")
    lines.append(f"Under Investigation        : {summary['under_investigation']}")
    lines.append(f"Blocked                    : {summary['blocked']}")
    lines.append(f"Pending Review             : {summary['pending_review']}")
    lines.append(f"Active Investigations      : {summary['active_investigations']}")
    lines.append(f"Pending Immediate Review   : {summary['pending_immediate_review']}")
    lines.append("")

    for index, finding in enumerate(reviewed_findings, start=1):
        lines.append(f"Finding {index}")
        lines.append("-" * 20)
        lines.append(f"SSID               : {finding.get('ssid', '')}")
        lines.append(f"BSSID              : {finding.get('bssid', '')}")
        lines.append(f"Threat Type        : {finding.get('threat_type', '')}")
        lines.append(f"Severity           : {finding.get('severity', '')}")
        lines.append(f"Confidence         : {finding.get('confidence', '')}%")
        lines.append(f"Original Priority  : {finding.get('priority', '')}")
        lines.append(f"Analyst Decision   : {finding.get('analyst_decision', '')}")
        lines.append(f"Adjusted Priority  : {finding.get('adjusted_priority', '')}")
        lines.append(f"Final Status       : {finding.get('final_status', '')}")
        lines.append(f"Analyst            : {finding.get('analyst', '')}")
        lines.append("")

        lines.append("Analyst Note:")
        lines.append(f"  {finding.get('analyst_note', '')}")
        lines.append("")

        lines.append("Evidence:")
        for evidence in finding.get("evidence", []):
            lines.append(f"  - {evidence}")

        lines.append("")
        lines.append("Recommended Actions:")
        for action in finding.get("recommended_actions", []):
            lines.append(f"  - {action}")

        lines.append("")

    with path.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines))


def print_summary(summary, output_json, output_txt):
    print("\nAnalyst Review Report Generated")
    print("-------------------------------")
    print(f"Total Findings             : {summary['total_findings']}")
    print(f"Trusted                    : {summary['trusted']}")
    print(f"False Positive             : {summary['false_positive']}")
    print(f"Under Investigation        : {summary['under_investigation']}")
    print(f"Blocked                    : {summary['blocked']}")
    print(f"Pending Review             : {summary['pending_review']}")
    print(f"Active Investigations      : {summary['active_investigations']}")
    print(f"Pending Immediate Review   : {summary['pending_immediate_review']}")
    print(f"\n[OK] JSON report saved to : {output_json}")
    print(f"[OK] Text report saved to : {output_txt}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Apply analyst decisions to evidence center findings."
    )

    parser.add_argument(
        "--evidence-json",
        default=str(DEFAULT_EVIDENCE_JSON),
        help="Path to evidence_center_report.json",
    )

    parser.add_argument(
        "--decisions-csv",
        default=str(DEFAULT_DECISIONS_CSV),
        help="Path to analyst_decisions.csv",
    )

    parser.add_argument(
        "--output-json",
        default=str(DEFAULT_OUTPUT_JSON),
        help="Path to analyst review JSON report",
    )

    parser.add_argument(
        "--output-txt",
        default=str(DEFAULT_OUTPUT_TXT),
        help="Path to analyst review text report",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    evidence_report = load_json(Path(args.evidence_json))
    decision_rows = read_decisions_csv(Path(args.decisions_csv))

    findings = evidence_report.get("findings", [])
    exact_index, bssid_index = build_decision_indexes(decision_rows)

    reviewed_findings = [
        review_finding(finding, exact_index, bssid_index)
        for finding in findings
    ]

    summary = build_summary(reviewed_findings)

    output_json = Path(args.output_json)
    output_txt = Path(args.output_txt)

    write_json_report(output_json, reviewed_findings, summary)
    write_text_report(output_txt, reviewed_findings, summary)
    print_summary(summary, output_json, output_txt)


if __name__ == "__main__":
    main()
