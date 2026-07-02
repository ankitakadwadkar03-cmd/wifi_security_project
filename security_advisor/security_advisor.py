"""AI-style security advisor for WiFi security reports.

Module 7 for WiFi Real-Time Security and Signal Analyzer.

Reads:
    security_reports/final_security_report.csv

Writes:
    security_reports/security_advisor_report.txt
    security_reports/security_advisor_report.json
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_REPORT_CSV = Path("security_reports/final_security_report.csv")
DEFAULT_TEXT_REPORT = Path("security_reports/security_advisor_report.txt")
DEFAULT_JSON_REPORT = Path("security_reports/security_advisor_report.json")

REQUIRED_COLUMNS = [
    "SSID",
    "BSSID",
    "Encryption",
    "Risk_Level",
    "Attack_Type",
    "Suspicious_Score",
    "Deauth_Count",
    "Unknown_MAC_Count",
    "Total_Packets",
]


def load_report(report_csv: str | Path = DEFAULT_REPORT_CSV) -> list[dict[str, str]]:
    """Load final security report rows safely."""

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
            return [_normalize_row(row) for row in reader]
    except Exception as exc:
        print(f"[WARNING] Could not read security report {path}: {exc}")
        return []


def analyze_network(network: dict[str, str]) -> dict[str, Any]:
    """Create explanation, score, and recommendations for one network."""

    attack_type = _normalize_attack_type(network.get("Attack_Type"))
    risk_level = _normalize_risk_level(network.get("Risk_Level"))
    score = _to_int(network.get("Suspicious_Score"), default=100)

    analysis = {
        "ssid": network["SSID"],
        "bssid": network["BSSID"],
        "encryption": network["Encryption"],
        "risk_level": risk_level,
        "attack_type": attack_type,
        "security_score": score,
        "total_packets": _to_int(network.get("Total_Packets")),
        "deauth_count": _to_int(network.get("Deauth_Count")),
        "unknown_mac_count": _to_int(network.get("Unknown_MAC_Count")),
        "explanation": _build_explanation(network, risk_level, attack_type),
        "recommendations": generate_recommendations(network),
    }
    return analysis


def generate_recommendations(network: dict[str, str]) -> list[str]:
    """Generate practical recommendations for one network."""

    recommendations: list[str] = []
    encryption = _clean_text(network.get("Encryption"), "Unknown").upper()
    attack_type = _normalize_attack_type(network.get("Attack_Type"))
    risk_level = _normalize_risk_level(network.get("Risk_Level"))
    deauth_count = _to_int(network.get("Deauth_Count"))
    unknown_mac_count = _to_int(network.get("Unknown_MAC_Count"))
    score = _to_int(network.get("Suspicious_Score"), default=100)

    if encryption == "OPEN":
        recommendations.append("Use WPA2 or WPA3 instead of an open network.")
    if encryption == "WEP":
        recommendations.append("Upgrade router security from WEP to WPA2 or WPA3.")
    if encryption in {"UNKNOWN", ""}:
        recommendations.append("Verify the access point encryption settings before trusting this network.")
    if attack_type == "EVIL_TWIN":
        recommendations.append("Verify the trusted BSSID before connecting to this SSID.")
        recommendations.append("Compare channel, signal strength, and router ownership for duplicate SSIDs.")
    if attack_type == "ROGUE_AP":
        recommendations.append("Verify ownership before trusting this access point.")
        recommendations.append("Remove or isolate unauthorized access points from the environment.")
    if attack_type == "SUSPICIOUS":
        recommendations.append("Continue monitoring this network for packet anomalies.")
    if deauth_count > 0:
        recommendations.append("Investigate possible wireless deauthentication activity.")
    if unknown_mac_count > 0:
        recommendations.append("Monitor for abnormal or unknown devices sending repeated traffic.")
    if risk_level in {"WARNING", "DANGER"} or score < 60:
        recommendations.append("Perform manual validation using trusted router MAC addresses and logs.")
    if not recommendations:
        recommendations.append("Maintain current security settings and continue periodic monitoring.")

    return _deduplicate(recommendations)


def calculate_grade(analyses: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate overall score and grade from all analyzed networks."""

    if not analyses:
        return {
            "overall_score": 100,
            "overall_grade": "A",
            "grade_label": "Excellent",
        }

    average_score = sum(item["security_score"] for item in analyses) / len(analyses)
    penalty = 0

    for item in analyses:
        if item["attack_type"] == "EVIL_TWIN":
            penalty += 20
        elif item["attack_type"] == "ROGUE_AP":
            penalty += 15
        elif item["attack_type"] == "SUSPICIOUS":
            penalty += 8

        if item["risk_level"] == "DANGER":
            penalty += 15
        elif item["risk_level"] == "WARNING":
            penalty += 8

    overall_score = max(0, min(100, round(average_score - penalty)))
    grade, label = _grade_from_score(overall_score)
    return {
        "overall_score": overall_score,
        "overall_grade": grade,
        "grade_label": label,
    }


def save_text_report(report: dict[str, Any], output_path: str | Path = DEFAULT_TEXT_REPORT) -> None:
    """Save the professional human-readable advisor report."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_build_text_report(report), encoding="utf-8")


def save_json_report(report: dict[str, Any], output_path: str | Path = DEFAULT_JSON_REPORT) -> None:
    """Save the structured advisor report as JSON."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=4), encoding="utf-8")


def print_summary(report: dict[str, Any]) -> None:
    """Print a clean professional report to the terminal."""

    print(_build_text_report(report))


def generate_advisor_report(
    report_csv: str | Path = DEFAULT_REPORT_CSV,
    text_output: str | Path = DEFAULT_TEXT_REPORT,
    json_output: str | Path = DEFAULT_JSON_REPORT,
) -> dict[str, Any]:
    rows = load_report(report_csv)
    analyses = [analyze_network(row) for row in rows]
    grade_info = calculate_grade(analyses)
    summary = _build_executive_summary(analyses, grade_info)
    recommendations = _build_overall_recommendations(analyses)

    report: dict[str, Any] = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_report": str(report_csv),
        "executive_summary": summary,
        "overall_recommendations": recommendations,
        "networks": analyses,
    }

    save_text_report(report, text_output)
    save_json_report(report, json_output)
    print_summary(report)
    print(f"\n[OK] Text report saved to: {Path(text_output)}")
    print(f"[OK] JSON report saved to: {Path(json_output)}")
    return report


def _build_explanation(network: dict[str, str], risk_level: str, attack_type: str) -> str:
    if attack_type == "ROGUE_AP":
        return (
            "This device was not matched with known scanned access points. It may be an unauthorized device. "
            "Further verification is recommended."
        )
    if attack_type == "EVIL_TWIN":
        return (
            "This network shares the same SSID as another access point but has a different BSSID. "
            "This may indicate an Evil Twin attack or a legitimate access point with the same SSID. "
            "Verify using channel, signal strength and trusted BSSID."
        )
    if attack_type == "SUSPICIOUS":
        return "This network generated unusual traffic patterns. Additional monitoring is recommended."
    if risk_level == "LOW RISK":
        return "This network has minor anomalies but no confirmed attack."
    if risk_level in {"WARNING", "DANGER"}:
        return "This network has elevated risk indicators and should be reviewed before being trusted."
    return "This network appears secure. No suspicious activity was detected during this scan."


def _build_executive_summary(analyses: list[dict[str, Any]], grade_info: dict[str, Any]) -> dict[str, Any]:
    return {
        "total_networks": len(analyses),
        "safe": sum(1 for item in analyses if item["risk_level"] == "SAFE"),
        "warning": sum(1 for item in analyses if item["risk_level"] == "WARNING"),
        "danger": sum(1 for item in analyses if item["risk_level"] == "DANGER"),
        "low_risk": sum(1 for item in analyses if item["risk_level"] == "LOW RISK"),
        "possible_rogue_ap": sum(1 for item in analyses if item["attack_type"] == "ROGUE_AP"),
        "possible_evil_twin": sum(1 for item in analyses if item["attack_type"] == "EVIL_TWIN"),
        "suspicious": sum(1 for item in analyses if item["attack_type"] == "SUSPICIOUS"),
        "overall_security_grade": grade_info["overall_grade"],
        "overall_grade_label": grade_info["grade_label"],
        "overall_security_score": grade_info["overall_score"],
    }


def _build_overall_recommendations(analyses: list[dict[str, Any]]) -> list[str]:
    recommendations: list[str] = []

    for item in analyses:
        recommendations.extend(item["recommendations"])

    if any(item["encryption"].upper() in {"OPEN", "WEP"} for item in analyses):
        recommendations.append("Enable WPA3 where supported, or WPA2 with a strong passphrase.")
    if any(item["attack_type"] == "EVIL_TWIN" for item in analyses):
        recommendations.append("Verify duplicate SSIDs against trusted router BSSIDs.")
    if any(item["attack_type"] == "ROGUE_AP" for item in analyses):
        recommendations.append("Remove or investigate unauthorized access points.")
    if any(item["attack_type"] == "SUSPICIOUS" for item in analyses):
        recommendations.append("Monitor packet anomalies over a longer capture window.")
    if any(item["deauth_count"] > 0 for item in analyses):
        recommendations.append("Investigate deauthentication activity and consider wireless intrusion monitoring.")

    if not recommendations:
        recommendations.append("No immediate action required. Continue scheduled WiFi security monitoring.")

    return _deduplicate(recommendations)


def _build_text_report(report: dict[str, Any]) -> str:
    summary = report["executive_summary"]
    lines = [
        "====================================================",
        " WiFi Security Advisor",
        "====================================================",
        f"Generated At   : {report['generated_at']}",
        f"Overall Grade : {summary['overall_security_grade']} ({summary['overall_grade_label']})",
        f"Security Score : {summary['overall_security_score']}/100",
        "",
        "Executive Summary:",
        f"Total Networks      : {summary['total_networks']}",
        f"Safe                : {summary['safe']}",
        f"Low Risk            : {summary['low_risk']}",
        f"Warning             : {summary['warning']}",
        f"Danger              : {summary['danger']}",
        f"Possible Rogue AP   : {summary['possible_rogue_ap']}",
        f"Possible Evil Twin  : {summary['possible_evil_twin']}",
        f"Suspicious          : {summary['suspicious']}",
        "",
        "Recommendations:",
    ]

    for recommendation in report["overall_recommendations"]:
        lines.append(f"- {recommendation}")

    lines.extend(["", "Network Analysis:"])
    if not report["networks"]:
        lines.append("No networks were found in the final security report.")
    else:
        for index, network in enumerate(report["networks"], start=1):
            lines.extend(
                [
                    "",
                    f"{index}. SSID           : {network['ssid']}",
                    f"   BSSID          : {network['bssid']}",
                    f"   Encryption     : {network['encryption']}",
                    f"   Risk Level     : {network['risk_level']}",
                    f"   Attack Type    : {network['attack_type']}",
                    f"   Security Score : {network['security_score']}/100",
                    f"   Explanation    : {network['explanation']}",
                    "   Recommendations:",
                ]
            )
            for recommendation in network["recommendations"]:
                lines.append(f"   - {recommendation}")

    lines.append("====================================================")
    return "\n".join(lines)


def _normalize_row(row: dict[str, str]) -> dict[str, str]:
    normalized = {}
    for column in REQUIRED_COLUMNS:
        normalized[column] = _clean_text(row.get(column), _default_for_column(column))
    return normalized


def _default_for_column(column: str) -> str:
    return {
        "SSID": "Unknown_Device",
        "BSSID": "Unknown",
        "Encryption": "Unknown",
        "Risk_Level": "SAFE",
        "Attack_Type": "NORMAL",
        "Suspicious_Score": "100",
        "Deauth_Count": "0",
        "Unknown_MAC_Count": "0",
        "Total_Packets": "0",
    }.get(column, "Unknown")


def _normalize_attack_type(value: str | None) -> str:
    cleaned = _clean_text(value, "NORMAL").upper().replace("-", "_").replace(" ", "_")
    if cleaned in {"NORMAL", "ROGUE_AP", "EVIL_TWIN", "SUSPICIOUS"}:
        return cleaned
    return "NORMAL"


def _normalize_risk_level(value: str | None) -> str:
    cleaned = " ".join(_clean_text(value, "SAFE").upper().replace("-", " ").split())
    if cleaned in {"SAFE", "LOW RISK", "WARNING", "DANGER"}:
        return cleaned
    return "SAFE"


def _grade_from_score(score: int) -> tuple[str, str]:
    if score >= 90:
        return "A", "Excellent"
    if score >= 80:
        return "B", "Good"
    if score >= 65:
        return "C", "Moderate Risk"
    if score >= 50:
        return "D", "High Risk"
    return "F", "Critical"


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _clean_text(value: object, default: str) -> str:
    cleaned = str(value).strip()
    if not cleaned or cleaned.lower() in {"nan", "none", "null"}:
        return default
    return cleaned


def _deduplicate(items: list[str]) -> list[str]:
    seen = set()
    unique_items = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique_items.append(item)
    return unique_items


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate AI-style WiFi security recommendations.")
    parser.add_argument("--report-csv", default=str(DEFAULT_REPORT_CSV), help="Final security report CSV path.")
    parser.add_argument("--text-output", default=str(DEFAULT_TEXT_REPORT), help="Text advisor report output path.")
    parser.add_argument("--json-output", default=str(DEFAULT_JSON_REPORT), help="JSON advisor report output path.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    generate_advisor_report(
        report_csv=args.report_csv,
        text_output=args.text_output,
        json_output=args.json_output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
