"""Real-time alert notification system.

Module 9 for WiFi Real-Time Security and Signal Analyzer.

Reads:
    security_reports/final_security_report.csv

Writes:
    security_reports/alert_notifications.log
    security_reports/alert_notifications.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_REPORT_CSV = Path("security_reports/final_security_report.csv")
DEFAULT_ALERT_LOG = Path("security_reports/alert_notifications.log")
DEFAULT_ALERT_JSON = Path("security_reports/alert_notifications.json")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
ANSI_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[92m",
    "INFO": "\033[92m",
}
ANSI_RESET = "\033[0m"

REQUIRED_COLUMNS = [
    "SSID",
    "BSSID",
    "Risk_Level",
    "Attack_Type",
    "Suspicious_Score",
]


def load_security_report(report_csv: str | Path = DEFAULT_REPORT_CSV) -> list[dict[str, str]]:
    """Load the latest final security report safely."""

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


def detect_alerts(report_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Detect alert-worthy rows and deduplicate to one alert per BSSID."""

    alerts_by_bssid: dict[str, dict[str, Any]] = {}
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for row in report_rows:
        reasons = _alert_reasons(row)
        if not reasons:
            continue

        bssid = row["BSSID"]
        severities = [assign_severity(row, reason) for reason in reasons]
        severity = _highest_severity(severities)

        if bssid not in alerts_by_bssid:
            alerts_by_bssid[bssid] = {
                "timestamp": timestamp,
                "ssid": row["SSID"],
                "bssid": bssid,
                "risk_level": row["Risk_Level"],
                "attack_type": row["Attack_Type"],
                "security_score": _to_int(row["Suspicious_Score"], default=100),
                "severity": severity,
                "reasons": [],
                "recommendations": [],
            }

        alert = alerts_by_bssid[bssid]
        alert["severity"] = _highest_severity([alert["severity"], severity])
        alert["reasons"] = _deduplicate([*alert["reasons"], *reasons])
        alert["recommendations"] = _deduplicate(
            [*alert["recommendations"], *[generate_recommendation(row, reason) for reason in reasons]]
        )
        alert["threat"] = " | ".join(alert["reasons"])
        alert["recommendation"] = " ".join(alert["recommendations"])

    alerts = list(alerts_by_bssid.values())
    return sorted(alerts, key=lambda alert: SEVERITY_ORDER.index(alert["severity"]))


def assign_severity(row: dict[str, str], reason: str) -> str:
    """Assign alert severity from attack type, risk level, and score."""

    attack_type = row["Attack_Type"]
    risk_level = row["Risk_Level"]
    score = _to_int(row["Suspicious_Score"], default=100)

    if attack_type == "EVIL_TWIN" or risk_level == "DANGER":
        return "CRITICAL"
    if attack_type == "ROGUE_AP":
        return "HIGH"
    if attack_type in {
        "SUSPICIOUS",
        "WEAK_ENCRYPTION",
    }:
        return "MEDIUM"
    if attack_type == "UNKNOWN_NETWORK":
        return "INFO"
    if risk_level == "LOW RISK" or score <= 60:
        return "LOW"
    return "INFO"


def generate_recommendation(row: dict[str, str], reason: str) -> str:
    """Generate an action-oriented recommendation for the alert."""

    attack_type = row["Attack_Type"]
    risk_level = row["Risk_Level"]
    score = _to_int(row["Suspicious_Score"], default=100)

    if attack_type == "EVIL_TWIN":
        return "Verify router ownership, compare the BSSID with the trusted router, and check channel and signal strength."
    if attack_type == "ROGUE_AP":
        return "Verify device ownership and remove or isolate unauthorized access points."
    if attack_type == "SUSPICIOUS":
        return "Continue monitoring and inspect packet activity for repeated anomalies."
    if attack_type == "WEAK_ENCRYPTION":
        return "Avoid sensitive activity until stronger WiFi encryption is enabled or the network is verified."
    if attack_type == "UNKNOWN_NETWORK":
        return "Verify the network owner and BSSID before treating this network as trusted."
    if risk_level == "DANGER":
        return "Treat this network as unsafe until manual validation is completed."
    if score <= 60:
        return "Review security score causes and validate encryption, packet behavior, and trusted BSSID."
    if risk_level == "LOW RISK":
        return "Monitor the network and confirm that minor anomalies do not repeat."
    return "No action required."


def print_alert_banner(alert: dict[str, Any], use_color: bool = True) -> None:
    """Print one professional terminal alert banner."""

    severity = alert["severity"]
    title = f"{severity} SECURITY ALERT"
    color = ANSI_COLORS.get(severity, "") if use_color else ""
    reset = ANSI_RESET if color else ""

    print(color + "====================================================" + reset)
    print(color + f" {title}" + reset)
    print(color + "====================================================" + reset)
    print(f"SSID         : {alert['ssid']}")
    print(f"BSSID        : {alert['bssid']}")
    print(f"Risk Level   : {alert['risk_level']}")
    print(f"Attack Type  : {alert['attack_type']}")
    print(f"Score        : {alert['security_score']}")
    print(f"Time         : {alert['timestamp']}")
    print("Reasons:")
    for reason in alert["reasons"]:
        print(f"- {reason}")
    print("Recommendation:")
    for recommendation in alert["recommendations"]:
        print(f"- {recommendation}")
    print(color + "====================================================" + reset)
    print()


def append_alert_log(alerts: list[dict[str, Any]], log_path: str | Path = DEFAULT_ALERT_LOG) -> None:
    """Append every generated alert to the plain text alert log."""

    if not alerts:
        return

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as log_file:
        for alert in alerts:
            reasons = json.dumps(alert["reasons"])
            log_file.write(
                f"{alert['timestamp']} | SSID={alert['ssid']} | BSSID={alert['bssid']} | "
                f"Risk_Level={alert['risk_level']} | Attack_Type={alert['attack_type']} | "
                f"Severity={alert['severity']} | Reasons={reasons} | Recommendation={alert['recommendation']}\n"
            )


def save_json_alerts(alerts: list[dict[str, Any]], json_path: str | Path = DEFAULT_ALERT_JSON) -> None:
    """Write the latest alert batch and summary to JSON."""

    path = Path(json_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": build_alert_summary(alerts),
        "alerts": alerts,
    }
    path.write_text(json.dumps(payload, indent=4), encoding="utf-8")


def build_alert_summary(alerts: list[dict[str, Any]]) -> dict[str, int]:
    """Build alert counts by severity."""

    summary = {
        "total_alerts": len(alerts),
        "critical_alerts": 0,
        "high_alerts": 0,
        "medium_alerts": 0,
        "low_alerts": 0,
        "information_alerts": 0,
    }
    for alert in alerts:
        severity = alert["severity"]
        if severity == "CRITICAL":
            summary["critical_alerts"] += 1
        elif severity == "HIGH":
            summary["high_alerts"] += 1
        elif severity == "MEDIUM":
            summary["medium_alerts"] += 1
        elif severity == "LOW":
            summary["low_alerts"] += 1
        elif severity == "INFO":
            summary["information_alerts"] += 1
    return summary


def print_alert_summary(alerts: list[dict[str, Any]]) -> None:
    """Print alert totals after all banners."""

    summary = build_alert_summary(alerts)
    print("Alert Summary")
    print(f"Total Alerts       : {summary['total_alerts']}")
    print(f"Critical Alerts    : {summary['critical_alerts']}")
    print(f"High Alerts        : {summary['high_alerts']}")
    print(f"Medium Alerts      : {summary['medium_alerts']}")
    print(f"Low Alerts         : {summary['low_alerts']}")
    print(f"Information Alerts : {summary['information_alerts']}")


def run_alert_notification(
    report_csv: str | Path = DEFAULT_REPORT_CSV,
    log_path: str | Path = DEFAULT_ALERT_LOG,
    json_path: str | Path = DEFAULT_ALERT_JSON,
    use_color: bool | None = None,
) -> list[dict[str, Any]]:
    """Perform the complete alert analysis workflow for Module 9."""

    rows = load_security_report(report_csv)
    alerts = detect_alerts(rows)
    color_enabled = _supports_color() if use_color is None else use_color

    if not alerts:
        print("No active security alerts.")
        save_json_alerts(alerts, json_path)
        return alerts

    for alert in alerts:
        print_alert_banner(alert, use_color=color_enabled)

    append_alert_log(alerts, log_path)
    save_json_alerts(alerts, json_path)
    print_alert_summary(alerts)
    print(f"\n[OK] Alert log updated: {Path(log_path)}")
    print(f"[OK] JSON alerts saved: {Path(json_path)}")
    return alerts


def _alert_reasons(row: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    attack_type = row["Attack_Type"]
    risk_level = row["Risk_Level"]
    score = _to_int(row["Suspicious_Score"], default=100)

    if attack_type == "EVIL_TWIN":
        reasons.append("Possible Evil Twin")
    if attack_type == "ROGUE_AP":
        reasons.append("Possible Rogue AP")
    if attack_type == "SUSPICIOUS":
        reasons.append("Suspicious Network Activity")
    if attack_type == "WEAK_ENCRYPTION":
        reasons.append("Weak WiFi Encryption")
    if attack_type == "UNKNOWN_NETWORK":
        reasons.append("Unverified Network")
    if risk_level == "DANGER":
        reasons.append("Danger Risk Level")
    if score <= 60:
        reasons.append("Low Security Score")

    return reasons


def _highest_severity(severities: list[str]) -> str:
    if not severities:
        return "INFO"
    return min(severities, key=SEVERITY_ORDER.index)


def _deduplicate(items: list[str]) -> list[str]:
    seen = set()
    unique_items = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique_items.append(item)
    return unique_items


def _normalize_row(row: dict[str, str]) -> dict[str, str]:
    normalized = {}
    for column in REQUIRED_COLUMNS:
        normalized[column] = _clean_text(row.get(column), _default_for_column(column))
    normalized["Risk_Level"] = _normalize_risk_level(normalized["Risk_Level"])
    normalized["Attack_Type"] = _normalize_attack_type(normalized["Attack_Type"])
    return normalized


def _default_for_column(column: str) -> str:
    return {
        "SSID": "Unknown_Device",
        "BSSID": "Unknown",
        "Risk_Level": "SAFE",
        "Attack_Type": "NORMAL",
        "Suspicious_Score": "100",
    }.get(column, "Unknown")


def _normalize_risk_level(value: str | None) -> str:
    cleaned = " ".join(_clean_text(value, "SAFE").upper().replace("-", " ").split())
    if cleaned in {"SAFE", "LOW RISK", "WARNING", "DANGER"}:
        return cleaned
    return "SAFE"


def _normalize_attack_type(value: str | None) -> str:
    cleaned = (
        _clean_text(value, "NORMAL")
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    if cleaned in {
        "NORMAL",
        "ROGUE_AP",
        "EVIL_TWIN",
        "SUSPICIOUS",
        "WEAK_ENCRYPTION",
        "UNKNOWN_NETWORK",
    }:
        return cleaned

    return "NORMAL"


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


def _supports_color() -> bool:
    return os.name != "nt" or bool(os.environ.get("ANSICON") or os.environ.get("WT_SESSION"))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate real-time WiFi security alert notifications.")
    parser.add_argument("--report-csv", default=str(DEFAULT_REPORT_CSV), help="Final security report CSV path.")
    parser.add_argument("--log-path", default=str(DEFAULT_ALERT_LOG), help="Append-only alert log path.")
    parser.add_argument("--json-path", default=str(DEFAULT_ALERT_JSON), help="JSON alert output path.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    run_alert_notification(
        report_csv=args.report_csv,
        log_path=args.log_path,
        json_path=args.json_path,
        use_color=not args.no_color,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
