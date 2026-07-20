from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)

# Allow the Vite frontend to access this API during development.
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ]
        }
    },
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NETWORK_CSV = PROJECT_ROOT / "scan_results" / "wifi_scan_results.csv"
SECURITY_REPORT_CSV = PROJECT_ROOT / "security_reports" / "final_security_report.csv"
REPORTS_DIRECTORY = PROJECT_ROOT / "security_reports"
HISTORY_DB = PROJECT_ROOT / "security_reports" / "history.db"
ALLOWED_REPORT_EXTENSIONS = {".csv", ".json", ".txt", ".log"}


def read_networks() -> list[dict]:
    """Read and normalize networks from the scanner CSV."""
    if not NETWORK_CSV.exists():
        return []

    networks: list[dict] = []

    with NETWORK_CSV.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            ssid = (row.get("SSID") or "").strip()
            bssid = (row.get("BSSID") or "").strip()

            # Ignore completely empty rows.
            if not ssid and not bssid:
                continue

            networks.append(
                {
                    "ssid": ssid or "Hidden Network",
                    "bssid": bssid,
                    "channel": (row.get("Channel") or "").strip(),
                    "frequency": (row.get("Frequency") or "").strip(),
                    "signal": (row.get("Signal") or "").strip(),
                    "encryption": (row.get("Encryption") or "Unknown").strip(),

                    # These values are intentionally not invented.
                    # Future modules will provide real vendor/threat analysis.
                    "vendor": "Not analyzed",
                    "status": "Unclassified",
                    "attack": "No analysis available",
                }
            )

    return networks


def _safe_int(value, default=0):
    """Convert a CSV value to an integer without crashing."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def read_threats() -> list[dict]:
    """Read non-normal findings from the final security report."""
    if not SECURITY_REPORT_CSV.exists():
        return []

    findings: list[dict] = []

    with SECURITY_REPORT_CSV.open(
        "r", encoding="utf-8", newline=""
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            attack_type = (
                row.get("Attack_Type") or "NORMAL"
            ).strip().upper()

            # Do not display normal networks as security findings.
            if attack_type in {"", "NORMAL"}:
                continue

            risk_level = (
                row.get("Risk_Level") or "UNKNOWN"
            ).strip().upper()

            severity = {
                "DANGER": "Critical",
                "WARNING": "High",
                "LOW RISK": "Medium",
            }.get(risk_level, "Review")

            title = {
                "ROGUE_AP": "Potential Rogue Access Point",
                "EVIL_TWIN": "Potential Evil Twin Network",
                "SUSPICIOUS": "Suspicious Wireless Activity",
            }.get(attack_type, "Wireless Security Finding")

            findings.append(
                {
                    "ssid": (
                        row.get("SSID") or "Unknown Device"
                    ).strip(),
                    "bssid": (row.get("BSSID") or "Unknown").strip(),
                    "encryption": (
                        row.get("Encryption") or "Unknown"
                    ).strip(),
                    "total_packets": _safe_int(
                        row.get("Total_Packets")
                    ),
                    "deauth_count": _safe_int(
                        row.get("Deauth_Count")
                    ),
                    "unknown_mac_count": _safe_int(
                        row.get("Unknown_MAC_Count")
                    ),
                    "suspicious_score": _safe_int(
                        row.get("Suspicious_Score"),
                        default=100,
                    ),
                    "risk_level": risk_level,
                    "attack_type": attack_type,
                    "severity": severity,
                    "title": title,
                    "summary": (
                        "This is a potential finding produced by automated "
                        "wireless analysis. Verify the BSSID and compare it "
                        "with trusted network records before taking action."
                    ),
                }
            )

    return findings


def _format_file_size(size_bytes: int) -> str:
    """Convert bytes into a readable file-size label."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def _report_category(filename: str) -> str:
    """Return a user-friendly category for a generated report."""
    lowered = filename.lower()

    if "alert" in lowered or "live" in lowered:
        return "Alerts and Monitoring"
    if "historical" in lowered or "trend" in lowered:
        return "Historical Analysis"
    if "evidence" in lowered or "analyst" in lowered:
        return "Investigation"
    if "pre_connect" in lowered:
        return "Pre-connect Safety"
    if "trusted_baseline" in lowered:
        return "Trusted Baseline"
    if "advisor" in lowered:
        return "Security Advice"
    return "Security Analysis"


def _report_description(filename: str) -> str:
    descriptions = {
        "final_security_report.csv":
            "Consolidated wireless findings, scores, risk levels and attack classifications.",
        "security_advisor_report.json":
            "Structured security recommendations generated from wireless analysis.",
        "security_advisor_report.txt":
            "Readable security recommendations and corrective actions.",
        "evidence_center_report.json":
            "Structured evidence collected for detected wireless findings.",
        "evidence_center_report.txt":
            "Readable evidence summary for analyst review.",
        "analyst_review_report.json":
            "Structured review information for security analysts.",
        "analyst_review_report.txt":
            "Readable analyst-review report.",
        "historical_trend_report.json":
            "Structured historical wireless-security trends.",
        "historical_trend_report.txt":
            "Readable historical trend summary.",
        "pre_connect_safety_report.csv":
            "Network safety recommendations before connecting.",
        "pre_connect_safety_report.json":
            "Structured pre-connect network safety analysis.",
        "trusted_baseline_report.csv":
            "Trusted network baseline records in CSV format.",
        "trusted_baseline_report.json":
            "Structured trusted network baseline records.",
        "alert_notifications.json":
            "Structured alert-notification history.",
        "alert_notifications.log":
            "Readable alert-notification log.",
        "live_alerts.log":
            "Live security-monitoring alert log.",
        "email_alert_preview.json":
            "Structured preview of generated email alerts.",
        "email_alert_preview.txt":
            "Readable preview of generated email alerts.",
        "security_report.csv":
            "General wireless-security analysis results.",
    }

    return descriptions.get(
        filename,
        "Generated NetShield wireless-security report.",
    )


def read_reports() -> list[dict]:
    """List browser-safe report files that currently exist."""
    if not REPORTS_DIRECTORY.exists():
        return []

    report_rows: list[dict] = []

    for report_path in REPORTS_DIRECTORY.iterdir():
        if not report_path.is_file():
            continue

        extension = report_path.suffix.lower()
        if extension not in ALLOWED_REPORT_EXTENSIONS:
            continue

        stat = report_path.stat()

        report_rows.append(
            {
                "filename": report_path.name,
                "title": report_path.stem.replace("_", " ").title(),
                "type": extension.removeprefix(".").upper(),
                "category": _report_category(report_path.name),
                "description": _report_description(report_path.name),
                "size_bytes": stat.st_size,
                "size": _format_file_size(stat.st_size),
                "modified_at": datetime.fromtimestamp(
                    stat.st_mtime,
                    tz=timezone.utc,
                ).isoformat(),
                "view_url": f"/api/reports/view/{report_path.name}",
                "download_url": (
                    f"/api/reports/download/{report_path.name}"
                ),
            }
        )

    return sorted(
        report_rows,
        key=lambda report: report["modified_at"],
        reverse=True,
    )


def _get_safe_report(filename: str) -> Path | None:
    """Resolve an allowed report without permitting path traversal."""
    if Path(filename).name != filename:
        return None

    report_path = REPORTS_DIRECTORY / filename

    if not report_path.is_file():
        return None

    if report_path.suffix.lower() not in ALLOWED_REPORT_EXTENSIONS:
        return None

    return report_path


def read_history() -> dict:
    """Read saved scan summaries and findings from the history database."""
    empty_result = {
        "scan_count": 0,
        "latest": None,
        "previous": None,
        "summaries": [],
        "recent_findings": [],
        "trends": {
            "network_change": None,
            "score_change": None,
            "finding_change": None,
        },
    }

    if not HISTORY_DB.exists():
        return empty_result

    try:
        with sqlite3.connect(HISTORY_DB) as connection:
            connection.row_factory = sqlite3.Row

            summary_rows = connection.execute(
                """
                SELECT
                    scan_timestamp,
                    total_networks,
                    safe_count,
                    low_risk_count,
                    warning_count,
                    danger_count,
                    rogue_count,
                    evil_twin_count,
                    average_security_score
                FROM scan_summary
                ORDER BY scan_timestamp DESC
                """
            ).fetchall()

            finding_rows = connection.execute(
                """
                SELECT
                    scan_id,
                    scan_timestamp,
                    ssid,
                    bssid,
                    encryption,
                    packet_count,
                    security_score,
                    risk_level,
                    attack_type
                FROM scan_history
                WHERE UPPER(COALESCE(attack_type, 'NORMAL')) <> 'NORMAL'
                ORDER BY scan_timestamp DESC, scan_id DESC
                LIMIT 12
                """
            ).fetchall()
    except sqlite3.Error as database_error:
        print(f"[WARNING] Unable to read history database: {database_error}")
        return empty_result

    summaries = []

    for row in summary_rows:
        summary = dict(row)
        summary["potential_findings"] = (
            int(summary.get("rogue_count") or 0)
            + int(summary.get("evil_twin_count") or 0)
        )
        summaries.append(summary)

    findings = [dict(row) for row in finding_rows]

    latest = summaries[0] if summaries else None
    previous = summaries[1] if len(summaries) > 1 else None

    trends = {
        "network_change": None,
        "score_change": None,
        "finding_change": None,
    }

    if latest and previous:
        trends = {
            "network_change": (
                int(latest["total_networks"] or 0)
                - int(previous["total_networks"] or 0)
            ),
            "score_change": round(
                float(latest["average_security_score"] or 0)
                - float(previous["average_security_score"] or 0),
                1,
            ),
            "finding_change": (
                int(latest["potential_findings"] or 0)
                - int(previous["potential_findings"] or 0)
            ),
        }

    return {
        "scan_count": len(summaries),
        "latest": latest,
        "previous": previous,
        "summaries": summaries,
        "recent_findings": findings,
        "trends": trends,
    }


@app.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "csv_found": NETWORK_CSV.exists(),
            "csv_path": str(NETWORK_CSV),
        }
    )


@app.get("/api/networks")
def networks():
    network_rows = read_networks()

    return jsonify(
        {
            "count": len(network_rows),
            "source": "wifi_scan_results.csv",
            "networks": network_rows,
        }
    )


@app.get("/api/threats")
def threats():
    threat_rows = read_threats()

    return jsonify(
        {
            "count": len(threat_rows),
            "source": "final_security_report.csv",
            "threats": threat_rows,
        }
    )


@app.get("/api/reports")
def reports():
    report_rows = read_reports()

    return jsonify(
        {
            "count": len(report_rows),
            "reports": report_rows,
        }
    )


@app.get("/api/reports/view/<path:filename>")
def view_report(filename):
    report_path = _get_safe_report(filename)

    if report_path is None:
        return jsonify({"error": "Report not found"}), 404

    content = report_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    # Make JSON reports easier to read in the browser.
    if report_path.suffix.lower() == ".json":
        try:
            content = json.dumps(
                json.loads(content),
                indent=2,
                ensure_ascii=False,
            )
        except json.JSONDecodeError:
            pass

    return Response(
        content,
        status=200,
        mimetype="text/plain",
        headers={
            "Content-Disposition": (
                f'inline; filename="{report_path.name}"'
            )
        },
    )


@app.get("/api/reports/download/<path:filename>")
def download_report(filename):
    report_path = _get_safe_report(filename)

    if report_path is None:
        return jsonify({"error": "Report not found"}), 404

    return send_from_directory(
        REPORTS_DIRECTORY,
        report_path.name,
        as_attachment=True,
    )


@app.get("/api/history")
def history():
    return jsonify(read_history())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
