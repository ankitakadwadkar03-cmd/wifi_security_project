from __future__ import annotations

import csv
import json
import os
import signal
import sys
import threading
import time
import sqlite3
import shutil
import subprocess
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory
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

SYSTEMCTL_PATH = "/usr/bin/systemctl"
SCANNER_SERVICE_NAME = "netshield-scanner.service"
SCANNER_SERVICE_INTERFACE = "wlan0"
CAPTURE_SERVICE_NAME = "netshield-capture.service"
CAPTURE_SERVICE_INTERFACE = "wlan0"
PACKET_LOG_CSV = PROJECT_ROOT / "packet_logs" / "wifi_packets.csv"
LIVE_PACKET_ALERT_HISTORY_JSON = (
    PROJECT_ROOT
    / "security_reports"
    / "live_packet_alert_history.json"
)
LIVE_PACKET_ALERT_HISTORY_LOG = (
    PROJECT_ROOT
    / "security_reports"
    / "live_packet_alert_history.log"
)


def _normalize_bssid(value: str | None) -> str:
    """Normalize a BSSID so scanner and report rows can be matched."""
    return str(value or "").strip().upper()


def _read_security_report_index() -> dict[str, dict]:
    """Index security-report rows by BSSID."""
    if not SECURITY_REPORT_CSV.exists():
        return {}

    report_index: dict[str, dict] = {}

    with SECURITY_REPORT_CSV.open(
        "r", encoding="utf-8", newline=""
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            bssid = _normalize_bssid(row.get("BSSID"))

            if bssid and bssid not in {"UNKNOWN", "BROADCAST"}:
                report_index[bssid] = dict(row)

    return report_index


def _network_status(report_row: dict | None) -> str:
    """Convert report risk and attack values into a frontend status."""
    if not report_row:
        return "Unclassified"

    attack_type = (
        report_row.get("Attack_Type") or "NORMAL"
    ).strip().upper()

    risk_level = (
        report_row.get("Risk_Level") or "UNKNOWN"
    ).strip().upper()

    # Any automated attack classification still requires verification,
    # even when its numeric risk score is marked SAFE.
    if attack_type not in {"", "NORMAL"}:
        return "Review"

    return {
        "SAFE": "Safe",
        "LOW RISK": "Review",
        "WARNING": "Warning",
        "DANGER": "Critical",
    }.get(risk_level, "Unclassified")


def _format_attack_type(report_row: dict | None) -> str:
    """Return a readable attack classification."""
    if not report_row:
        return "No analysis available"

    attack_type = (
        report_row.get("Attack_Type") or "NORMAL"
    ).strip().upper()

    return attack_type.replace("_", " ").title()


def read_networks() -> list[dict]:
    """Read scanner networks and merge matching security-report results."""
    if not NETWORK_CSV.exists():
        return []

    report_index = _read_security_report_index()
    networks: list[dict] = []

    with NETWORK_CSV.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            ssid = (row.get("SSID") or "").strip()
            bssid = _normalize_bssid(row.get("BSSID"))

            if not ssid and not bssid:
                continue

            report_row = report_index.get(bssid)

            networks.append(
                {
                    "ssid": ssid or "Hidden Network",
                    "bssid": bssid,
                    "channel": (row.get("Channel") or "").strip(),
                    "frequency": (row.get("Frequency") or "").strip(),
                    "signal": (row.get("Signal") or "").strip(),
                    "encryption": (
                        row.get("Encryption") or "Unknown"
                    ).strip(),
                    "vendor": "Not analyzed",
                    "status": _network_status(report_row),
                    "attack": _format_attack_type(report_row),
                    "security_score": (
                        _safe_int(
                            report_row.get("Suspicious_Score"),
                            default=100,
                        )
                        if report_row
                        else None
                    ),
                }
            )

    return networks

def _safe_int(value, default=0):
    """Convert a CSV value to an integer without crashing."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def read_packets(limit: int = 50) -> list[dict]:
    """Return the most recent packet-capture rows."""
    if not PACKET_LOG_CSV.exists():
        return []

    safe_limit = max(1, min(limit, 500))
    recent_rows = deque(maxlen=safe_limit)

    with PACKET_LOG_CSV.open(
        "r", encoding="utf-8", newline=""
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            recent_rows.append(
                {
                    "timestamp": (
                        row.get("Timestamp") or ""
                    ).strip(),
                    "packet_type": (
                        row.get("Packet Type") or "Unknown"
                    ).strip(),
                    "source_mac": _normalize_bssid(
                        row.get("Source MAC")
                    ),
                    "destination_mac": (
                        row.get("Destination MAC") or "Unknown"
                    ).strip(),
                    "bssid": _normalize_bssid(
                        row.get("BSSID")
                    ),
                    "frame_type": (
                        row.get("Frame Type") or "Unknown"
                    ).strip(),
                    "signal_strength": _safe_int(
                        row.get("Signal Strength"),
                        default=0,
                    ),
                }
            )

    return list(reversed(recent_rows))


def read_packet_alerts() -> list[dict]:
    """Detect potential security events in the latest captured packets."""
    packets = read_packets(limit=200)

    if not packets:
        return []

    def timestamp_seconds(value: str) -> int | None:
        try:
            parsed = datetime.strptime(value, "%H:%M:%S")
            return (
                parsed.hour * 3600
                + parsed.minute * 60
                + parsed.second
            )
        except (TypeError, ValueError):
            return None

    latest_seconds = None
    latest_timestamp = ""

    for packet in packets:
        packet_timestamp = packet.get("timestamp", "")
        latest_seconds = timestamp_seconds(packet_timestamp)

        if latest_seconds is not None:
            latest_timestamp = packet_timestamp
            break

    if latest_seconds is None:
        return []

    def packets_within(seconds: int) -> list[dict]:
        recent = []

        for packet in packets:
            packet_seconds = timestamp_seconds(
                packet.get("timestamp", "")
            )

            if packet_seconds is None:
                continue

            age = (latest_seconds - packet_seconds) % 86400

            if age <= seconds:
                recent.append(packet)

        return recent

    alerts: list[dict] = []

    recent_10 = packets_within(10)
    recent_5 = packets_within(5)

    # High: multiple deauthentication frames in a short period.
    deauth_packets = [
        packet
        for packet in recent_10
        if "deauth" in str(
            packet.get("packet_type", "")
        ).lower()
    ]

    if len(deauth_packets) >= 5:
        packet = deauth_packets[0]

        alerts.append(
            {
                "severity": "High",
                "title": "Potential Deauthentication Burst",
                "bssid": (
                    packet.get("bssid")
                    or packet.get("source_mac")
                    or "Unknown"
                ),
                "summary": (
                    f"{len(deauth_packets)} deauthentication packets "
                    "were observed within 10 seconds. This is an "
                    "automated defensive alert and should be verified "
                    "before concluding that an attack occurred."
                ),
                "source": "live_packet_analysis",
                "alert_type": "DEAUTH_BURST",
            }
        )

    # Medium: unusually high total packet activity.
    if len(recent_5) >= 40:
        alerts.append(
            {
                "severity": "Medium",
                "title": "High Packet Activity",
                "bssid": "Multiple Devices",
                "summary": (
                    f"{len(recent_5)} packets were observed within "
                    "5 seconds. This may be normal busy-network traffic "
                    "or activity that requires further review."
                ),
                "source": "live_packet_analysis",
                "alert_type": "PACKET_BURST",
            }
        )

    # Count Authentication and Probe Request activity by source.
    auth_by_source: dict[str, int] = {}
    probe_by_source: dict[str, int] = {}

    for packet in recent_10:
        source = packet.get("source_mac") or "Unknown"

        if source in {"", "UNKNOWN", "BROADCAST"}:
            continue

        packet_type = str(
            packet.get("packet_type", "")
        ).lower()

        if packet_type == "authentication":
            auth_by_source[source] = (
                auth_by_source.get(source, 0) + 1
            )

        if packet_type == "probe request":
            probe_by_source[source] = (
                probe_by_source.get(source, 0) + 1
            )

    if auth_by_source:
        source, count = max(
            auth_by_source.items(),
            key=lambda item: item[1],
        )

        if count >= 15:
            alerts.append(
                {
                    "severity": "Medium",
                    "title": "Repeated Authentication Activity",
                    "bssid": source,
                    "summary": (
                        f"{count} authentication packets from the same "
                        "source were observed within 10 seconds. Review "
                        "the activity to determine whether it is expected."
                    ),
                    "source": "live_packet_analysis",
                    "alert_type": "AUTH_BURST",
                }
            )

    if probe_by_source:
        source, count = max(
            probe_by_source.items(),
            key=lambda item: item[1],
        )

        if count >= 20:
            alerts.append(
                {
                    "severity": "Low",
                    "title": "Repeated Probe Request Activity",
                    "bssid": source,
                    "summary": (
                        f"{count} probe requests from the same source "
                        "were observed within 10 seconds. Device discovery "
                        "can cause this normally, so this alert is "
                        "informational and requires context."
                    ),
                    "source": "live_packet_analysis",
                    "alert_type": "PROBE_BURST",
                }
            )

    alert_counts = {
        "DEAUTH_BURST": len(deauth_packets),
        "PACKET_BURST": len(recent_5),
        "AUTH_BURST": max(auth_by_source.values(), default=0),
        "PROBE_BURST": max(probe_by_source.values(), default=0),
    }

    for alert in alerts:
        alert_type = alert.get("alert_type", "PACKET_ACTIVITY")
        severity = alert.get("severity", "Low")

        alert.setdefault("ssid", "Live Packet Activity")
        alert.setdefault("encryption", "Not applicable")
        alert.setdefault("attack_type", alert_type)
        alert.setdefault("evidence_timestamp", latest_timestamp)
        alert.setdefault(
            "total_packets",
            alert_counts.get(alert_type, 0),
        )
        alert.setdefault(
            "risk_level",
            {
                "High": "WARNING",
                "Medium": "LOW RISK",
                "Low": "LOW RISK",
            }.get(severity, "REVIEW"),
        )

    severity_order = {
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    alerts.sort(
        key=lambda alert: severity_order.get(
            alert.get("severity"),
            0,
        ),
        reverse=True,
    )

    return alerts


def read_packet_alert_history(limit: int = 100) -> list[dict]:
    """Read saved live packet-alert history, newest first."""
    if not LIVE_PACKET_ALERT_HISTORY_JSON.exists():
        return []

    try:
        payload = json.loads(
            LIVE_PACKET_ALERT_HISTORY_JSON.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        return []

    history = payload.get("alerts", [])

    if not isinstance(history, list):
        return []

    safe_limit = max(1, min(limit, 200))

    return list(reversed(history[-safe_limit:]))


def save_packet_alert_history(alerts: list[dict]) -> list[dict]:
    """Persist packet alerts while avoiding polling duplicates."""
    if not alerts:
        return read_packet_alert_history()

    LIVE_PACKET_ALERT_HISTORY_JSON.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    existing_history = read_packet_alert_history(limit=200)
    history = list(reversed(existing_history))

    now = datetime.now()
    now_text = now.strftime("%Y-%m-%d %H:%M:%S")

    new_log_entries: list[dict] = []

    for alert in alerts:
        alert_type = str(
            alert.get("alert_type")
            or alert.get("attack_type")
            or "PACKET_ACTIVITY"
        )

        bssid = str(
            alert.get("bssid") or "Unknown"
        )

        matching_event = None

        for event in reversed(history):
            if (
                event.get("alert_type") == alert_type
                and event.get("bssid") == bssid
            ):
                last_seen_text = (
                    event.get("last_seen")
                    or event.get("recorded_at")
                    or ""
                )

                try:
                    last_seen = datetime.strptime(
                        last_seen_text,
                        "%Y-%m-%d %H:%M:%S",
                    )
                except (TypeError, ValueError):
                    continue

                if (now - last_seen).total_seconds() <= 30:
                    matching_event = event

                break

        if matching_event is not None:
            matching_event.update(
                {
                    "last_seen": now_text,
                    "evidence_timestamp": alert.get(
                        "evidence_timestamp", ""
                    ),
                    "severity": alert.get(
                        "severity", "Low"
                    ),
                    "title": alert.get(
                        "title", "Packet Security Alert"
                    ),
                    "ssid": alert.get(
                        "ssid", "Live Packet Activity"
                    ),
                    "summary": alert.get(
                        "summary", ""
                    ),
                    "total_packets": alert.get(
                        "total_packets", 0
                    ),
                    "risk_level": alert.get(
                        "risk_level", "REVIEW"
                    ),
                }
            )

            continue

        history_event = {
            "recorded_at": now_text,
            "last_seen": now_text,
            "evidence_timestamp": alert.get(
                "evidence_timestamp", ""
            ),
            "severity": alert.get("severity", "Low"),
            "title": alert.get(
                "title", "Packet Security Alert"
            ),
            "ssid": alert.get(
                "ssid", "Live Packet Activity"
            ),
            "bssid": bssid,
            "attack_type": alert.get(
                "attack_type", alert_type
            ),
            "alert_type": alert_type,
            "total_packets": alert.get(
                "total_packets", 0
            ),
            "risk_level": alert.get(
                "risk_level", "REVIEW"
            ),
            "summary": alert.get("summary", ""),
            "source": "live_packet_analysis",
        }

        history.append(history_event)
        new_log_entries.append(history_event)

    history = history[-200:]

    payload = {
        "updated_at": now_text,
        "count": len(history),
        "alerts": history,
    }

    LIVE_PACKET_ALERT_HISTORY_JSON.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    if new_log_entries:
        with LIVE_PACKET_ALERT_HISTORY_LOG.open(
            "a",
            encoding="utf-8",
        ) as log_file:
            for event in new_log_entries:
                log_file.write(
                    f"{event['recorded_at']} | "
                    f"Severity={event['severity']} | "
                    f"Type={event['alert_type']} | "
                    f"BSSID={event['bssid']} | "
                    f"Packets={event['total_packets']} | "
                    f"Summary={event['summary']}\n"
                )

    return list(reversed(history))


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
        "live_packet_alert_history.json":
            "Structured history and evidence for detected live packet alerts.",
        "live_packet_alert_history.log":
            "Readable evidence log for detected live packet alerts.",
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


def read_adapter_status() -> dict:
    """Detect available Linux wireless interfaces using the iw command."""
    if shutil.which("iw") is None:
        return {
            "available": False,
            "state": "command_missing",
            "interfaces": [],
            "message": "The iw command is not installed.",
        }

    try:
        result = subprocess.run(
            ["iw", "dev"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as command_error:
        return {
            "available": False,
            "state": "error",
            "interfaces": [],
            "message": f"Unable to inspect wireless interfaces: {command_error}",
        }

    if result.returncode != 0:
        return {
            "available": False,
            "state": "error",
            "interfaces": [],
            "message": (
                result.stderr.strip()
                or "The iw command could not inspect wireless interfaces."
            ),
        }

    interfaces = []
    current_interface = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()

        if line.startswith("Interface "):
            if current_interface:
                interfaces.append(current_interface)

            current_interface = {
                "name": line.split(" ", 1)[1].strip(),
                "mode": "unknown",
            }

        elif line.startswith("type ") and current_interface:
            current_interface["mode"] = line.split(" ", 1)[1].strip()

    if current_interface:
        interfaces.append(current_interface)

    if not interfaces:
        return {
            "available": False,
            "state": "not_detected",
            "interfaces": [],
            "message": "No wireless adapter is currently detected.",
        }

    return {
        "available": True,
        "state": "idle",
        "interfaces": interfaces,
        "message": f"{len(interfaces)} wireless interface(s) detected.",
    }



def _run_service_command(
    arguments: list[str],
    timeout: int = 50,
) -> tuple[int, str, str]:
    """Run one narrowly permitted systemctl command through sudo."""
    try:
        result = subprocess.run(
            [
                "sudo",
                "-n",
                SYSTEMCTL_PATH,
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as command_error:
        return -1, "", str(command_error)

    return (
        result.returncode,
        result.stdout.strip(),
        result.stderr.strip(),
    )


def _read_scanner_service_state() -> tuple[str, str]:
    """Return the current systemd service state and any error details."""
    return_code, output, error = _run_service_command(
        ["is-active", SCANNER_SERVICE_NAME],
        timeout=10,
    )

    service_state = output.strip().lower()

    if return_code == 0:
        return service_state or "active", ""

    if service_state in {
        "inactive",
        "failed",
        "activating",
        "deactivating",
    }:
        return service_state, error

    return (
        "error",
        error
        or output
        or "Unable to read the NetShield scanner service state.",
    )


def _read_scanner_service_pid() -> int | None:
    """Return the scanner service MainPID when one is available."""
    return_code, output, _error = _run_service_command(
        [
            "show",
            SCANNER_SERVICE_NAME,
            "--property=MainPID",
            "--value",
        ],
        timeout=10,
    )

    if return_code != 0:
        return None

    try:
        process_id = int(output)
    except (TypeError, ValueError):
        return None

    return process_id if process_id > 0 else None


def read_scanner_status() -> dict:
    """Return protected scanner-service and adapter status."""
    service_state, service_error = _read_scanner_service_state()

    state_mapping = {
        "active": "running",
        "activating": "starting",
        "deactivating": "stopping",
        "inactive": "idle",
        "failed": "error",
        "error": "error",
    }

    scanner_state = state_mapping.get(service_state, "error")
    running = scanner_state in {
        "starting",
        "running",
        "stopping",
    }

    messages = {
        "starting": (
            f"Starting scanner on {SCANNER_SERVICE_INTERFACE}."
        ),
        "running": (
            f"Scanning on {SCANNER_SERVICE_INTERFACE}."
        ),
        "stopping": "Stopping scanner safely.",
        "idle": "Scanner is idle.",
        "error": (
            "The scanner service encountered an error."
        ),
    }

    return {
        "state": scanner_state,
        "running": running,
        "interface": (
            SCANNER_SERVICE_INTERFACE if running else None
        ),
        "pid": (
            _read_scanner_service_pid() if running else None
        ),
        "started_at": None,
        "stopped_at": None,
        "last_error": service_error,
        "message": messages[scanner_state],
        "adapter": read_adapter_status(),
    }


def start_scanner_process(
    interface: str | None = None,
) -> tuple[dict, int]:
    """Start the protected NetShield scanner service."""
    capture_status = read_capture_status()

    if capture_status["running"]:
        return {
            "ok": False,
            "state": "service_conflict",
            "message": (
                "Stop packet capture before starting WiFi scanning."
            ),
            "capture": capture_status,
        }, 409

    adapter = read_adapter_status()

    if not adapter["available"]:
        return {
            "ok": False,
            "state": "not_detected",
            "message": adapter["message"],
        }, 409

    interface_names = [
        item["name"]
        for item in adapter["interfaces"]
    ]

    selected_interface = interface or interface_names[0]

    if selected_interface not in interface_names:
        return {
            "ok": False,
            "state": "invalid_interface",
            "message": (
                f"Wireless interface '{selected_interface}' "
                "is not currently available."
            ),
        }, 400

    if selected_interface != SCANNER_SERVICE_INTERFACE:
        return {
            "ok": False,
            "state": "interface_not_configured",
            "message": (
                "The protected scanner service is configured for "
                f"{SCANNER_SERVICE_INTERFACE}, not "
                f"{selected_interface}."
            ),
        }, 409

    current_status = read_scanner_status()

    if current_status["running"]:
        return {
            "ok": False,
            "state": current_status["state"],
            "message": "The scanner is already running.",
            "scanner": current_status,
        }, 409

    return_code, output, error = _run_service_command(
        ["start", SCANNER_SERVICE_NAME],
    )

    if return_code != 0:
        return {
            "ok": False,
            "state": "error",
            "message": (
                error
                or output
                or "Unable to start the scanner service."
            ),
        }, 500

    scanner_status = read_scanner_status()

    return {
        "ok": True,
        "scanner": scanner_status,
    }, 202


def stop_scanner_process() -> tuple[dict, int]:
    """Stop the protected scanner service safely."""
    current_status = read_scanner_status()

    if not current_status["running"]:
        current_status["state"] = "idle"
        current_status["message"] = "Scanner is already stopped."

        return {
            "ok": True,
            "scanner": current_status,
        }, 200

    return_code, output, error = _run_service_command(
        ["stop", SCANNER_SERVICE_NAME],
    )

    if return_code != 0:
        return {
            "ok": False,
            "state": "error",
            "message": (
                error
                or output
                or "Unable to stop the scanner service."
            ),
        }, 500

    scanner_status = read_scanner_status()
    scanner_status["message"] = (
        "Scanner stopped. Latest CSV results were preserved."
    )

    return {
        "ok": True,
        "scanner": scanner_status,
    }, 200


def _read_capture_service_state() -> tuple[str, str]:
    """Return the packet-capture systemd service state."""
    return_code, output, error = _run_service_command(
        ["is-active", CAPTURE_SERVICE_NAME],
        timeout=10,
    )

    service_state = output.strip().lower()

    if return_code == 0:
        return service_state or "active", ""

    if service_state in {
        "inactive",
        "failed",
        "activating",
        "deactivating",
    }:
        return service_state, error

    return (
        "error",
        error
        or output
        or "Unable to read the NetShield capture service state.",
    )


def _read_capture_service_pid() -> int | None:
    """Return the packet-capture service MainPID."""
    return_code, output, _error = _run_service_command(
        [
            "show",
            CAPTURE_SERVICE_NAME,
            "--property=MainPID",
            "--value",
        ],
        timeout=10,
    )

    if return_code != 0:
        return None

    try:
        process_id = int(output)
    except (TypeError, ValueError):
        return None

    return process_id if process_id > 0 else None


def read_capture_status() -> dict:
    """Return packet-capture service and adapter status."""
    service_state, service_error = _read_capture_service_state()

    state_mapping = {
        "active": "running",
        "activating": "starting",
        "deactivating": "stopping",
        "inactive": "idle",
        "failed": "error",
        "error": "error",
    }

    capture_state = state_mapping.get(service_state, "error")

    running = capture_state in {
        "starting",
        "running",
        "stopping",
    }

    messages = {
        "starting": (
            f"Starting packet capture on {CAPTURE_SERVICE_INTERFACE}."
        ),
        "running": (
            f"Capturing packets on {CAPTURE_SERVICE_INTERFACE}."
        ),
        "stopping": "Stopping packet capture safely.",
        "idle": "Packet capture is idle.",
        "error": "The packet-capture service encountered an error.",
    }

    return {
        "state": capture_state,
        "running": running,
        "interface": (
            CAPTURE_SERVICE_INTERFACE if running else None
        ),
        "pid": (
            _read_capture_service_pid() if running else None
        ),
        "last_error": service_error,
        "message": messages[capture_state],
        "adapter": read_adapter_status(),
        "packet_log_found": PACKET_LOG_CSV.exists(),
    }


def start_capture_process(
    interface: str | None = None,
) -> tuple[dict, int]:
    """Start the protected packet-capture service."""
    scanner_status = read_scanner_status()

    if scanner_status["running"]:
        return {
            "ok": False,
            "state": "service_conflict",
            "message": (
                "Stop WiFi scanning before starting packet capture."
            ),
            "scanner": scanner_status,
        }, 409

    adapter = read_adapter_status()

    if not adapter["available"]:
        return {
            "ok": False,
            "state": "not_detected",
            "message": adapter["message"],
        }, 409

    interface_names = [
        item["name"]
        for item in adapter["interfaces"]
    ]

    selected_interface = interface or interface_names[0]

    if selected_interface not in interface_names:
        return {
            "ok": False,
            "state": "invalid_interface",
            "message": (
                f"Wireless interface '{selected_interface}' "
                "is not currently available."
            ),
        }, 400

    if selected_interface != CAPTURE_SERVICE_INTERFACE:
        return {
            "ok": False,
            "state": "interface_not_configured",
            "message": (
                "The protected packet-capture service is configured "
                f"for {CAPTURE_SERVICE_INTERFACE}, not "
                f"{selected_interface}."
            ),
        }, 409

    current_status = read_capture_status()

    if current_status["running"]:
        return {
            "ok": False,
            "state": current_status["state"],
            "message": "Packet capture is already running.",
            "capture": current_status,
        }, 409

    return_code, output, error = _run_service_command(
        ["start", CAPTURE_SERVICE_NAME],
    )

    if return_code != 0:
        return {
            "ok": False,
            "state": "error",
            "message": (
                error
                or output
                or "Unable to start packet capture."
            ),
        }, 500

    capture_status = read_capture_status()

    return {
        "ok": True,
        "capture": capture_status,
    }, 202


def stop_capture_process() -> tuple[dict, int]:
    """Stop the protected packet-capture service safely."""
    current_status = read_capture_status()

    if not current_status["running"]:
        current_status["state"] = "idle"
        current_status["message"] = (
            "Packet capture is already stopped."
        )

        return {
            "ok": True,
            "capture": current_status,
        }, 200

    return_code, output, error = _run_service_command(
        ["stop", CAPTURE_SERVICE_NAME],
    )

    if return_code != 0:
        return {
            "ok": False,
            "state": "error",
            "message": (
                error
                or output
                or "Unable to stop packet capture."
            ),
        }, 500

    capture_status = read_capture_status()
    capture_status["message"] = (
        "Packet capture stopped. CSV log was preserved."
    )

    return {
        "ok": True,
        "capture": capture_status,
    }, 200


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


@app.get("/api/packets")
def packets():
    limit = request.args.get(
        "limit",
        default=50,
        type=int,
    )

    packet_rows = read_packets(limit=limit)

    return jsonify(
        {
            "count": len(packet_rows),
            "source": "wifi_packets.csv",
            "packets": packet_rows,
        }
    )


@app.get("/api/alerts/history")
def alert_history():
    limit = request.args.get(
        "limit",
        default=50,
        type=int,
    )

    history_rows = read_packet_alert_history(limit=limit)

    return jsonify(
        {
            "count": len(history_rows),
            "source": "live_packet_alert_history.json",
            "alerts": history_rows,
        }
    )


@app.get("/api/threats")
def threats():
    live_alerts = read_packet_alerts()

    if live_alerts:
        save_packet_alert_history(live_alerts)

    report_findings = read_threats()

    threat_rows = live_alerts + report_findings

    return jsonify(
        {
            "count": len(threat_rows),
            "sources": [
                "live_packet_analysis",
                "final_security_report.csv",
            ],
            "live_alert_count": len(live_alerts),
            "report_finding_count": len(report_findings),
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


@app.get("/api/adapter/status")
def adapter_status():
    return jsonify(read_adapter_status())


@app.get("/api/scanner/status")
def scanner_status():
    return jsonify(read_scanner_status())


@app.post("/api/scanner/start")
def scanner_start():
    request_data = request.get_json(silent=True) or {}
    response, status_code = start_scanner_process(
        request_data.get("interface")
    )
    return jsonify(response), status_code


@app.post("/api/scanner/stop")
def scanner_stop():
    response, status_code = stop_scanner_process()
    return jsonify(response), status_code


@app.get("/api/capture/status")
def capture_status():
    return jsonify(read_capture_status())


@app.post("/api/capture/start")
def capture_start():
    request_data = request.get_json(silent=True) or {}
    response, status_code = start_capture_process(
        request_data.get("interface")
    )
    return jsonify(response), status_code


@app.post("/api/capture/stop")
def capture_stop():
    response, status_code = stop_capture_process()
    return jsonify(response), status_code


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
