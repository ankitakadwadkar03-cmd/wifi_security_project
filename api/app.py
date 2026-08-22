from __future__ import annotations

import csv
import hashlib
import json
import os
import signal
import sys
import threading
import time
import tempfile
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
SCANNER_STATUS_JSON = PROJECT_ROOT / "scan_results" / "scanner_status.json"
SECURITY_REPORT_CSV = PROJECT_ROOT / "security_reports" / "final_security_report.csv"
TRUSTED_NETWORKS_CSV = PROJECT_ROOT / "trusted_baseline" / "trusted_networks.csv"
REPORTS_DIRECTORY = PROJECT_ROOT / "security_reports"
SECURITY_ADVISOR_TEXT = (
    REPORTS_DIRECTORY
    / "security_advisor_report.txt"
)
SECURITY_ADVISOR_JSON = (
    REPORTS_DIRECTORY
    / "security_advisor_report.json"
)

TRUSTED_BASELINE_REPORT_CSV = (
    REPORTS_DIRECTORY
    / "trusted_baseline_report.csv"
)
TRUSTED_BASELINE_REPORT_JSON = (
    REPORTS_DIRECTORY
    / "trusted_baseline_report.json"
)
CURRENT_TRUSTED_BASELINE_VERSION = "baseline-aware-v2"

LEGACY_TRUSTED_BASELINE_DIRECTORY = (
    REPORTS_DIRECTORY
    / "legacy_trusted_baseline"
)

PRE_CONNECT_REPORT_CSV = (
    REPORTS_DIRECTORY
    / "pre_connect_safety_report.csv"
)

PRE_CONNECT_REPORT_JSON = (
    REPORTS_DIRECTORY
    / "pre_connect_safety_report.json"
)

CURRENT_PRE_CONNECT_VERSION = "baseline-aware-v2"

HISTORY_DB = PROJECT_ROOT / "security_reports" / "history.db"
HISTORICAL_TREND_TEXT = (
    REPORTS_DIRECTORY
    / "historical_trend_report.txt"
)
HISTORICAL_TREND_JSON = (
    REPORTS_DIRECTORY
    / "historical_trend_report.json"
)
LEGACY_HISTORY_DIRECTORY = (
    REPORTS_DIRECTORY
    / "legacy_history"
)

ALERT_NOTIFICATION_LOG = (
    REPORTS_DIRECTORY
    / "alert_notifications.log"
)
ALERT_NOTIFICATION_JSON = (
    REPORTS_DIRECTORY
    / "alert_notifications.json"
)
CURRENT_ALERT_NOTIFICATION_VERSION = "baseline-aware-v2"

LEGACY_ALERT_NOTIFICATION_DIRECTORY = (
    REPORTS_DIRECTORY
    / "legacy_alert_notifications"
)

ALLOWED_REPORT_EXTENSIONS = {".csv", ".json", ".txt", ".log"}

SYSTEMCTL_PATH = "/usr/bin/systemctl"
SCANNER_SERVICE_NAME = "netshield-scanner.service"
SCANNER_SERVICE_INTERFACE = "wlan0"
CAPTURE_SERVICE_NAME = "netshield-capture.service"
CAPTURE_SERVICE_INTERFACE = "wlan0"
PACKET_LOG_CSV = PROJECT_ROOT / "packet_logs" / "wifi_packets.csv"
CAPTURE_STATUS_JSON = PROJECT_ROOT / "packet_logs" / "capture_status.json"
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


def read_packets(
    limit: int = 50,
    session_start_row: int | None = None,
) -> list[dict]:
    """Return recent packet rows, optionally limited to one capture session."""
    if not PACKET_LOG_CSV.exists():
        return []

    safe_limit = max(1, min(limit, 500))
    safe_start_row = (
        max(0, int(session_start_row))
        if session_start_row is not None
        else 0
    )
    recent_rows = deque(maxlen=safe_limit)

    with PACKET_LOG_CSV.open(
        "r", encoding="utf-8", newline=""
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        for row_index, row in enumerate(reader):
            if row_index < safe_start_row:
                continue

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
    """Detect security events only within the latest capture session."""
    progress = read_capture_progress()

    session_start_row = _safe_int(
        progress.get("session_start_row"),
        default=0,
    )

    packets = read_packets(
        limit=200,
        session_start_row=session_start_row,
    )

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
                "EVIL_TWIN": "Critical",
                "ROGUE_AP": "High",
                "SUSPICIOUS": "Medium",
                "WEAK_ENCRYPTION": "Medium",
                "UNKNOWN_NETWORK": "Review",
            }.get(
                attack_type,
                {
                    "DANGER": "Critical",
                    "WARNING": "High",
                    "LOW RISK": "Medium",
                }.get(risk_level, "Review"),
            )

            title = {
                "ROGUE_AP": "Potential Rogue Access Point",
                "EVIL_TWIN": "Potential Evil Twin Network",
                "SUSPICIOUS": "Suspicious Wireless Activity",
                "WEAK_ENCRYPTION": "Weak WiFi Encryption",
                "UNKNOWN_NETWORK": "Unverified Network",
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
                    "confidence": _safe_int(
                        row.get("Confidence"),
                        default=0,
                    ),
                    "detection_reason": (
                        row.get("Detection_Reason")
                        or ""
                    ).strip(),
                    "recommended_action": (
                        row.get("Recommended_Action")
                        or ""
                    ).strip(),
                    "summary": (
                        (
                            row.get("Detection_Reason")
                            or ""
                        ).strip()
                        or (
                            "This is a potential finding produced by "
                            "automated wireless analysis. Verify the "
                            "BSSID and compare it with trusted network "
                            "records before taking action."
                        )
                    ),
                }
            )

    return findings


def get_threat_report_status() -> dict:
    """Check whether the saved threat report matches current inputs."""

    if not SECURITY_REPORT_CSV.exists():
        return {
            "status": "missing",
            "analysis_required": True,
            "stale_sources": [],
            "message": (
                "No threat analysis report exists yet. "
                "Run Threat Analysis to generate one."
            ),
        }

    try:
        report_mtime = SECURITY_REPORT_CSV.stat().st_mtime
    except OSError:
        return {
            "status": "unavailable",
            "analysis_required": True,
            "stale_sources": [],
            "message": (
                "Threat report freshness could not be verified. "
                "Run Threat Analysis again."
            ),
        }

    source_files = [
        ("WiFi scan", NETWORK_CSV),
        ("packet capture", PACKET_LOG_CSV),
        ("trusted baseline", TRUSTED_NETWORKS_CSV),
    ]

    stale_sources = []

    for label, source_path in source_files:
        if not source_path.exists():
            continue

        try:
            if source_path.stat().st_mtime > report_mtime:
                stale_sources.append(label)
        except OSError:
            continue

    if stale_sources:
        return {
            "status": "stale",
            "analysis_required": True,
            "stale_sources": stale_sources,
            "message": (
                "Saved threat findings are older than current "
                + ", ".join(stale_sources)
                + ". Run Threat Analysis again."
            ),
        }

    return {
        "status": "current",
        "analysis_required": False,
        "stale_sources": [],
        "message": "Threat analysis report is current.",
    }


def get_trusted_baseline_report_status() -> dict:
    """Check whether generated Trusted Baseline reports match current sources."""

    report_files = [
        TRUSTED_BASELINE_REPORT_CSV,
        TRUSTED_BASELINE_REPORT_JSON,
    ]

    existing_files = [
        report
        for report in report_files
        if report.exists()
    ]

    if not existing_files:
        return {
            "status": "missing",
            "generation_required": True,
            "analysis_version": None,
            "current_version":
                CURRENT_TRUSTED_BASELINE_VERSION,
            "migration_required": False,
            "message": (
                "No current Trusted Baseline report exists yet. "
                "Generate it from the latest WiFi scan and "
                "trusted-network baseline."
            ),
        }

    if len(existing_files) != len(report_files):
        return {
            "status": "incomplete",
            "generation_required": True,
            "analysis_version": None,
            "current_version":
                CURRENT_TRUSTED_BASELINE_VERSION,
            "migration_required": True,
            "message": (
                "Trusted Baseline report files are incomplete "
                "and cannot be treated as current."
            ),
        }

    try:
        payload = json.loads(
            TRUSTED_BASELINE_REPORT_JSON.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        return {
            "status": "unavailable",
            "generation_required": True,
            "analysis_version": None,
            "current_version":
                CURRENT_TRUSTED_BASELINE_VERSION,
            "migration_required": True,
            "message": (
                "Trusted Baseline JSON could not be "
                "validated: "
                + str(exc)
            ),
        }

    stored_version = str(
        payload.get(
            "analysis_version",
            "",
        )
    ).strip()

    stored_scan_fingerprint = str(
        payload.get(
            "source_scan_sha256",
            "",
        )
    ).strip()

    stored_baseline_fingerprint = str(
        payload.get(
            "source_trusted_baseline_sha256",
            "",
        )
    ).strip()

    if (
        stored_version
            != CURRENT_TRUSTED_BASELINE_VERSION
        or not stored_scan_fingerprint
        or not stored_baseline_fingerprint
    ):
        return {
            "status": "legacy",
            "generation_required": True,
            "analysis_version": (
                stored_version
                or "legacy-pre-provenance"
            ),
            "current_version":
                CURRENT_TRUSTED_BASELINE_VERSION,
            "migration_required": True,
            "archive_legacy_url":
                "/api/trusted-baseline/archive-legacy",
            "message": (
                "Saved Trusted Baseline reports were "
                "created before the current provenance-aware "
                "format and are not treated as current."
            ),
        }

    current_scan_fingerprint = (
        _calculate_file_sha256(
            NETWORK_CSV
        )
    )

    current_baseline_fingerprint = (
        _calculate_file_sha256(
            TRUSTED_NETWORKS_CSV
        )
    )

    if (
        current_scan_fingerprint is None
        or current_baseline_fingerprint is None
    ):
        return {
            "status": "unavailable",
            "generation_required": True,
            "analysis_version": stored_version,
            "current_version":
                CURRENT_TRUSTED_BASELINE_VERSION,
            "migration_required": False,
            "message": (
                "Current WiFi scan or trusted-network "
                "baseline could not be fingerprinted."
            ),
        }

    stale_sources = []

    if (
        stored_scan_fingerprint
        != current_scan_fingerprint
    ):
        stale_sources.append(
            "WiFi scan"
        )

    if (
        stored_baseline_fingerprint
        != current_baseline_fingerprint
    ):
        stale_sources.append(
            "trusted baseline"
        )

    if stale_sources:
        return {
            "status": "stale",
            "generation_required": True,
            "analysis_version": stored_version,
            "current_version":
                CURRENT_TRUSTED_BASELINE_VERSION,
            "migration_required": False,
            "stale_sources": stale_sources,
            "message": (
                "Saved Trusted Baseline reports do not match "
                "the current "
                + ", ".join(stale_sources)
                + ". Generate them again."
            ),
        }

    return {
        "status": "current",
        "generation_required": False,
        "analysis_version": stored_version,
        "current_version":
            CURRENT_TRUSTED_BASELINE_VERSION,
        "migration_required": False,
        "stale_sources": [],
        "message": (
            "Trusted Baseline reports match the current "
            "WiFi scan and trusted-network baseline."
        ),
    }


def archive_legacy_trusted_baseline() -> tuple[dict, int]:
    """Archive legacy Trusted Baseline reports without deleting evidence."""

    status = get_trusted_baseline_report_status()

    if status["status"] != "legacy":
        return {
            "ok": False,
            "state": "archive_not_required",
            "message": (
                "Legacy Trusted Baseline archive is not "
                "required for status "
                + str(status["status"])
                + "."
            ),
            "baseline_status": status["status"],
        }, 409

    source_files = [
        TRUSTED_BASELINE_REPORT_CSV,
        TRUSTED_BASELINE_REPORT_JSON,
    ]

    existing_files = [
        source
        for source in source_files
        if source.exists()
    ]

    if len(existing_files) != len(source_files):
        return {
            "ok": False,
            "state": "legacy_files_incomplete",
            "message": (
                "Legacy Trusted Baseline reports are incomplete "
                "and cannot be archived as one verified pair."
            ),
        }, 409

    archive_stamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    archive_directory = (
        LEGACY_TRUSTED_BASELINE_DIRECTORY
        / archive_stamp
    )

    moved_files: list[tuple[Path, Path]] = []

    try:
        archive_directory.mkdir(
            parents=True,
            exist_ok=False,
        )

        for source in existing_files:
            destination = (
                archive_directory
                / source.name
            )

            source.replace(destination)

            moved_files.append(
                (
                    source,
                    destination,
                )
            )

    except OSError as exc:
        for source, destination in reversed(
            moved_files
        ):
            if destination.exists():
                try:
                    destination.replace(source)
                except OSError:
                    pass

        try:
            archive_directory.rmdir()
        except OSError:
            pass

        return {
            "ok": False,
            "state": "archive_failed",
            "message": (
                "Legacy Trusted Baseline reports could "
                "not be archived: "
                + str(exc)
            ),
        }, 500

    try:
        archive_display = str(
            archive_directory.relative_to(
                PROJECT_ROOT
            )
        )
    except ValueError:
        archive_display = str(
            archive_directory
        )

    return {
        "ok": True,
        "state": "archived",
        "message": (
            "Legacy Trusted Baseline reports were "
            "archived successfully."
        ),
        "archive_directory": archive_display,
        "archived_files": [
            destination.name
            for _, destination in moved_files
        ],
        "after_status":
            get_trusted_baseline_report_status()[
                "status"
            ],
    }, 200


def run_trusted_baseline_generation() -> tuple[dict, int]:
    """Safely generate Trusted Baseline reports from current sources."""

    status = get_trusted_baseline_report_status()

    if status["status"] == "legacy":
        return {
            "ok": False,
            "state": "legacy_baseline_detected",
            "message": (
                "Legacy Trusted Baseline reports must be "
                "archived before generating the current "
                "provenance-aware reports."
            ),
            "baseline_status": "legacy",
            "migration_required": True,
            "archive_legacy_url":
                "/api/trusted-baseline/archive-legacy",
        }, 409

    if status["status"] in {
        "incomplete",
        "unavailable",
    }:
        return {
            "ok": False,
            "state": "baseline_outputs_unavailable",
            "message": status["message"],
            "baseline_status": status["status"],
        }, 409

    scan_fingerprint = _calculate_file_sha256(
        NETWORK_CSV
    )

    trusted_fingerprint = _calculate_file_sha256(
        TRUSTED_NETWORKS_CSV
    )

    if (
        scan_fingerprint is None
        or trusted_fingerprint is None
    ):
        return {
            "ok": False,
            "state": "source_unavailable",
            "message": (
                "Current WiFi scan or trusted-network "
                "baseline is missing or unreadable."
            ),
        }, 409

    if status["status"] == "current":
        return {
            "ok": True,
            "state": "already_current",
            "message": (
                "Trusted Baseline reports already match "
                "the current WiFi scan and trusted baseline."
            ),
            "baseline_status": "current",
        }, 200

    try:
        scan_mtime = NETWORK_CSV.stat().st_mtime_ns
        trusted_mtime = (
            TRUSTED_NETWORKS_CSV.stat().st_mtime_ns
        )
    except OSError as exc:
        return {
            "ok": False,
            "state": "source_unavailable",
            "message": str(exc),
        }, 500

    REPORTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="netshield-baseline-",
            dir=REPORTS_DIRECTORY,
        ) as temp_directory:
            temp_directory = Path(
                temp_directory
            )

            temporary_csv = (
                temp_directory
                / TRUSTED_BASELINE_REPORT_CSV.name
            )

            temporary_json = (
                temp_directory
                / TRUSTED_BASELINE_REPORT_JSON.name
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(
                        PROJECT_ROOT
                        / "trusted_baseline"
                        / "trusted_baseline_checker.py"
                    ),
                    "--scan-csv",
                    str(NETWORK_CSV),
                    "--trusted-csv",
                    str(TRUSTED_NETWORKS_CSV),
                    "--output-csv",
                    str(temporary_csv),
                    "--output-json",
                    str(temporary_json),
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return {
                    "ok": False,
                    "state": "baseline_generation_failed",
                    "message": (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or (
                            "Trusted Baseline generation "
                            "failed."
                        )
                    ),
                }, 500

            if (
                not temporary_csv.exists()
                or not temporary_json.exists()
            ):
                return {
                    "ok": False,
                    "state": "baseline_output_missing",
                    "message": (
                        "Trusted Baseline generation did not "
                        "produce both report files."
                    ),
                }, 500

            try:
                payload = json.loads(
                    temporary_json.read_text(
                        encoding="utf-8"
                    )
                )
            except (
                OSError,
                json.JSONDecodeError,
            ) as exc:
                return {
                    "ok": False,
                    "state": "baseline_validation_failed",
                    "message": (
                        "Generated Trusted Baseline JSON "
                        "is invalid: "
                        + str(exc)
                    ),
                }, 500

            if (
                payload.get("analysis_version")
                    != CURRENT_TRUSTED_BASELINE_VERSION
                or payload.get(
                    "source_scan_sha256"
                ) != scan_fingerprint
                or payload.get(
                    "source_trusted_baseline_sha256"
                ) != trusted_fingerprint
                or not isinstance(
                    payload.get("summary"),
                    dict,
                )
                or not isinstance(
                    payload.get("findings"),
                    list,
                )
            ):
                return {
                    "ok": False,
                    "state": "baseline_validation_failed",
                    "message": (
                        "Generated Trusted Baseline reports "
                        "failed version, fingerprint, or "
                        "structure validation."
                    ),
                }, 500

            current_scan_fingerprint = (
                _calculate_file_sha256(
                    NETWORK_CSV
                )
            )

            current_trusted_fingerprint = (
                _calculate_file_sha256(
                    TRUSTED_NETWORKS_CSV
                )
            )

            try:
                current_scan_mtime = (
                    NETWORK_CSV.stat().st_mtime_ns
                )
                current_trusted_mtime = (
                    TRUSTED_NETWORKS_CSV.stat().st_mtime_ns
                )
            except OSError as exc:
                return {
                    "ok": False,
                    "state": "source_changed",
                    "message": (
                        "Trusted Baseline source became "
                        "unavailable during generation: "
                        + str(exc)
                    ),
                }, 409

            if (
                current_scan_mtime != scan_mtime
                or current_trusted_mtime
                    != trusted_mtime
                or current_scan_fingerprint
                    != scan_fingerprint
                or current_trusted_fingerprint
                    != trusted_fingerprint
            ):
                return {
                    "ok": False,
                    "state": "source_changed",
                    "message": (
                        "WiFi scan or trusted baseline changed "
                        "during report generation. Run again."
                    ),
                }, 409

            targets = [
                (
                    temporary_csv,
                    TRUSTED_BASELINE_REPORT_CSV,
                ),
                (
                    temporary_json,
                    TRUSTED_BASELINE_REPORT_JSON,
                ),
            ]

            backups = []

            try:
                for _, destination in targets:
                    if destination.exists():
                        backup = (
                            temp_directory
                            / (
                                destination.name
                                + ".backup"
                            )
                        )

                        shutil.copy2(
                            destination,
                            backup,
                        )

                        backups.append(
                            (
                                destination,
                                backup,
                            )
                        )

                replaced = []

                for source, destination in targets:
                    source.replace(destination)
                    replaced.append(destination)

            except OSError as exc:
                for destination in replaced:
                    try:
                        destination.unlink(
                            missing_ok=True
                        )
                    except OSError:
                        pass

                for destination, backup in backups:
                    if backup.exists():
                        shutil.copy2(
                            backup,
                            destination,
                        )

                return {
                    "ok": False,
                    "state": "baseline_save_failed",
                    "message": (
                        "Trusted Baseline reports could not "
                        "be saved atomically: "
                        + str(exc)
                    ),
                }, 500

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "state": "baseline_timeout",
            "message": (
                "Trusted Baseline generation timed out."
            ),
        }, 500

    except OSError as exc:
        return {
            "ok": False,
            "state": "baseline_error",
            "message": str(exc),
        }, 500

    final_status = (
        get_trusted_baseline_report_status()
    )

    return {
        "ok": True,
        "state": "completed",
        "message": (
            "Trusted Baseline reports generated successfully."
        ),
        "baseline_status":
            final_status["status"],
        "network_count":
            payload["summary"].get(
                "total_networks",
                len(payload["findings"]),
            ),
        "summary": payload["summary"],
        "reports": [
            TRUSTED_BASELINE_REPORT_CSV.name,
            TRUSTED_BASELINE_REPORT_JSON.name,
        ],
    }, 200


def get_pre_connect_safety_status() -> dict:
    """Check whether Pre-Connect Safety reports match the current baseline."""

    report_files = [
        PRE_CONNECT_REPORT_CSV,
        PRE_CONNECT_REPORT_JSON,
    ]

    existing_files = [
        report
        for report in report_files
        if report.exists()
    ]

    if not existing_files:
        baseline_status = (
            get_trusted_baseline_report_status()
        )

        return {
            "status": "missing",
            "generation_required": True,
            "trusted_baseline_required": (
                baseline_status["status"]
                != "current"
            ),
            "analysis_version": None,
            "current_version":
                CURRENT_PRE_CONNECT_VERSION,
            "migration_required": False,
            "message": (
                "No current Pre-Connect Safety report "
                "exists yet."
            ),
        }

    if len(existing_files) != len(report_files):
        return {
            "status": "incomplete",
            "generation_required": True,
            "trusted_baseline_required": False,
            "analysis_version": None,
            "current_version":
                CURRENT_PRE_CONNECT_VERSION,
            "migration_required": True,
            "message": (
                "Pre-Connect Safety report files are "
                "incomplete and cannot be treated as current."
            ),
        }

    try:
        payload = json.loads(
            PRE_CONNECT_REPORT_JSON.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        return {
            "status": "unavailable",
            "generation_required": True,
            "trusted_baseline_required": False,
            "analysis_version": None,
            "current_version":
                CURRENT_PRE_CONNECT_VERSION,
            "migration_required": True,
            "message": (
                "Pre-Connect Safety JSON could not be "
                "validated: "
                + str(exc)
            ),
        }

    stored_version = str(
        payload.get(
            "analysis_version",
            "",
        )
    ).strip()

    stored_source_fingerprint = str(
        payload.get(
            "source_trusted_baseline_report_sha256",
            "",
        )
    ).strip()

    if (
        stored_version
            != CURRENT_PRE_CONNECT_VERSION
        or not stored_source_fingerprint
    ):
        return {
            "status": "legacy",
            "generation_required": True,
            "trusted_baseline_required": False,
            "analysis_version": (
                stored_version
                or "legacy-pre-provenance"
            ),
            "current_version":
                CURRENT_PRE_CONNECT_VERSION,
            "migration_required": True,
            "message": (
                "Saved Pre-Connect Safety reports were "
                "created before the current provenance-aware "
                "format and are not treated as current."
            ),
        }

    baseline_status = (
        get_trusted_baseline_report_status()
    )

    if baseline_status["status"] != "current":
        return {
            "status": "stale",
            "generation_required": True,
            "trusted_baseline_required": True,
            "analysis_version": stored_version,
            "current_version":
                CURRENT_PRE_CONNECT_VERSION,
            "migration_required": False,
            "stale_sources": [
                "Trusted Baseline report"
            ],
            "message": (
                "Pre-Connect Safety cannot be treated as "
                "current because the Trusted Baseline report "
                "must be updated first."
            ),
        }

    current_source_fingerprint = (
        _calculate_file_sha256(
            TRUSTED_BASELINE_REPORT_CSV
        )
    )

    if current_source_fingerprint is None:
        return {
            "status": "unavailable",
            "generation_required": True,
            "trusted_baseline_required": True,
            "analysis_version": stored_version,
            "current_version":
                CURRENT_PRE_CONNECT_VERSION,
            "migration_required": False,
            "message": (
                "Current Trusted Baseline CSV could not "
                "be fingerprinted."
            ),
        }

    if (
        stored_source_fingerprint
        != current_source_fingerprint
    ):
        return {
            "status": "stale",
            "generation_required": True,
            "trusted_baseline_required": False,
            "analysis_version": stored_version,
            "current_version":
                CURRENT_PRE_CONNECT_VERSION,
            "migration_required": False,
            "stale_sources": [
                "Trusted Baseline report"
            ],
            "message": (
                "Saved Pre-Connect Safety reports do not "
                "match the current Trusted Baseline report. "
                "Generate them again."
            ),
        }

    return {
        "status": "current",
        "generation_required": False,
        "trusted_baseline_required": False,
        "analysis_version": stored_version,
        "current_version":
            CURRENT_PRE_CONNECT_VERSION,
        "migration_required": False,
        "stale_sources": [],
        "message": (
            "Pre-Connect Safety reports match the current "
            "Trusted Baseline report."
        ),
    }


def get_security_advisor_status() -> dict:
    """Check whether saved Security Advisor reports are current."""

    advisor_files = [
        SECURITY_ADVISOR_TEXT,
        SECURITY_ADVISOR_JSON,
    ]

    existing_files = [
        path
        for path in advisor_files
        if path.exists()
    ]

    if not existing_files:
        return {
            "status": "missing",
            "generation_required": True,
            "threat_analysis_required": (
                get_threat_report_status()[
                    "analysis_required"
                ]
            ),
            "message": (
                "No Security Advisor report exists yet. "
                "Generate Security Advisor after completing "
                "current Threat Analysis."
            ),
        }

    if len(existing_files) != len(advisor_files):
        return {
            "status": "incomplete",
            "generation_required": True,
            "threat_analysis_required": (
                get_threat_report_status()[
                    "analysis_required"
                ]
            ),
            "message": (
                "Security Advisor report files are incomplete. "
                "Generate Security Advisor again."
            ),
        }

    threat_status = get_threat_report_status()

    if threat_status["status"] != "current":
        return {
            "status": "stale",
            "generation_required": True,
            "threat_analysis_required": True,
            "message": (
                "Saved Security Advisor reports cannot be "
                "treated as current because the Threat Analysis "
                "report is not current. "
                + threat_status["message"]
            ),
        }

    try:
        source_mtime = (
            SECURITY_REPORT_CSV.stat().st_mtime_ns
        )

        advisor_mtimes = [
            advisor_path.stat().st_mtime_ns
            for advisor_path in advisor_files
        ]

    except OSError as exc:
        return {
            "status": "unavailable",
            "generation_required": True,
            "threat_analysis_required": False,
            "message": (
                "Security Advisor freshness could not be "
                "verified: "
                + str(exc)
            ),
        }

    if any(
        advisor_mtime < source_mtime
        for advisor_mtime in advisor_mtimes
    ):
        return {
            "status": "stale",
            "generation_required": True,
            "threat_analysis_required": False,
            "message": (
                "Saved Security Advisor reports are older than "
                "the current Threat Analysis report. "
                "Generate Security Advisor again."
            ),
        }

    return {
        "status": "current",
        "generation_required": False,
        "threat_analysis_required": False,
        "message": (
            "Security Advisor reports are current."
        ),
    }


def get_alert_notification_status() -> dict:
    """Check compatibility and freshness of saved Module 9 outputs."""

    alert_files = [
        ALERT_NOTIFICATION_LOG,
        ALERT_NOTIFICATION_JSON,
    ]

    existing_files = [
        alert_path
        for alert_path in alert_files
        if alert_path.exists()
    ]

    threat_status = get_threat_report_status()

    if not existing_files:
        return {
            "status": "missing",
            "generation_required": True,
            "threat_analysis_required": (
                threat_status["analysis_required"]
            ),
            "analysis_version": None,
            "current_version":
                CURRENT_ALERT_NOTIFICATION_VERSION,
            "migration_required": False,
            "message": (
                "No current Alert Notification reports exist yet. "
                "Generate alerts after completing current "
                "Threat Analysis."
            ),
        }

    if len(existing_files) != len(alert_files):
        return {
            "status": "incomplete",
            "generation_required": True,
            "threat_analysis_required": (
                threat_status["analysis_required"]
            ),
            "analysis_version": None,
            "current_version":
                CURRENT_ALERT_NOTIFICATION_VERSION,
            "migration_required": True,
            "message": (
                "Alert Notification output files are incomplete. "
                "They are not treated as current Module 9 results."
            ),
        }

    try:
        payload = json.loads(
            ALERT_NOTIFICATION_JSON.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        return {
            "status": "unavailable",
            "generation_required": True,
            "threat_analysis_required": (
                threat_status["analysis_required"]
            ),
            "analysis_version": None,
            "current_version":
                CURRENT_ALERT_NOTIFICATION_VERSION,
            "migration_required": True,
            "message": (
                "Alert Notification JSON could not be "
                "validated: "
                + str(exc)
            ),
        }

    stored_version = str(
        payload.get(
            "analysis_version",
            "",
        )
    ).strip()

    stored_fingerprint = str(
        payload.get(
            "source_report_sha256",
            "",
        )
    ).strip()

    if (
        stored_version
        != CURRENT_ALERT_NOTIFICATION_VERSION
        or not stored_fingerprint
    ):
        return {
            "status": "legacy",
            "generation_required": True,
            "threat_analysis_required": (
                threat_status["analysis_required"]
            ),
            "analysis_version": (
                stored_version
                or "legacy-pre-baseline"
            ),
            "current_version":
                CURRENT_ALERT_NOTIFICATION_VERSION,
            "migration_required": True,
            "archive_legacy_url":
                "/api/alerts/archive-legacy",
            "message": (
                "Saved Alert Notification files were created "
                "before the current baseline-aware threat logic "
                "and are not treated as current Module 9 alerts."
            ),
        }

    if threat_status["status"] != "current":
        return {
            "status": "stale",
            "generation_required": True,
            "threat_analysis_required": True,
            "analysis_version": stored_version,
            "current_version":
                CURRENT_ALERT_NOTIFICATION_VERSION,
            "migration_required": False,
            "message": (
                "Saved Alert Notifications cannot be treated "
                "as current because Threat Analysis is not "
                "current. "
                + threat_status["message"]
            ),
        }

    source_fingerprint = _calculate_file_sha256(
        SECURITY_REPORT_CSV
    )

    if source_fingerprint is None:
        return {
            "status": "unavailable",
            "generation_required": True,
            "threat_analysis_required": False,
            "analysis_version": stored_version,
            "current_version":
                CURRENT_ALERT_NOTIFICATION_VERSION,
            "migration_required": False,
            "message": (
                "Current Threat Analysis could not be "
                "fingerprinted for Alert Notification "
                "freshness verification."
            ),
        }

    if stored_fingerprint != source_fingerprint:
        return {
            "status": "stale",
            "generation_required": True,
            "threat_analysis_required": False,
            "analysis_version": stored_version,
            "current_version":
                CURRENT_ALERT_NOTIFICATION_VERSION,
            "migration_required": False,
            "message": (
                "Saved Alert Notifications belong to an older "
                "Threat Analysis report. Generate Module 9 "
                "again for the current findings."
            ),
        }

    return {
        "status": "current",
        "generation_required": False,
        "threat_analysis_required": False,
        "analysis_version": stored_version,
        "current_version":
            CURRENT_ALERT_NOTIFICATION_VERSION,
        "migration_required": False,
        "message": (
            "Alert Notification reports match the current "
            "Threat Analysis."
        ),
    }


def archive_legacy_alert_notifications() -> tuple[dict, int]:
    """Archive legacy Module 9 outputs without deleting evidence."""

    alert_status = get_alert_notification_status()

    if alert_status["status"] != "legacy":
        return {
            "ok": False,
            "state": "archive_not_required",
            "message": (
                "Legacy Alert Notification archive is not "
                "required for status "
                + str(alert_status["status"])
                + "."
            ),
            "alert_status": alert_status["status"],
        }, 409

    source_files = [
        ALERT_NOTIFICATION_LOG,
        ALERT_NOTIFICATION_JSON,
    ]

    existing_files = [
        source
        for source in source_files
        if source.exists()
    ]

    if len(existing_files) != len(source_files):
        return {
            "ok": False,
            "state": "legacy_files_incomplete",
            "message": (
                "Legacy Alert Notification files are "
                "incomplete and cannot be archived as "
                "one verified pair."
            ),
        }, 409

    archive_stamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    archive_directory = (
        LEGACY_ALERT_NOTIFICATION_DIRECTORY
        / archive_stamp
    )

    moved_files: list[tuple[Path, Path]] = []

    try:
        archive_directory.mkdir(
            parents=True,
            exist_ok=False,
        )

        for source in existing_files:
            destination = (
                archive_directory
                / source.name
            )

            source.replace(destination)

            moved_files.append(
                (
                    source,
                    destination,
                )
            )

    except OSError as exc:
        for source, destination in reversed(
            moved_files
        ):
            if destination.exists():
                try:
                    destination.replace(source)
                except OSError:
                    pass

        try:
            archive_directory.rmdir()
        except OSError:
            pass

        return {
            "ok": False,
            "state": "archive_failed",
            "message": (
                "Legacy Alert Notification files could "
                "not be archived: "
                + str(exc)
            ),
        }, 500

    try:
        archive_display = str(
            archive_directory.relative_to(
                PROJECT_ROOT
            )
        )
    except ValueError:
        archive_display = str(
            archive_directory
        )

    return {
        "ok": True,
        "state": "archived",
        "message": (
            "Legacy Alert Notification files were "
            "archived successfully. NetShield can now "
            "generate baseline-aware Module 9 alerts."
        ),
        "archive_directory": archive_display,
        "archived_files": [
            destination.name
            for _, destination in moved_files
        ],
        "after_status":
            get_alert_notification_status()["status"],
    }, 200


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
    advisor_status = get_security_advisor_status()
    alert_status = get_alert_notification_status()
    trusted_baseline_status = (
        get_trusted_baseline_report_status()
    )
    pre_connect_status = (
        get_pre_connect_safety_status()
    )

    advisor_filenames = {
        SECURITY_ADVISOR_TEXT.name,
        SECURITY_ADVISOR_JSON.name,
    }

    alert_filenames = {
        ALERT_NOTIFICATION_LOG.name,
        ALERT_NOTIFICATION_JSON.name,
    }

    trusted_baseline_filenames = {
        TRUSTED_BASELINE_REPORT_CSV.name,
        TRUSTED_BASELINE_REPORT_JSON.name,
    }

    pre_connect_filenames = {
        PRE_CONNECT_REPORT_CSV.name,
        PRE_CONNECT_REPORT_JSON.name,
    }

    for report_path in REPORTS_DIRECTORY.iterdir():
        if not report_path.is_file():
            continue

        extension = report_path.suffix.lower()
        if extension not in ALLOWED_REPORT_EXTENSIONS:
            continue

        stat = report_path.stat()

        report_row = {
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

        if report_path.name in advisor_filenames:
            report_row.update(
                {
                    "freshness_status": advisor_status[
                        "status"
                    ],
                    "generation_required": advisor_status[
                        "generation_required"
                    ],
                    "threat_analysis_required": (
                        advisor_status[
                            "threat_analysis_required"
                        ]
                    ),
                    "freshness_message": advisor_status[
                        "message"
                    ],
                }
            )

        if report_path.name in alert_filenames:
            report_row.update(
                {
                    "freshness_status": alert_status[
                        "status"
                    ],
                    "generation_required": alert_status[
                        "generation_required"
                    ],
                    "threat_analysis_required": (
                        alert_status[
                            "threat_analysis_required"
                        ]
                    ),
                    "freshness_message": alert_status[
                        "message"
                    ],
                }
            )

        if (
            report_path.name
            in trusted_baseline_filenames
        ):
            report_row.update(
                {
                    "freshness_status":
                        trusted_baseline_status[
                            "status"
                        ],
                    "generation_required":
                        trusted_baseline_status[
                            "generation_required"
                        ],
                    "freshness_message":
                        trusted_baseline_status[
                            "message"
                        ],
                }
            )

        if (
            report_path.name
            in pre_connect_filenames
        ):
            report_row.update(
                {
                    "freshness_status":
                        pre_connect_status[
                            "status"
                        ],
                    "generation_required":
                        pre_connect_status[
                            "generation_required"
                        ],
                    "freshness_message":
                        pre_connect_status[
                            "message"
                        ],
                }
            )

        report_rows.append(report_row)

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


def get_history_storage_status() -> dict:
    """Inspect history compatibility without modifying the database."""

    current_version = "baseline-aware-v2"

    if not HISTORY_DB.exists():
        return {
            "status": "missing",
            "analysis_version": None,
            "current_version": current_version,
            "migration_required": False,
            "message": (
                "No current historical database exists yet. "
                "Generate Historical Trends after completing "
                "current Threat Analysis."
            ),
        }

    try:
        with sqlite3.connect(HISTORY_DB) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    """
                ).fetchall()
            }

            if "scan_history" not in tables:
                return {
                    "status": "unavailable",
                    "analysis_version": None,
                    "current_version": current_version,
                    "migration_required": True,
                    "message": (
                        "History database does not contain the "
                        "expected scan_history table."
                    ),
                }

            history_count = connection.execute(
                "SELECT COUNT(*) FROM scan_history"
            ).fetchone()[0]

            if "history_metadata" not in tables:
                if history_count > 0:
                    return {
                        "status": "legacy",
                        "analysis_version":
                            "legacy-pre-baseline",
                        "current_version": current_version,
                        "migration_required": True,
                        "message": (
                            "Saved history was created by the older "
                            "threat-detection logic and is not mixed "
                            "with current baseline-aware history."
                        ),
                    }

                return {
                    "status": "empty",
                    "analysis_version": None,
                    "current_version": current_version,
                    "migration_required": False,
                    "message": (
                        "History database is empty and has not yet "
                        "stored a baseline-aware analysis."
                    ),
                }

            version_row = connection.execute(
                """
                SELECT value
                FROM history_metadata
                WHERE key = 'analysis_version'
                """
            ).fetchone()

            stored_version = (
                str(version_row[0]).strip()
                if version_row
                else None
            )

            if stored_version != current_version:
                return {
                    "status": "legacy",
                    "analysis_version": (
                        stored_version
                        or "legacy-pre-baseline"
                    ),
                    "current_version": current_version,
                    "migration_required": True,
                    "message": (
                        "Saved history uses an older analysis "
                        "version and is not shown as current "
                        "NetShield history."
                    ),
                }

            return {
                "status": "current",
                "analysis_version": stored_version,
                "current_version": current_version,
                "migration_required": False,
                "message": (
                    "Historical data uses the current "
                    "baseline-aware analysis version."
                ),
            }

    except sqlite3.Error as database_error:
        return {
            "status": "unavailable",
            "analysis_version": None,
            "current_version": current_version,
            "migration_required": True,
            "message": (
                "History database could not be inspected: "
                + str(database_error)
            ),
        }


def archive_legacy_history() -> tuple[dict, int]:
    """Archive legacy history without deleting historical evidence."""

    storage_status = get_history_storage_status()

    if storage_status["status"] != "legacy":
        return {
            "ok": False,
            "state": "archive_not_required",
            "message": (
                "Legacy history archive is not required for "
                f"history status {storage_status['status']}."
            ),
            "history_status": storage_status["status"],
        }, 409

    source_files = [
        HISTORY_DB,
        HISTORICAL_TREND_TEXT,
        HISTORICAL_TREND_JSON,
    ]

    existing_files = [
        source
        for source in source_files
        if source.exists()
    ]

    if not existing_files:
        return {
            "ok": False,
            "state": "legacy_files_missing",
            "message": (
                "Legacy history was detected but no archiveable "
                "history files were found."
            ),
        }, 409

    archive_stamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    archive_directory = (
        LEGACY_HISTORY_DIRECTORY
        / archive_stamp
    )

    moved_files: list[tuple[Path, Path]] = []

    try:
        archive_directory.mkdir(
            parents=True,
            exist_ok=False,
        )

        for source in existing_files:
            destination = (
                archive_directory
                / source.name
            )

            source.replace(destination)

            moved_files.append(
                (
                    source,
                    destination,
                )
            )

    except OSError as exc:
        # Restore anything already moved so an incomplete
        # archive operation does not lose the active files.
        for source, destination in reversed(
            moved_files
        ):
            if destination.exists():
                destination.replace(source)

        try:
            archive_directory.rmdir()
        except OSError:
            pass

        return {
            "ok": False,
            "state": "archive_failed",
            "message": (
                "Legacy history could not be archived: "
                + str(exc)
            ),
        }, 500

    try:
        archive_display_path = str(
            archive_directory.relative_to(
                PROJECT_ROOT
            )
        )
    except ValueError:
        archive_display_path = str(
            archive_directory
        )

    return {
        "ok": True,
        "state": "archived",
        "message": (
            "Legacy history was archived successfully. "
            "NetShield can now begin a clean baseline-aware "
            "history timeline."
        ),
        "archive_directory": archive_display_path,
        "archived_files": [
            destination.name
            for _, destination in moved_files
        ],
    }, 200


def read_history() -> dict:
    """Read only current-version historical analysis data."""

    storage_status = get_history_storage_status()
    threat_status = get_threat_report_status()

    generation_allowed = (
        storage_status["status"] in {
            "missing",
            "empty",
            "current",
        }
        and threat_status["status"] == "current"
    )

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
        "history_status": storage_status["status"],
        "analysis_version": storage_status[
            "analysis_version"
        ],
        "current_version": storage_status[
            "current_version"
        ],
        "migration_required": storage_status[
            "migration_required"
        ],
        "message": storage_status["message"],
        "archive_legacy_url": (
            "/api/history/archive-legacy"
            if storage_status["status"] == "legacy"
            else None
        ),
        "generate_url": "/api/history/generate",
        "generation_allowed": generation_allowed,
        "threat_report_status": threat_status["status"],
        "threat_analysis_required": threat_status[
            "analysis_required"
        ],
        "threat_report_message": threat_status["message"],
    }

    if storage_status["status"] != "current":
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
                    suspicious_count,
                    weak_encryption_count,
                    unknown_network_count,
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
                WHERE UPPER(
                    COALESCE(
                        attack_type,
                        'NORMAL'
                    )
                ) <> 'NORMAL'
                ORDER BY
                    scan_timestamp DESC,
                    scan_id DESC
                LIMIT 12
                """
            ).fetchall()

    except sqlite3.Error as database_error:
        result = dict(empty_result)

        result.update(
            {
                "history_status": "unavailable",
                "migration_required": True,
                "message": (
                    "Unable to read current history database: "
                    + str(database_error)
                ),
            }
        )

        return result

    summaries = []

    for row in summary_rows:
        summary = dict(row)

        summary["potential_findings"] = sum(
            int(
                summary.get(column)
                or 0
            )
            for column in (
                "rogue_count",
                "evil_twin_count",
                "suspicious_count",
                "weak_encryption_count",
                "unknown_network_count",
            )
        )

        summaries.append(summary)

    findings = [
        dict(row)
        for row in finding_rows
    ]

    latest = (
        summaries[0]
        if summaries
        else None
    )

    previous = (
        summaries[1]
        if len(summaries) > 1
        else None
    )

    trends = {
        "network_change": None,
        "score_change": None,
        "finding_change": None,
    }

    if latest and previous:
        trends = {
            "network_change": (
                int(
                    latest[
                        "total_networks"
                    ]
                    or 0
                )
                - int(
                    previous[
                        "total_networks"
                    ]
                    or 0
                )
            ),
            "score_change": round(
                float(
                    latest[
                        "average_security_score"
                    ]
                    or 0
                )
                - float(
                    previous[
                        "average_security_score"
                    ]
                    or 0
                ),
                1,
            ),
            "finding_change": (
                int(
                    latest[
                        "potential_findings"
                    ]
                    or 0
                )
                - int(
                    previous[
                        "potential_findings"
                    ]
                    or 0
                )
            ),
        }

    return {
        "scan_count": len(summaries),
        "latest": latest,
        "previous": previous,
        "summaries": summaries,
        "recent_findings": findings,
        "trends": trends,
        "history_status": "current",
        "analysis_version": storage_status[
            "analysis_version"
        ],
        "current_version": storage_status[
            "current_version"
        ],
        "migration_required": False,
        "message": storage_status["message"],
        "archive_legacy_url": None,
        "generate_url": "/api/history/generate",
        "generation_allowed": generation_allowed,
        "threat_report_status": threat_status["status"],
        "threat_analysis_required": threat_status[
            "analysis_required"
        ],
        "threat_report_message": threat_status["message"],
    }

def _read_interface_capabilities(interface: str) -> dict:
    """Read supported WiFi bands and enabled channels for an interface."""
    capabilities = {
        "phy": None,
        "bands": [],
        "enabled_channels": [],
        "disabled_channels": [],
        "supports_2_4_ghz": False,
        "supports_5_ghz": False,
    }

    try:
        interface_result = subprocess.run(
            ["iw", "dev", interface, "info"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return capabilities

    if interface_result.returncode != 0:
        return capabilities

    phy_name = None

    for raw_line in interface_result.stdout.splitlines():
        line = raw_line.strip()

        if line.startswith("wiphy "):
            phy_number = line.split(" ", 1)[1].strip()
            phy_name = f"phy{phy_number}"
            break

    if not phy_name:
        return capabilities

    capabilities["phy"] = phy_name

    try:
        phy_result = subprocess.run(
            ["iw", "phy", phy_name, "info"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return capabilities

    if phy_result.returncode != 0:
        return capabilities

    bands = set()
    enabled_channels = []
    disabled_channels = []

    for raw_line in phy_result.stdout.splitlines():
        line = raw_line.strip()

        if "MHz [" not in line:
            continue

        try:
            frequency_text = (
                line.split("MHz", 1)[0]
                .replace("*", "")
                .strip()
            )

            frequency = float(frequency_text)

            channel = int(
                line.split("[", 1)[1]
                .split("]", 1)[0]
                .strip()
            )
        except (IndexError, ValueError):
            continue

        if 2300 <= frequency < 3000:
            band = "2.4 GHz"
        elif 4900 <= frequency < 5925:
            band = "5 GHz"
        elif 5925 <= frequency <= 7125:
            band = "6 GHz"
        else:
            band = "Other"

        bands.add(band)

        if "(disabled)" in line.lower():
            if channel not in disabled_channels:
                disabled_channels.append(channel)
        else:
            if channel not in enabled_channels:
                enabled_channels.append(channel)

    capabilities["bands"] = sorted(bands)
    capabilities["enabled_channels"] = enabled_channels
    capabilities["disabled_channels"] = disabled_channels
    capabilities["supports_2_4_ghz"] = "2.4 GHz" in bands
    capabilities["supports_5_ghz"] = "5 GHz" in bands

    return capabilities


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
                "channel": None,
            }

        elif line.startswith("type ") and current_interface:
            current_interface["mode"] = line.split(" ", 1)[1].strip()

        elif line.startswith("channel ") and current_interface:
            try:
                current_interface["channel"] = int(
                    line.split()[1]
                )
            except (IndexError, ValueError):
                current_interface["channel"] = None

    if current_interface:
        interfaces.append(current_interface)

    for interface in interfaces:
        interface["capabilities"] = _read_interface_capabilities(
            interface["name"]
        )

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


def read_scanner_progress() -> dict:
    """Read runtime WiFi scanner sweep progress."""
    empty_progress = {
        "state": "idle",
        "interface": None,
        "sweep_number": 0,
        "current_channel": None,
        "channels_completed": 0,
        "total_channels": 0,
        "enabled_channels": [],
        "session_network_count": 0,
        "last_sweep_completed_at": None,
        "updated_at": None,
    }

    if not SCANNER_STATUS_JSON.exists():
        return empty_progress

    try:
        payload = json.loads(
            SCANNER_STATUS_JSON.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        return empty_progress

    if not isinstance(payload, dict):
        return empty_progress

    return {
        **empty_progress,
        **payload,
    }


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

    progress = read_scanner_progress()

    if not running:
        progress["state"] = "idle"
        progress["current_channel"] = None

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

    adapter = read_adapter_status()

    if adapter.get("available"):
        adapter["state"] = {
            "starting": "starting",
            "running": "scanning",
            "stopping": "stopping",
            "idle": "idle",
            "error": "error",
        }.get(scanner_state, adapter.get("state"))

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
        "adapter": adapter,
        "progress": progress,
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


def read_capture_progress() -> dict:
    """Read live packet-capture runtime progress."""
    empty_progress = {
        "state": "idle",
        "interface": None,
        "last_error": "",
        "packet_count": 0,
        "session_start_row": 0,
        "packet_rate": 0.0,
        "elapsed_seconds": 0.0,
        "packet_type_counts": {},
        "started_at": None,
        "last_packet_at": None,
        "current_channel": None,
        "channel_index": 0,
        "total_channels": 0,
        "enabled_channels": [],
        "sweep_number": 0,
        "updated_at": None,
    }

    if not CAPTURE_STATUS_JSON.exists():
        return empty_progress

    try:
        payload = json.loads(
            CAPTURE_STATUS_JSON.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        return empty_progress

    if not isinstance(payload, dict):
        return empty_progress

    return {
        **empty_progress,
        **payload,
    }


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

    progress = read_capture_progress()

    runtime_error = str(
        progress.get("last_error") or ""
    ).strip()

    if (
        capture_state == "idle"
        and progress.get("state") == "error"
        and runtime_error
    ):
        capture_state = "error"

    if not running:
        if capture_state != "error":
            progress["state"] = "idle"

        progress["current_channel"] = None
        progress["channel_index"] = 0
        progress["packet_rate"] = 0.0

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

    adapter = read_adapter_status()

    if adapter.get("available"):
        adapter["state"] = {
            "starting": "starting",
            "running": "capturing",
            "stopping": "stopping",
            "idle": "idle",
            "error": "error",
        }.get(
            capture_state,
            adapter.get("state"),
        )

    return {
        "state": capture_state,
        "running": running,
        "interface": (
            CAPTURE_SERVICE_INTERFACE if running else None
        ),
        "pid": (
            _read_capture_service_pid() if running else None
        ),
        "last_error": (
            str(progress.get("last_error") or "").strip()
            or service_error
        ),
        "message": messages[capture_state],
        "adapter": adapter,
        "packet_log_found": PACKET_LOG_CSV.exists(),
        "progress": progress,
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

    updated_at = None
    age_seconds = None

    if NETWORK_CSV.exists():
        modified_time = datetime.fromtimestamp(
            NETWORK_CSV.stat().st_mtime,
            tz=timezone.utc,
        )

        updated_at = modified_time.isoformat()
        age_seconds = max(
            0,
            round(
                (
                    datetime.now(timezone.utc)
                    - modified_time
                ).total_seconds(),
                1,
            ),
        )

    return jsonify(
        {
            "count": len(network_rows),
            "source": "wifi_scan_results.csv",
            "updated_at": updated_at,
            "age_seconds": age_seconds,
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

    updated_at = None
    age_seconds = None

    if PACKET_LOG_CSV.exists():
        modified_time = datetime.fromtimestamp(
            PACKET_LOG_CSV.stat().st_mtime,
            tz=timezone.utc,
        )

        updated_at = modified_time.isoformat()
        age_seconds = max(
            0,
            round(
                (
                    datetime.now(timezone.utc)
                    - modified_time
                ).total_seconds(),
                1,
            ),
        )

    return jsonify(
        {
            "count": len(packet_rows),
            "source": "wifi_packets.csv",
            "updated_at": updated_at,
            "age_seconds": age_seconds,
            "packets": packet_rows,
        }
    )


def _write_latest_capture_session_csv(
    output_path: Path,
) -> int:
    """Write only the latest capture session to a temporary CSV."""
    progress = read_capture_progress()
    session_start_row = max(
        0,
        _safe_int(
            progress.get("session_start_row"),
            default=0,
        ),
    )

    if not PACKET_LOG_CSV.exists():
        raise FileNotFoundError(
            "Packet log does not exist."
        )

    with PACKET_LOG_CSV.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as source_file:
        reader = csv.DictReader(source_file)

        if not reader.fieldnames:
            raise RuntimeError(
                "Packet log has no CSV headers."
            )

        rows = [
            dict(row)
            for row_index, row in enumerate(reader)
            if row_index >= session_start_row
        ]

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with output_path.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as output_file:
            writer = csv.DictWriter(
                output_file,
                fieldnames=reader.fieldnames,
            )
            writer.writeheader()
            writer.writerows(rows)

    return len(rows)


def run_threat_analysis() -> tuple[dict, int]:
    """Generate a fresh threat report from the latest completed data."""
    scanner_status = read_scanner_status()
    capture_status = read_capture_status()

    if scanner_status.get("running"):
        return {
            "ok": False,
            "state": "scanner_running",
            "message": (
                "Stop WiFi scanning before running threat analysis."
            ),
        }, 409

    if capture_status.get("running"):
        return {
            "ok": False,
            "state": "capture_running",
            "message": (
                "Stop packet capture before running threat analysis."
            ),
        }, 409

    if not NETWORK_CSV.exists():
        return {
            "ok": False,
            "state": "scan_data_missing",
            "message": (
                "No WiFi scan results are available. "
                "Run the WiFi scanner first."
            ),
        }, 409

    if not PACKET_LOG_CSV.exists():
        return {
            "ok": False,
            "state": "packet_data_missing",
            "message": (
                "No packet log is available. "
                "Run packet capture first."
            ),
        }, 409

    REPORTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="netshield-threat-",
            dir=REPORTS_DIRECTORY,
        ) as temp_directory:
            temp_directory = Path(temp_directory)

            session_packet_csv = (
                temp_directory
                / "latest_capture_session.csv"
            )

            temporary_report = (
                temp_directory
                / "final_security_report.csv"
            )

            session_packet_count = (
                _write_latest_capture_session_csv(
                    session_packet_csv
                )
            )

            module_4 = subprocess.run(
                [
                    sys.executable,
                    str(
                        PROJECT_ROOT
                        / "report_generator"
                        / "security_report_generator.py"
                    ),
                    "--scan-csv",
                    str(NETWORK_CSV),
                    "--packet-csv",
                    str(session_packet_csv),
                    "--report-csv",
                    str(temporary_report),
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if module_4.returncode != 0:
                return {
                    "ok": False,
                    "state": "report_generation_failed",
                    "message": (
                        module_4.stderr.strip()
                        or module_4.stdout.strip()
                        or "Security report generation failed."
                    ),
                }, 500

            module_5 = subprocess.run(
                [
                    sys.executable,
                    str(
                        PROJECT_ROOT
                        / "evil_twin_detection"
                        / "evil_twin_detector.py"
                    ),
                    "--scan-csv",
                    str(NETWORK_CSV),
                    "--packet-csv",
                    str(session_packet_csv),
                    "--report-csv",
                    str(temporary_report),
                    "--trusted-csv",
                    str(TRUSTED_NETWORKS_CSV),
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if module_5.returncode != 0:
                return {
                    "ok": False,
                    "state": "attack_classification_failed",
                    "message": (
                        module_5.stderr.strip()
                        or module_5.stdout.strip()
                        or "Attack classification failed."
                    ),
                }, 500

            if not temporary_report.exists():
                return {
                    "ok": False,
                    "state": "report_missing",
                    "message": (
                        "Threat analysis completed without "
                        "producing a report."
                    ),
                }, 500

            with temporary_report.open(
                "r",
                encoding="utf-8",
                newline="",
            ) as report_file:
                reader = csv.DictReader(report_file)
                report_rows = list(reader)
                report_fields = reader.fieldnames or []

            if "Attack_Type" not in report_fields:
                return {
                    "ok": False,
                    "state": "classification_missing",
                    "message": (
                        "Threat analysis did not produce "
                        "Attack_Type classifications."
                    ),
                }, 500

            temporary_report.replace(
                SECURITY_REPORT_CSV
            )

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "state": "analysis_timeout",
            "message": "Threat analysis timed out.",
        }, 500

    except (OSError, RuntimeError) as exc:
        return {
            "ok": False,
            "state": "analysis_error",
            "message": str(exc),
        }, 500

    findings = read_threats()

    return {
        "ok": True,
        "state": "completed",
        "message": "Threat analysis completed successfully.",
        "session_packet_count": session_packet_count,
        "network_count": len(report_rows),
        "finding_count": len(findings),
        "report": "final_security_report.csv",
        "findings": findings,
    }, 200


def _calculate_file_sha256(
    path: Path,
) -> str | None:
    """Return SHA-256 for a file without modifying it."""

    if not path.exists() or not path.is_file():
        return None

    digest = hashlib.sha256()

    try:
        with path.open("rb") as input_file:
            for chunk in iter(
                lambda: input_file.read(
                    1024 * 1024
                ),
                b"",
            ):
                digest.update(chunk)
    except OSError:
        return None

    return digest.hexdigest()


def _read_history_source_fingerprint() -> str | None:
    """Read the last Threat Analysis fingerprint from active history."""

    if not HISTORY_DB.exists():
        return None

    try:
        with sqlite3.connect(HISTORY_DB) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    """
                ).fetchall()
            }

            if "history_metadata" not in tables:
                return None

            row = connection.execute(
                """
                SELECT value
                FROM history_metadata
                WHERE key = 'last_source_sha256'
                """
            ).fetchone()

            if not row:
                return None

            value = str(row[0]).strip()

            return value or None

    except sqlite3.Error:
        return None


def run_historical_trends() -> tuple[dict, int]:
    """Safely store current Threat Analysis in historical trends."""

    threat_status = get_threat_report_status()

    if threat_status["status"] != "current":
        return {
            "ok": False,
            "state": "threat_analysis_required",
            "message": threat_status["message"],
            "report_status": threat_status["status"],
            "analysis_required": True,
            "stale_sources": threat_status[
                "stale_sources"
            ],
        }, 409

    history_status = get_history_storage_status()

    if history_status["status"] == "legacy":
        return {
            "ok": False,
            "state": "legacy_history_detected",
            "message": (
                "Legacy history must be archived before "
                "starting the baseline-aware timeline."
            ),
            "history_status": "legacy",
            "migration_required": True,
            "archive_legacy_url":
                "/api/history/archive-legacy",
        }, 409

    if history_status["status"] == "unavailable":
        return {
            "ok": False,
            "state": "history_unavailable",
            "message": history_status["message"],
            "history_status": "unavailable",
        }, 409

    try:
        source_report_mtime = (
            SECURITY_REPORT_CSV.stat().st_mtime_ns
        )
    except OSError as exc:
        return {
            "ok": False,
            "state": "report_unavailable",
            "message": (
                "Threat report could not be accessed: "
                + str(exc)
            ),
        }, 500

    source_fingerprint = _calculate_file_sha256(
        SECURITY_REPORT_CSV
    )

    if source_fingerprint is None:
        return {
            "ok": False,
            "state": "report_unavailable",
            "message": (
                "Threat report could not be fingerprinted "
                "for historical storage."
            ),
        }, 500

    stored_fingerprint = (
        _read_history_source_fingerprint()
    )

    if (
        stored_fingerprint
        and stored_fingerprint
        == source_fingerprint
    ):
        return {
            "ok": True,
            "state": "already_recorded",
            "message": (
                "This exact Threat Analysis is already "
                "stored in history. No duplicate snapshot "
                "was created."
            ),
            "source_report_sha256":
                source_fingerprint,
            "history": read_history(),
        }, 200

    REPORTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="netshield-history-",
            dir=REPORTS_DIRECTORY,
        ) as temp_directory:
            temp_directory = Path(
                temp_directory
            )

            temporary_database = (
                temp_directory
                / "history.db"
            )

            temporary_text = (
                temp_directory
                / "historical_trend_report.txt"
            )

            temporary_json = (
                temp_directory
                / "historical_trend_report.json"
            )

            if HISTORY_DB.exists():
                shutil.copy2(
                    HISTORY_DB,
                    temporary_database,
                )

            module_8 = subprocess.run(
                [
                    sys.executable,
                    str(
                        PROJECT_ROOT
                        / "historical_trends"
                        / "historical_trend_engine.py"
                    ),
                    "--report-csv",
                    str(SECURITY_REPORT_CSV),
                    "--database",
                    str(temporary_database),
                    "--text-output",
                    str(temporary_text),
                    "--json-output",
                    str(temporary_json),
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if module_8.returncode != 0:
                return {
                    "ok": False,
                    "state": "history_generation_failed",
                    "message": (
                        module_8.stderr.strip()
                        or module_8.stdout.strip()
                        or (
                            "Historical Trend generation "
                            "failed."
                        )
                    ),
                }, 500

            required_outputs = [
                temporary_database,
                temporary_text,
                temporary_json,
            ]

            if not all(
                output.exists()
                for output in required_outputs
            ):
                return {
                    "ok": False,
                    "state": "history_output_missing",
                    "message": (
                        "Historical Trend generation did "
                        "not produce the database and both "
                        "report files."
                    ),
                }, 500

            try:
                report_data = json.loads(
                    temporary_json.read_text(
                        encoding="utf-8"
                    )
                )
            except (
                OSError,
                json.JSONDecodeError,
            ) as exc:
                return {
                    "ok": False,
                    "state": "history_validation_failed",
                    "message": (
                        "Generated Historical Trend JSON "
                        "is invalid: "
                        + str(exc)
                    ),
                }, 500

            required_sections = {
                "current_scan",
                "comparison",
                "statistics",
                "executive_summary",
            }

            if (
                not isinstance(
                    report_data,
                    dict,
                )
                or not required_sections.issubset(
                    report_data
                )
                or report_data.get("state")
                    != "completed"
                or report_data.get(
                    "history_version"
                )
                    != "baseline-aware-v2"
                or report_data.get(
                    "source_report_sha256"
                )
                    != source_fingerprint
            ):
                return {
                    "ok": False,
                    "state": "history_validation_failed",
                    "message": (
                        "Generated Historical Trend report "
                        "failed current-version validation."
                    ),
                }, 500

            try:
                text_content = (
                    temporary_text.read_text(
                        encoding="utf-8"
                    ).strip()
                )
            except OSError as exc:
                return {
                    "ok": False,
                    "state": "history_validation_failed",
                    "message": (
                        "Generated Historical Trend text "
                        "report could not be read: "
                        + str(exc)
                    ),
                }, 500

            if not text_content:
                return {
                    "ok": False,
                    "state": "history_validation_failed",
                    "message": (
                        "Generated Historical Trend text "
                        "report is empty."
                    ),
                }, 500

            try:
                with sqlite3.connect(
                    temporary_database
                ) as connection:
                    tables = {
                        row[0]
                        for row in connection.execute(
                            """
                            SELECT name
                            FROM sqlite_master
                            WHERE type = 'table'
                            """
                        ).fetchall()
                    }

                    required_tables = {
                        "scan_history",
                        "scan_summary",
                        "history_metadata",
                    }

                    if not required_tables.issubset(
                        tables
                    ):
                        return {
                            "ok": False,
                            "state":
                                "history_validation_failed",
                            "message": (
                                "Generated history database "
                                "is missing required tables."
                            ),
                        }, 500

                    version_row = connection.execute(
                        """
                        SELECT value
                        FROM history_metadata
                        WHERE key = 'analysis_version'
                        """
                    ).fetchone()

                    fingerprint_row = (
                        connection.execute(
                            """
                            SELECT value
                            FROM history_metadata
                            WHERE key =
                                'last_source_sha256'
                            """
                        ).fetchone()
                    )

                    scan_count = connection.execute(
                        """
                        SELECT COUNT(
                            DISTINCT scan_id
                        )
                        FROM scan_history
                        """
                    ).fetchone()[0]

            except sqlite3.Error as exc:
                return {
                    "ok": False,
                    "state": "history_validation_failed",
                    "message": (
                        "Generated history database could "
                        "not be validated: "
                        + str(exc)
                    ),
                }, 500

            if (
                not version_row
                or version_row[0]
                    != "baseline-aware-v2"
                or not fingerprint_row
                or fingerprint_row[0]
                    != source_fingerprint
                or scan_count < 1
            ):
                return {
                    "ok": False,
                    "state": "history_validation_failed",
                    "message": (
                        "Generated history database failed "
                        "version or source verification."
                    ),
                }, 500

            # Verify Threat Analysis did not change while
            # Historical Trends was being generated.
            try:
                current_report_mtime = (
                    SECURITY_REPORT_CSV.stat().st_mtime_ns
                )
            except OSError as exc:
                return {
                    "ok": False,
                    "state": "report_changed",
                    "message": (
                        "Threat report became unavailable "
                        "during Historical Trend generation: "
                        + str(exc)
                    ),
                }, 409

            current_fingerprint = (
                _calculate_file_sha256(
                    SECURITY_REPORT_CSV
                )
            )

            if (
                current_report_mtime
                    != source_report_mtime
                or current_fingerprint
                    != source_fingerprint
            ):
                return {
                    "ok": False,
                    "state": "report_changed",
                    "message": (
                        "Threat Analysis changed while "
                        "Historical Trends was running. "
                        "Generate history again."
                    ),
                }, 409

            final_threat_status = (
                get_threat_report_status()
            )

            if (
                final_threat_status["status"]
                != "current"
            ):
                return {
                    "ok": False,
                    "state": "threat_analysis_changed",
                    "message":
                        final_threat_status[
                            "message"
                        ],
                    "report_status":
                        final_threat_status[
                            "status"
                        ],
                    "stale_sources":
                        final_threat_status[
                            "stale_sources"
                        ],
                }, 409

            targets = [
                (
                    temporary_database,
                    HISTORY_DB,
                    temp_directory
                    / "previous_history.db",
                ),
                (
                    temporary_text,
                    HISTORICAL_TREND_TEXT,
                    temp_directory
                    / "previous_historical_trend_report.txt",
                ),
                (
                    temporary_json,
                    HISTORICAL_TREND_JSON,
                    temp_directory
                    / "previous_historical_trend_report.json",
                ),
            ]

            previous_states = []

            for (
                _temporary,
                target,
                backup,
            ) in targets:
                existed = target.exists()

                previous_states.append(
                    (
                        target,
                        backup,
                        existed,
                    )
                )

                if existed:
                    shutil.copy2(
                        target,
                        backup,
                    )

            try:
                for (
                    temporary,
                    target,
                    _backup,
                ) in targets:
                    temporary.replace(
                        target
                    )

            except OSError:
                # Restore all active files if any one of
                # the three replacements fails.
                for (
                    target,
                    backup,
                    existed,
                ) in previous_states:
                    if (
                        existed
                        and backup.exists()
                    ):
                        shutil.copy2(
                            backup,
                            target,
                        )
                    elif not existed:
                        target.unlink(
                            missing_ok=True
                        )

                raise

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "state": "history_timeout",
            "message": (
                "Historical Trend generation timed out."
            ),
        }, 500

    except OSError as exc:
        return {
            "ok": False,
            "state": "history_error",
            "message": str(exc),
        }, 500

    history = read_history()

    return {
        "ok": True,
        "state": "completed",
        "message": (
            "Historical Trends updated successfully."
        ),
        "history_status":
            history.get("history_status"),
        "scan_count":
            history.get("scan_count"),
        "latest":
            history.get("latest"),
        "source_report_sha256":
            source_fingerprint,
        "reports": [
            HISTORY_DB.name,
            HISTORICAL_TREND_TEXT.name,
            HISTORICAL_TREND_JSON.name,
        ],
    }, 200


def run_security_advisor() -> tuple[dict, int]:
    """Generate Security Advisor reports from current threat analysis."""

    report_status = get_threat_report_status()

    if report_status["status"] != "current":
        return {
            "ok": False,
            "state": "threat_analysis_required",
            "message": report_status["message"],
            "report_status": report_status["status"],
            "analysis_required": True,
            "stale_sources": report_status[
                "stale_sources"
            ],
        }, 409

    try:
        source_report_mtime = (
            SECURITY_REPORT_CSV.stat().st_mtime_ns
        )
    except OSError as exc:
        return {
            "ok": False,
            "state": "report_unavailable",
            "message": (
                "Threat report could not be accessed: "
                + str(exc)
            ),
        }, 500

    REPORTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="netshield-advisor-",
            dir=REPORTS_DIRECTORY,
        ) as temp_directory:
            temp_directory = Path(temp_directory)

            temporary_text = (
                temp_directory
                / "security_advisor_report.txt"
            )

            temporary_json = (
                temp_directory
                / "security_advisor_report.json"
            )

            module_7 = subprocess.run(
                [
                    sys.executable,
                    str(
                        PROJECT_ROOT
                        / "security_advisor"
                        / "security_advisor.py"
                    ),
                    "--report-csv",
                    str(SECURITY_REPORT_CSV),
                    "--text-output",
                    str(temporary_text),
                    "--json-output",
                    str(temporary_json),
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if module_7.returncode != 0:
                return {
                    "ok": False,
                    "state": "advisor_generation_failed",
                    "message": (
                        module_7.stderr.strip()
                        or module_7.stdout.strip()
                        or "Security Advisor generation failed."
                    ),
                }, 500

            if (
                not temporary_text.exists()
                or not temporary_json.exists()
            ):
                return {
                    "ok": False,
                    "state": "advisor_report_missing",
                    "message": (
                        "Security Advisor completed without "
                        "producing both report files."
                    ),
                }, 500

            try:
                advisor_data = json.loads(
                    temporary_json.read_text(
                        encoding="utf-8"
                    )
                )
            except (
                OSError,
                json.JSONDecodeError,
            ) as exc:
                return {
                    "ok": False,
                    "state": "advisor_validation_failed",
                    "message": (
                        "Generated advisor JSON is invalid: "
                        + str(exc)
                    ),
                }, 500

            required_sections = {
                "executive_summary",
                "overall_recommendations",
                "networks",
            }

            if (
                not isinstance(advisor_data, dict)
                or not required_sections.issubset(
                    advisor_data
                )
            ):
                return {
                    "ok": False,
                    "state": "advisor_validation_failed",
                    "message": (
                        "Generated Security Advisor report "
                        "is missing required sections."
                    ),
                }, 500

            # Ensure the source threat report was not replaced
            # while Module 7 was generating advice.
            try:
                current_report_mtime = (
                    SECURITY_REPORT_CSV.stat().st_mtime_ns
                )
            except OSError as exc:
                return {
                    "ok": False,
                    "state": "report_changed",
                    "message": (
                        "Threat report became unavailable "
                        "during advisor generation: "
                        + str(exc)
                    ),
                }, 409

            if (
                current_report_mtime
                != source_report_mtime
            ):
                return {
                    "ok": False,
                    "state": "report_changed",
                    "message": (
                        "Threat Analysis changed while the "
                        "Security Advisor was running. "
                        "Run Security Advisor again."
                    ),
                }, 409

            final_status = get_threat_report_status()

            if final_status["status"] != "current":
                return {
                    "ok": False,
                    "state": "threat_analysis_changed",
                    "message": final_status["message"],
                    "report_status": final_status[
                        "status"
                    ],
                    "stale_sources": final_status[
                        "stale_sources"
                    ],
                }, 409

            # Keep backups inside the temporary directory so
            # both real advisor files can be restored if one
            # replacement unexpectedly fails.
            backup_text = (
                temp_directory
                / "previous_advisor_report.txt"
            )

            backup_json = (
                temp_directory
                / "previous_advisor_report.json"
            )

            text_existed = SECURITY_ADVISOR_TEXT.exists()
            json_existed = SECURITY_ADVISOR_JSON.exists()

            if text_existed:
                shutil.copy2(
                    SECURITY_ADVISOR_TEXT,
                    backup_text,
                )

            if json_existed:
                shutil.copy2(
                    SECURITY_ADVISOR_JSON,
                    backup_json,
                )

            try:
                temporary_text.replace(
                    SECURITY_ADVISOR_TEXT
                )

                temporary_json.replace(
                    SECURITY_ADVISOR_JSON
                )

            except OSError:
                # Roll back so a partially updated advisor
                # report pair is not left behind.
                if text_existed and backup_text.exists():
                    shutil.copy2(
                        backup_text,
                        SECURITY_ADVISOR_TEXT,
                    )
                elif not text_existed:
                    SECURITY_ADVISOR_TEXT.unlink(
                        missing_ok=True
                    )

                if json_existed and backup_json.exists():
                    shutil.copy2(
                        backup_json,
                        SECURITY_ADVISOR_JSON,
                    )
                elif not json_existed:
                    SECURITY_ADVISOR_JSON.unlink(
                        missing_ok=True
                    )

                raise

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "state": "advisor_timeout",
            "message": "Security Advisor generation timed out.",
        }, 500

    except OSError as exc:
        return {
            "ok": False,
            "state": "advisor_error",
            "message": str(exc),
        }, 500

    summary = advisor_data[
        "executive_summary"
    ]

    return {
        "ok": True,
        "state": "completed",
        "message": (
            "Security Advisor generated successfully."
        ),
        "report_status": "current",
        "reports": [
            SECURITY_ADVISOR_TEXT.name,
            SECURITY_ADVISOR_JSON.name,
        ],
        "network_count": len(
            advisor_data["networks"]
        ),
        "overall_score": summary.get(
            "overall_security_score"
        ),
        "overall_grade": summary.get(
            "overall_security_grade"
        ),
        "grade_label": summary.get(
            "overall_grade_label"
        ),
        "recommendation_count": len(
            advisor_data[
                "overall_recommendations"
            ]
        ),
    }, 200


def run_alert_notifications() -> tuple[dict, int]:
    """Safely generate Module 9 alerts from current Threat Analysis."""

    threat_status = get_threat_report_status()

    if threat_status["status"] != "current":
        return {
            "ok": False,
            "state": "threat_analysis_required",
            "message": threat_status["message"],
            "report_status": threat_status["status"],
            "analysis_required": True,
            "stale_sources": threat_status[
                "stale_sources"
            ],
        }, 409

    alert_status = get_alert_notification_status()

    if alert_status["status"] == "legacy":
        return {
            "ok": False,
            "state": "legacy_alerts_detected",
            "message": (
                "Legacy Alert Notification files must be "
                "preserved separately before current "
                "baseline-aware alerts are generated."
            ),
            "alert_status": "legacy",
            "migration_required": True,
        }, 409

    if alert_status["status"] in {
        "incomplete",
        "unavailable",
    }:
        return {
            "ok": False,
            "state": "alert_outputs_unavailable",
            "message": alert_status["message"],
            "alert_status": alert_status["status"],
            "migration_required": alert_status[
                "migration_required"
            ],
        }, 409

    try:
        source_report_mtime = (
            SECURITY_REPORT_CSV.stat().st_mtime_ns
        )
    except OSError as exc:
        return {
            "ok": False,
            "state": "report_unavailable",
            "message": (
                "Threat report could not be accessed: "
                + str(exc)
            ),
        }, 500

    source_fingerprint = _calculate_file_sha256(
        SECURITY_REPORT_CSV
    )

    if source_fingerprint is None:
        return {
            "ok": False,
            "state": "report_unavailable",
            "message": (
                "Threat report could not be fingerprinted "
                "for Alert Notification generation."
            ),
        }, 500

    if alert_status["status"] == "current":
        return {
            "ok": True,
            "state": "already_recorded",
            "message": (
                "This exact Threat Analysis has already "
                "been processed by Alert Notifications. "
                "No duplicate alerts were written."
            ),
            "source_report_sha256":
                source_fingerprint,
            "alert_status": "current",
        }, 200

    REPORTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="netshield-alerts-",
            dir=REPORTS_DIRECTORY,
        ) as temp_directory:
            temp_directory = Path(
                temp_directory
            )

            temporary_log = (
                temp_directory
                / ALERT_NOTIFICATION_LOG.name
            )

            temporary_json = (
                temp_directory
                / ALERT_NOTIFICATION_JSON.name
            )

            # Preserve valid current-version alert history
            # when processing a newer Threat Analysis.
            if (
                alert_status["status"] == "stale"
                and ALERT_NOTIFICATION_LOG.exists()
            ):
                shutil.copy2(
                    ALERT_NOTIFICATION_LOG,
                    temporary_log,
                )

            module_9 = subprocess.run(
                [
                    sys.executable,
                    str(
                        PROJECT_ROOT
                        / "alert_notification"
                        / "alert_notification_system.py"
                    ),
                    "--report-csv",
                    str(SECURITY_REPORT_CSV),
                    "--log-path",
                    str(temporary_log),
                    "--json-path",
                    str(temporary_json),
                    "--no-color",
                ],
                cwd=PROJECT_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if module_9.returncode != 0:
                return {
                    "ok": False,
                    "state": "alert_generation_failed",
                    "message": (
                        module_9.stderr.strip()
                        or module_9.stdout.strip()
                        or (
                            "Alert Notification generation "
                            "failed."
                        )
                    ),
                }, 500

            # A valid zero-alert run may not write any log
            # lines, but Module 9 still exposes a log file.
            temporary_log.touch(
                exist_ok=True
            )

            if not temporary_json.exists():
                return {
                    "ok": False,
                    "state": "alert_output_missing",
                    "message": (
                        "Alert Notification generation did "
                        "not produce its JSON output."
                    ),
                }, 500

            try:
                alert_data = json.loads(
                    temporary_json.read_text(
                        encoding="utf-8"
                    )
                )
            except (
                OSError,
                json.JSONDecodeError,
            ) as exc:
                return {
                    "ok": False,
                    "state": "alert_validation_failed",
                    "message": (
                        "Generated Alert Notification JSON "
                        "is invalid: "
                        + str(exc)
                    ),
                }, 500

            if (
                not isinstance(alert_data, dict)
                or alert_data.get("state")
                    != "completed"
                or alert_data.get("analysis_version")
                    != CURRENT_ALERT_NOTIFICATION_VERSION
                or alert_data.get(
                    "source_report_sha256"
                ) != source_fingerprint
                or not isinstance(
                    alert_data.get("summary"),
                    dict,
                )
                or not isinstance(
                    alert_data.get("alerts"),
                    list,
                )
            ):
                return {
                    "ok": False,
                    "state": "alert_validation_failed",
                    "message": (
                        "Generated Alert Notification output "
                        "failed version, fingerprint, or "
                        "structure validation."
                    ),
                }, 500

            # Ensure Threat Analysis did not change while
            # Module 9 was generating alerts.
            current_report_fingerprint = (
                _calculate_file_sha256(
                    SECURITY_REPORT_CSV
                )
            )

            try:
                current_report_mtime = (
                    SECURITY_REPORT_CSV.stat().st_mtime_ns
                )
            except OSError as exc:
                return {
                    "ok": False,
                    "state": "report_changed",
                    "message": (
                        "Threat report became unavailable "
                        "during alert generation: "
                        + str(exc)
                    ),
                }, 409

            if (
                current_report_mtime
                    != source_report_mtime
                or current_report_fingerprint
                    != source_fingerprint
            ):
                return {
                    "ok": False,
                    "state": "report_changed",
                    "message": (
                        "Threat Analysis changed while "
                        "Alert Notifications were being "
                        "generated. Run Module 9 again."
                    ),
                }, 409

            final_threat_status = (
                get_threat_report_status()
            )

            if final_threat_status["status"] != "current":
                return {
                    "ok": False,
                    "state": "threat_analysis_required",
                    "message": final_threat_status[
                        "message"
                    ],
                    "analysis_required": True,
                }, 409

            targets = [
                (
                    temporary_log,
                    ALERT_NOTIFICATION_LOG,
                ),
                (
                    temporary_json,
                    ALERT_NOTIFICATION_JSON,
                ),
            ]

            backups = []

            try:
                for _, destination in targets:
                    if destination.exists():
                        backup = (
                            temp_directory
                            / (
                                destination.name
                                + ".backup"
                            )
                        )

                        shutil.copy2(
                            destination,
                            backup,
                        )

                        backups.append(
                            (
                                destination,
                                backup,
                            )
                        )

                replaced = []

                for source, destination in targets:
                    source.replace(destination)
                    replaced.append(destination)

            except OSError as exc:
                for destination in replaced:
                    try:
                        destination.unlink(
                            missing_ok=True
                        )
                    except OSError:
                        pass

                for destination, backup in backups:
                    if backup.exists():
                        shutil.copy2(
                            backup,
                            destination,
                        )

                return {
                    "ok": False,
                    "state": "alert_save_failed",
                    "message": (
                        "Alert Notification outputs could "
                        "not be saved atomically: "
                        + str(exc)
                    ),
                }, 500

    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "state": "alert_timeout",
            "message": (
                "Alert Notification generation timed out."
            ),
        }, 500

    except OSError as exc:
        return {
            "ok": False,
            "state": "alert_error",
            "message": str(exc),
        }, 500

    final_status = get_alert_notification_status()

    return {
        "ok": True,
        "state": "completed",
        "message": (
            "Alert Notifications generated successfully."
        ),
        "alert_status": final_status["status"],
        "source_report_sha256":
            source_fingerprint,
        "alert_count": alert_data[
            "summary"
        ].get(
            "total_alerts",
            len(alert_data["alerts"]),
        ),
        "summary": alert_data["summary"],
        "reports": [
            ALERT_NOTIFICATION_LOG.name,
            ALERT_NOTIFICATION_JSON.name,
        ],
    }, 200


@app.post("/api/trusted-baseline/archive-legacy")
def archive_legacy_trusted_baseline_route():
    response, status_code = (
        archive_legacy_trusted_baseline()
    )
    return jsonify(response), status_code


@app.post("/api/trusted-baseline/generate")
def generate_trusted_baseline():
    response, status_code = (
        run_trusted_baseline_generation()
    )
    return jsonify(response), status_code


@app.post("/api/security-advisor/generate")
def generate_security_advisor():
    response, status_code = (
        run_security_advisor()
    )
    return jsonify(response), status_code


@app.post("/api/threats/analyze")
def analyze_threats():
    response, status_code = run_threat_analysis()
    return jsonify(response), status_code


@app.post("/api/alerts/archive-legacy")
def archive_legacy_alert_notifications_route():
    response, status_code = (
        archive_legacy_alert_notifications()
    )
    return jsonify(response), status_code


@app.post("/api/alerts/generate")
def generate_alert_notifications():
    response, status_code = (
        run_alert_notifications()
    )
    return jsonify(response), status_code


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
    capture_status = read_capture_status()
    capture_progress = capture_status.get(
        "progress",
        {},
    )

    live_capture_active = (
        capture_status.get("state") == "running"
        and capture_progress.get("state") == "capturing"
    )

    live_alerts = (
        read_packet_alerts()
        if live_capture_active
        else []
    )

    if live_alerts:
        save_packet_alert_history(live_alerts)

    report_status = get_threat_report_status()

    report_findings = (
        read_threats()
        if report_status["status"] == "current"
        else []
    )

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
            "report_status": report_status["status"],
            "analysis_required": report_status[
                "analysis_required"
            ],
            "stale_sources": report_status[
                "stale_sources"
            ],
            "report_message": report_status["message"],
            "threats": threat_rows,
        }
    )


@app.get("/api/reports")
def reports():
    report_rows = read_reports()
    advisor_status = get_security_advisor_status()
    alert_status = get_alert_notification_status()
    trusted_baseline_status = (
        get_trusted_baseline_report_status()
    )

    return jsonify(
        {
            "count": len(report_rows),
            "reports": report_rows,
            "trusted_baseline": {
                "status":
                    trusted_baseline_status["status"],
                "generation_required":
                    trusted_baseline_status[
                        "generation_required"
                    ],
                "migration_required":
                    trusted_baseline_status.get(
                        "migration_required",
                        False,
                    ),
                "analysis_version":
                    trusted_baseline_status.get(
                        "analysis_version"
                    ),
                "current_version":
                    trusted_baseline_status.get(
                        "current_version"
                    ),
                "message":
                    trusted_baseline_status["message"],
                "generate_url":
                    "/api/trusted-baseline/generate",
                "archive_legacy_url":
                    trusted_baseline_status.get(
                        "archive_legacy_url"
                    ),
            },
            "security_advisor": {
                "status": advisor_status["status"],
                "generation_required": advisor_status[
                    "generation_required"
                ],
                "threat_analysis_required": advisor_status[
                    "threat_analysis_required"
                ],
                "message": advisor_status["message"],
                "generate_url": (
                    "/api/security-advisor/generate"
                ),
            },
            "alert_notifications": {
                "status": alert_status["status"],
                "generation_required": alert_status[
                    "generation_required"
                ],
                "threat_analysis_required": alert_status[
                    "threat_analysis_required"
                ],
                "migration_required": alert_status.get(
                    "migration_required",
                    False,
                ),
                "analysis_version": alert_status.get(
                    "analysis_version"
                ),
                "current_version": alert_status.get(
                    "current_version"
                ),
                "message": alert_status["message"],
                "generate_url": "/api/alerts/generate",
                "archive_legacy_url": alert_status.get(
                    "archive_legacy_url"
                ),
            },
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


@app.post("/api/history/archive-legacy")
def archive_legacy_history_route():
    response, status_code = (
        archive_legacy_history()
    )
    return jsonify(response), status_code


@app.post("/api/history/generate")
def generate_historical_trends():
    response, status_code = (
        run_historical_trends()
    )
    return jsonify(response), status_code


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
