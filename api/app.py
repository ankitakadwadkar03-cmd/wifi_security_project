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

SCANNER_SCRIPT = PROJECT_ROOT / "scanner" / "wifi_scanner.py"
SCANNER_LOG_PATH = PROJECT_ROOT / "scanner" / "scanner_control.log"

SCANNER_PROCESS = None
SCANNER_LOG_HANDLE = None
SCANNER_LOCK = threading.Lock()

SCANNER_STATE = {
    "state": "idle",
    "interface": None,
    "pid": None,
    "started_at": None,
    "stopped_at": None,
    "last_error": "",
    "message": "Scanner is idle.",
}


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


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_scanner_log_tail(max_lines: int = 10) -> str:
    """Read the latest scanner log lines for useful error messages."""
    if not SCANNER_LOG_PATH.exists():
        return ""

    try:
        lines = SCANNER_LOG_PATH.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()

        return "\n".join(lines[-max_lines:])
    except OSError:
        return ""


def _close_scanner_log_locked() -> None:
    global SCANNER_LOG_HANDLE

    if SCANNER_LOG_HANDLE is not None:
        try:
            SCANNER_LOG_HANDLE.close()
        except OSError:
            pass

        SCANNER_LOG_HANDLE = None


def _refresh_scanner_state_locked() -> None:
    """Update scanner state when the child process has exited."""
    global SCANNER_PROCESS

    if SCANNER_PROCESS is None:
        return

    exit_code = SCANNER_PROCESS.poll()

    if exit_code is None:
        return

    SCANNER_STATE["pid"] = None
    SCANNER_STATE["stopped_at"] = _utc_timestamp()

    if exit_code == 0:
        SCANNER_STATE["state"] = "idle"
        SCANNER_STATE["message"] = "Scanner stopped normally."
        SCANNER_STATE["last_error"] = ""
    else:
        SCANNER_STATE["state"] = "error"
        SCANNER_STATE["message"] = (
            f"Scanner exited with code {exit_code}."
        )
        SCANNER_STATE["last_error"] = _read_scanner_log_tail()

    SCANNER_PROCESS = None
    _close_scanner_log_locked()


def read_scanner_status() -> dict:
    """Return scanner process and wireless-adapter status."""
    with SCANNER_LOCK:
        _refresh_scanner_state_locked()
        scanner_state = dict(SCANNER_STATE)

    adapter = read_adapter_status()

    scanner_state["running"] = scanner_state["state"] in {
        "starting",
        "running",
        "stopping",
    }
    scanner_state["adapter"] = adapter

    return scanner_state


def start_scanner_process(interface: str | None = None) -> tuple[dict, int]:
    """Start the scanner for one validated wireless interface."""
    global SCANNER_PROCESS
    global SCANNER_LOG_HANDLE

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

    with SCANNER_LOCK:
        _refresh_scanner_state_locked()

        if SCANNER_PROCESS is not None:
            return {
                "ok": False,
                "state": SCANNER_STATE["state"],
                "message": "A scanner process is already running.",
                "scanner": dict(SCANNER_STATE),
            }, 409

        if not SCANNER_SCRIPT.exists():
            return {
                "ok": False,
                "state": "error",
                "message": "The WiFi scanner script was not found.",
            }, 500

        command = [
            sys.executable,
            str(SCANNER_SCRIPT),
            "--interface",
            selected_interface,
        ]

        # Do not run the Flask web application as root and do not
        # execute editable project files through unrestricted sudo.
        # A restricted scanner service will be configured separately.
        if os.geteuid() != 0:
            return {
                "ok": False,
                "state": "permission_required",
                "message": (
                    "Secure scanner permissions are not configured yet. "
                    "Do not run the Flask backend as root."
                ),
            }, 403

        SCANNER_LOG_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        SCANNER_LOG_HANDLE = SCANNER_LOG_PATH.open(
            "a",
            encoding="utf-8",
        )

        SCANNER_LOG_HANDLE.write(
            f"\n[{_utc_timestamp()}] Starting scanner on "
            f"{selected_interface}\n"
        )
        SCANNER_LOG_HANDLE.flush()

        try:
            SCANNER_PROCESS = subprocess.Popen(
                command,
                cwd=PROJECT_ROOT,
                stdout=SCANNER_LOG_HANDLE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except OSError as process_error:
            _close_scanner_log_locked()

            SCANNER_STATE.update(
                {
                    "state": "error",
                    "interface": selected_interface,
                    "pid": None,
                    "last_error": str(process_error),
                    "message": "Unable to start the scanner process.",
                }
            )

            return {
                "ok": False,
                "scanner": dict(SCANNER_STATE),
            }, 500

        SCANNER_STATE.update(
            {
                "state": "starting",
                "interface": selected_interface,
                "pid": SCANNER_PROCESS.pid,
                "started_at": _utc_timestamp(),
                "stopped_at": None,
                "last_error": "",
                "message": (
                    f"Starting scanner on {selected_interface}."
                ),
            }
        )

    # Give immediate setup failures a moment to appear.
    time.sleep(0.5)

    with SCANNER_LOCK:
        _refresh_scanner_state_locked()

        if SCANNER_PROCESS is None:
            return {
                "ok": False,
                "scanner": dict(SCANNER_STATE),
            }, 500

        SCANNER_STATE["state"] = "running"
        SCANNER_STATE["message"] = (
            f"Scanning on {selected_interface}."
        )

        return {
            "ok": True,
            "scanner": dict(SCANNER_STATE),
        }, 202


def stop_scanner_process() -> tuple[dict, int]:
    """Stop the running scanner and allow it to save the latest CSV."""
    global SCANNER_PROCESS

    with SCANNER_LOCK:
        _refresh_scanner_state_locked()

        if SCANNER_PROCESS is None:
            SCANNER_STATE.update(
                {
                    "state": "idle",
                    "pid": None,
                    "message": "Scanner is already stopped.",
                }
            )

            return {
                "ok": True,
                "scanner": dict(SCANNER_STATE),
            }, 200

        process = SCANNER_PROCESS

        SCANNER_STATE["state"] = "stopping"
        SCANNER_STATE["message"] = "Stopping scanner safely."

    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=30)
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass

    with SCANNER_LOCK:
        SCANNER_PROCESS = None
        SCANNER_STATE.update(
            {
                "state": "idle",
                "pid": None,
                "stopped_at": _utc_timestamp(),
                "last_error": "",
                "message": (
                    "Scanner stopped. Latest CSV results were preserved."
                ),
            }
        )
        _close_scanner_log_locked()

        return {
            "ok": True,
            "scanner": dict(SCANNER_STATE),
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
