from __future__ import annotations

import csv
from pathlib import Path

from flask import Flask, jsonify
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
