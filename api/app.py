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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
