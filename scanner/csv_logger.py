"""CSV logging for WiFi scan results."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Mapping


CSV_HEADERS = ["SSID", "BSSID", "Channel", "Frequency", "Signal", "Encryption"]


def _read_existing_networks(csv_path: Path) -> dict[str, dict[str, str]]:
    """Read previously discovered networks so new scans do not forget them."""
    if not csv_path.exists():
        return {}

    with csv_path.open("r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        networks: dict[str, dict[str, str]] = {}

        for row in reader:
            bssid = (row.get("BSSID") or "").strip().upper()
            if bssid:
                networks[bssid] = {header: row.get(header, "") for header in CSV_HEADERS}

        return networks


def save_to_csv(
    networks: Mapping[str, Mapping[str, str | int | None]],
    csv_path: str | Path = "wifi_scan_results.csv",
) -> None:
    """Merge latest scan snapshot with previous CSV data and save it."""
    output_path = Path(csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    merged_networks ={}

    for network in networks.values():
        bssid = str(network.get("BSSID") or "").strip().upper()
        if not bssid:
            continue

        merged_networks[bssid] = {
            header: "" if network.get(header) is None else str(network.get(header, ""))
            for header in CSV_HEADERS
        }

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
        writer.writeheader()

        for network in sorted(
            merged_networks.values(),
            key=lambda item: (item.get("SSID", ""), item.get("BSSID", "")),
        ):
            writer.writerow({header: network.get(header, "") for header in CSV_HEADERS})
