"""CSV logging for WiFi scan results."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Mapping


CSV_HEADERS = ["SSID", "BSSID", "Channel", "Frequency", "Signal", "Encryption"]


def save_to_csv(
    networks: Mapping[str, Mapping[str, str | int | None]],
    csv_path: str | Path = "wifi_scan_results.csv",
) -> None:
    """Write the latest scan snapshot to a CSV file."""

    output_path = Path(csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
        writer.writeheader()

        for network in sorted(networks.values(), key=lambda item: str(item.get("SSID", ""))):
            writer.writerow({header: network.get(header, "") for header in CSV_HEADERS})
