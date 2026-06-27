"""CSV logger for captured WiFi packet metadata."""

from __future__ import annotations

import csv
from pathlib import Path

from packet_analyzer import PacketAnalysis


CSV_HEADERS = [
    "Timestamp",
    "Packet Type",
    "Source MAC",
    "Destination MAC",
    "BSSID",
    "Frame Type",
    "Signal Strength",
]


class PacketCSVLogger:
    """Append packet analysis rows to a CSV file."""

    def __init__(self, csv_path: str | Path) -> None:
        self.csv_path = Path(csv_path)
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_header()

    def log_packet(self, analysis: PacketAnalysis) -> None:
        with self.csv_path.open("a", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
            writer.writerow(analysis.as_csv_row())

    def _ensure_header(self) -> None:
        if self.csv_path.exists() and self.csv_path.stat().st_size > 0:
            return

        with self.csv_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADERS)
            writer.writeheader()
