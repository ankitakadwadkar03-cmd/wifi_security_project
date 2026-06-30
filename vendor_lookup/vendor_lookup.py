"""Vendor lookup using offline IEEE OUI CSV database."""

from __future__ import annotations

import csv
from pathlib import Path


DEFAULT_OUI_CSV = Path(__file__).with_name("oui.csv")


def normalize_mac_prefix(mac_address: str | None) -> str:
    if not mac_address:
        return ""

    cleaned = mac_address.strip().upper().replace("-", ":")
    if cleaned in {"UNKNOWN", "BROADCAST"}:
        return ""

    parts = cleaned.split(":")
    if len(parts) < 3:
        return ""

    return "".join(parts[:3])


def load_oui_database(csv_path: str | Path = DEFAULT_OUI_CSV) -> dict[str, str]:
    path = Path(csv_path)
    if not path.exists():
        return {}

    vendors: dict[str, str] = {}

    with path.open("r", newline="", encoding="utf-8", errors="replace") as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            assignment = (row.get("Assignment") or "").strip().upper()
            organization = (row.get("Organization Name") or "").strip()

            if assignment and organization:
                vendors[assignment] = organization

    return vendors


def lookup_vendor(mac_address: str | None, vendors: dict[str, str] | None = None) -> str:
    if vendors is None:
        vendors = load_oui_database()

    prefix = normalize_mac_prefix(mac_address)

    if not prefix:
        return "Unknown"

    return vendors.get(prefix, "Unknown")
