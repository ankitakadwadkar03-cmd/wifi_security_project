"""Threat detection for the security dashboard."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_DEAUTH_THRESHOLD = 10
DEFAULT_UNKNOWN_MAC_THRESHOLD = 50


@dataclass(frozen=True)
class NetworkThreatSummary:
    ssid: str
    bssid: str
    encryption: str
    packet_count: int
    threat_detected: str
    deauth_count: int
    unknown_mac_count: int
    suspicious_packet_count: int


def read_csv_rows(csv_path: str | Path) -> list[dict[str, str]]:
    path = Path(csv_path)
    if not path.exists():
        return []

    with path.open("r", newline="", encoding="utf-8") as csv_file:
        return [dict(row) for row in csv.DictReader(csv_file)]


def detect_threats(
    scan_csv_path: str | Path,
    packet_csv_path: str | Path,
    deauth_threshold: int = DEFAULT_DEAUTH_THRESHOLD,
    unknown_mac_threshold: int = DEFAULT_UNKNOWN_MAC_THRESHOLD,
) -> list[NetworkThreatSummary]:
    scan_rows = read_csv_rows(scan_csv_path)
    packet_rows = read_csv_rows(packet_csv_path)

    networks = _build_network_index(scan_rows)
    packet_stats = _calculate_packet_stats(packet_rows, networks)

    summaries: list[NetworkThreatSummary] = []
    for bssid, network in networks.items():
        stats = packet_stats.get(bssid, _empty_stats())
        threat = _select_threat(
            encryption=network["encryption"],
            deauth_count=stats["deauth_count"],
            unknown_mac_count=stats["unknown_mac_count"],
            suspicious_packet_count=stats["suspicious_packet_count"],
            deauth_threshold=deauth_threshold,
            unknown_mac_threshold=unknown_mac_threshold,
        )
        summaries.append(
            NetworkThreatSummary(
                ssid=network["ssid"],
                bssid=bssid,
                encryption=network["encryption"],
                packet_count=stats["packet_count"],
                threat_detected=threat,
                deauth_count=stats["deauth_count"],
                unknown_mac_count=stats["unknown_mac_count"],
                suspicious_packet_count=stats["suspicious_packet_count"],
            )
        )

    for bssid, stats in packet_stats.items():
        if bssid in networks:
            continue
        threat = _select_threat(
            encryption="Unknown",
            deauth_count=stats["deauth_count"],
            unknown_mac_count=stats["unknown_mac_count"],
            suspicious_packet_count=stats["suspicious_packet_count"],
            deauth_threshold=deauth_threshold,
            unknown_mac_threshold=unknown_mac_threshold,
        )
        summaries.append(
            NetworkThreatSummary(
                ssid="Unknown_Device",
                bssid=bssid,
                encryption="Unknown",
                packet_count=stats["packet_count"],
                threat_detected=threat,
                deauth_count=stats["deauth_count"],
                unknown_mac_count=stats["unknown_mac_count"],
                suspicious_packet_count=stats["suspicious_packet_count"],
            )
        )

    return sorted(
        summaries,
        key=lambda item: (item.threat_detected == "Normal Traffic", -item.packet_count, item.ssid),
    )


def _build_network_index(scan_rows: Iterable[dict[str, str]]) -> dict[str, dict[str, str]]:
    networks: dict[str, dict[str, str]] = {}

    for row in scan_rows:
        bssid = _normalize_mac(row.get("BSSID"))
        if bssid == "Unknown":
            continue

        networks[bssid] = {
            "ssid": row.get("SSID") or "Unknown_AP",
            "encryption": row.get("Encryption") or "Unknown",
        }

    return networks


def _calculate_packet_stats(
    packet_rows: Iterable[dict[str, str]],
    networks: dict[str, dict[str, str]],
) -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = defaultdict(_empty_stats)
    known_bssids = set(networks.keys())
    source_counts: Counter[str] = Counter()

    packet_rows = list(packet_rows)
    for row in packet_rows:
        source_mac = _normalize_mac(row.get("Source MAC"))
        if source_mac not in {"Unknown", "Broadcast"}:
            source_counts[source_mac] += 1

    repeated_unknown_macs = {
        mac for mac, count in source_counts.items() if mac not in known_bssids and count >= DEFAULT_UNKNOWN_MAC_THRESHOLD
    }

    for row in packet_rows:
        bssid = _resolve_packet_bssid(row, known_bssids)
        packet_type = (row.get("Packet Type") or "Unknown").strip()
        source_mac = _normalize_mac(row.get("Source MAC"))

        stats[bssid]["packet_count"] += 1

        if packet_type.lower() == "deauthentication":
            stats[bssid]["deauth_count"] += 1
            stats[bssid]["suspicious_packet_count"] += 1

        if source_mac in repeated_unknown_macs:
            stats[bssid]["unknown_mac_count"] += 1
            stats[bssid]["suspicious_packet_count"] += 1

    return dict(stats)


def _resolve_packet_bssid(row: dict[str, str], known_bssids: set[str]) -> str:
    bssid = _normalize_mac(row.get("BSSID"))
    if bssid not in {"Unknown", "Broadcast"}:
        return bssid

    source_mac = _normalize_mac(row.get("Source MAC"))
    destination_mac = _normalize_mac(row.get("Destination MAC"))

    if source_mac in known_bssids:
        return source_mac
    if destination_mac in known_bssids:
        return destination_mac
    return "Unknown"


def _select_threat(
    encryption: str,
    deauth_count: int,
    unknown_mac_count: int,
    suspicious_packet_count: int,
    deauth_threshold: int,
    unknown_mac_threshold: int,
) -> str:
    normalized_encryption = encryption.strip().lower()

    if deauth_count >= deauth_threshold:
        return "Deauthentication Attack"
    if unknown_mac_count >= unknown_mac_threshold:
        return "Unknown MAC Flooding"
    if suspicious_packet_count > 0:
        return "Suspicious Packet Behavior"
    if normalized_encryption == "open":
        return "Unsecured Network"
    if normalized_encryption == "wep":
        return "Weak Encryption"
    return "Normal Traffic"


def _empty_stats() -> dict[str, int]:
    return {
        "packet_count": 0,
        "deauth_count": 0,
        "unknown_mac_count": 0,
        "suspicious_packet_count": 0,
    }


def _normalize_mac(mac_address: str | None) -> str:
    if not mac_address:
        return "Unknown"

    cleaned = mac_address.strip()
    if not cleaned:
        return "Unknown"
    if cleaned.lower() == "ff:ff:ff:ff:ff:ff":
        return "Broadcast"
    return cleaned.upper()
