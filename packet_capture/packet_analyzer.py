"""Packet classification and security analysis for 802.11 traffic."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque

from scapy.layers.dot11 import Dot11


BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"


@dataclass(frozen=True)
class PacketAnalysis:
    """Normalized packet details used by the terminal view and CSV logger."""

    timestamp: str
    packet_type: str
    source_mac: str
    destination_mac: str
    bssid: str
    frame_type: str
    signal_strength: int | None
    alert: str

    def as_csv_row(self) -> dict[str, str | int | None]:
        return {
            "Timestamp": self.timestamp,
            "Packet Type": self.packet_type,
            "Source MAC": self.source_mac,
            "Destination MAC": self.destination_mac,
            "BSSID": self.bssid,
            "Frame Type": self.frame_type,
            "Signal Strength": self.signal_strength,
        }


class PacketAnalyzer:
    """Analyze 802.11 packets and detect simple suspicious traffic patterns."""

    def __init__(
        self,
        deauth_threshold: int = 10,
        unknown_mac_threshold: int = 50,
        window_seconds: int = 30,
    ) -> None:
        self.deauth_threshold = deauth_threshold
        self.unknown_mac_threshold = unknown_mac_threshold
        self.window_seconds = window_seconds
        self.deauth_events: Deque[float] = deque()
        self.source_events: dict[str, Deque[float]] = defaultdict(deque)
        self.known_bssids: set[str] = set()

    def analyze_packet(self, packet: Any) -> PacketAnalysis | None:
        """Classify one Scapy packet and return structured details."""

        if not packet.haslayer(Dot11):
            return None

        dot11 = packet[Dot11]
        now = datetime.now()
        epoch_time = now.timestamp()

        packet_type = self._classify_packet(dot11)
        if packet_type is None:
            return None

        source_mac = self._normalize_mac(dot11.addr2)
        destination_mac = self._normalize_mac(dot11.addr1)
        bssid = self._extract_bssid(dot11)
        frame_type = self._frame_type_name(dot11.type)
        signal_strength = getattr(packet, "dBm_AntSignal", None)

        if packet_type in {"Beacon", "Probe Response"} and bssid != "Unknown":
            self.known_bssids.add(bssid)
        if packet_type == "Beacon" and source_mac != "Unknown":
            self.known_bssids.add(source_mac)

        alert = self._detect_alert(packet_type, source_mac, epoch_time)

        return PacketAnalysis(
            timestamp=now.strftime("%H:%M:%S"),
            packet_type=packet_type,
            source_mac=source_mac,
            destination_mac=destination_mac,
            bssid=bssid,
            frame_type=frame_type,
            signal_strength=int(signal_strength) if signal_strength is not None else None,
            alert=alert,
        )

    def is_deauth_attack_alert(self, analysis: PacketAnalysis | None) -> bool:
        return analysis is not None and "Deauthentication Attack" in analysis.alert

    def _classify_packet(self, dot11: Dot11) -> str | None:
        if dot11.type == 0:
            subtype_map = {
                4: "Probe Request",
                5: "Probe Response",
                8: "Beacon",
                11: "Authentication",
                12: "Deauthentication",
            }
            return subtype_map.get(dot11.subtype)

        if dot11.type == 2:
            return "Data"

        return None

    def _extract_bssid(self, dot11: Dot11) -> str:
        if dot11.type == 0:
            if dot11.subtype == 4:
                return "Broadcast"
            return self._normalize_mac(dot11.addr3 or dot11.addr2)

        if dot11.type == 2:
            return self._normalize_mac(dot11.addr3)

        return "Unknown"

    def _detect_alert(self, packet_type: str, source_mac: str, epoch_time: float) -> str:
        alerts: list[str] = []

        if packet_type == "Deauthentication":
            self.deauth_events.append(epoch_time)
            self._trim_events(self.deauth_events, epoch_time)
            if len(self.deauth_events) >= self.deauth_threshold:
                alerts.append("Suspicious: Possible WiFi Deauthentication Attack")

        if source_mac not in {"Unknown", "Broadcast", BROADCAST_MAC}:
            source_history = self.source_events[source_mac]
            source_history.append(epoch_time)
            self._trim_events(source_history, epoch_time)

            if source_mac not in self.known_bssids and len(source_history) >= self.unknown_mac_threshold:
                alerts.append("Suspicious: Unknown MAC repeated traffic")

        return " | ".join(alerts) if alerts else "Normal"

    def _trim_events(self, events: Deque[float], epoch_time: float) -> None:
        oldest_allowed = epoch_time - self.window_seconds
        while events and events[0] < oldest_allowed:
            events.popleft()

    @staticmethod
    def _normalize_mac(mac_address: str | None) -> str:
        if not mac_address:
            return "Unknown"
        if mac_address.lower() == "ff:ff:ff:ff:ff:ff":
            return "Broadcast"
        return mac_address.upper()

    @staticmethod
    def _frame_type_name(frame_type: int) -> str:
        return {
            0: "Management",
            1: "Control",
            2: "Data",
            3: "Extension",
        }.get(frame_type, "Unknown")
