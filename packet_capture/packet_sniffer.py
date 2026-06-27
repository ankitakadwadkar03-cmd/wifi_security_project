"""Live 802.11 packet capture for Kali Linux monitor-mode interfaces.

Run:
    sudo python3 packet_capture/packet_sniffer.py --interface wlan0mon
"""

from __future__ import annotations

import argparse
import signal
import sys
from collections import deque
from pathlib import Path
from typing import Any, Deque

from scapy.all import conf, sniff

from packet_analyzer import PacketAnalysis, PacketAnalyzer
from packet_logger import PacketCSVLogger


DEFAULT_OUTPUT = Path("packet_logs/wifi_packets.csv")
MAX_VISIBLE_ROWS = 20


class LivePacketMonitor:
    """Coordinate packet sniffing, analysis, logging, and terminal output."""

    def __init__(
        self,
        interface: str,
        output_path: str | Path,
        deauth_threshold: int,
        unknown_mac_threshold: int,
        window_seconds: int,
    ) -> None:
        self.interface = interface
        self.stop_requested = False
        self.analyzer = PacketAnalyzer(
            deauth_threshold=deauth_threshold,
            unknown_mac_threshold=unknown_mac_threshold,
            window_seconds=window_seconds,
        )
        self.logger = PacketCSVLogger(output_path)
        self.recent_packets: Deque[PacketAnalysis] = deque(maxlen=MAX_VISIBLE_ROWS)

    def start(self) -> None:
        print(f"Starting live packet capture on {self.interface}. Press Ctrl+C to stop.")
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _packet: self.stop_requested,
        )

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_requested = True

    def _handle_packet(self, packet: Any) -> None:
        analysis = self.analyzer.analyze_packet(packet)
        if analysis is None:
            return

        self.logger.log_packet(analysis)
        self.recent_packets.append(analysis)
        self._print_live_table()

        if self.analyzer.is_deauth_attack_alert(analysis):
            print("\n[ALERT] Possible WiFi Deauthentication Attack Detected")

    def _print_live_table(self) -> None:
        headers = ["Timestamp", "Packet Type", "Source MAC", "Destination MAC", "Alert"]
        rows = [
            [
                analysis.timestamp,
                analysis.packet_type,
                analysis.source_mac,
                analysis.destination_mac,
                "Suspicious" if analysis.alert != "Normal" else "Normal",
            ]
            for analysis in self.recent_packets
        ]

        widths = [
            max(len(header), *(len(row[index]) for row in rows)) if rows else len(header)
            for index, header in enumerate(headers)
        ]

        print("\033c", end="")
        print("WiFi Real-Time Security and Signal Analyzer - Live Packet Capture")
        print(f"Interface: {self.interface}")
        print(self._separator(widths))
        print("| " + " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)) + " |")
        print(self._separator(widths))

        for row in rows:
            print("| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |")

        print(self._separator(widths))
        print(f"Packets shown: {len(rows)} | CSV logging active")

    @staticmethod
    def _separator(widths: list[int]) -> str:
        return "+-" + "-+-".join("-" * width for width in widths) + "-+"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live 802.11 packet sniffer for Kali Linux")
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Monitor-mode interface, for example wlan0mon.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"CSV log path. Default: {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--deauth-threshold",
        type=int,
        default=10,
        help="Number of deauthentication frames in the time window before raising an alert.",
    )
    parser.add_argument(
        "--unknown-mac-threshold",
        type=int,
        default=50,
        help="Packets from a non-BSSID source in the time window before raising an alert.",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=30,
        help="Detection time window in seconds.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    try:
        conf.verb = 0
        monitor = LivePacketMonitor(
            interface=args.interface,
            output_path=args.output,
            deauth_threshold=args.deauth_threshold,
            unknown_mac_threshold=args.unknown_mac_threshold,
            window_seconds=args.window_seconds,
        )
        signal.signal(signal.SIGINT, monitor.request_stop)
        signal.signal(signal.SIGTERM, monitor.request_stop)
        monitor.start()
    except PermissionError:
        print("Permission denied. Run with sudo/root privileges.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Interface error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

    print("\nPacket capture stopped. CSV log saved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
