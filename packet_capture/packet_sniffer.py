"""Live 802.11 packet capture for Kali Linux monitor-mode interfaces.

Run:
    sudo python3 packet_capture/packet_sniffer.py --interface wlan0mon
"""

from __future__ import annotations

import argparse
import json
import shutil
import signal
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque

from scapy.all import conf, sniff

from packet_analyzer import PacketAnalysis, PacketAnalyzer
from packet_logger import PacketCSVLogger


DEFAULT_OUTPUT = Path("packet_logs/wifi_packets.csv")
MAX_VISIBLE_ROWS = 20
STATUS_WRITE_INTERVAL_SECONDS = 1.0


def _run_command(
    command: list[str],
    check: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _require_command(command_name: str) -> None:
    if shutil.which(command_name) is None:
        raise RuntimeError(
            f"Required command not found: {command_name}"
        )


def _interface_exists(interface: str) -> bool:
    try:
        _run_command(["iwconfig", interface])
        return True
    except subprocess.CalledProcessError:
        return False


def _parse_monitor_interface(
    airmon_output: str,
    interface: str,
) -> str:
    for line in airmon_output.splitlines():
        lowered_line = line.lower()

        if "monitor mode" in lowered_line and "enabled" in lowered_line:
            tokens = (
                line.replace(")", " ")
                .replace("(", " ")
                .split()
            )

            for token in reversed(tokens):
                if token.startswith(interface) and token != interface:
                    return token

    candidate = f"{interface}mon"

    if _interface_exists(candidate):
        return candidate

    return interface


def _verify_monitor_mode(interface: str) -> None:
    try:
        result = _run_command(["iwconfig", interface])
    except subprocess.CalledProcessError as command_error:
        raise RuntimeError(
            f"Could not verify interface {interface}: "
            f"{command_error.stderr.strip()}"
        ) from command_error

    normalized_output = result.stdout.lower().replace(" ", "")

    if "mode:monitor" not in normalized_output:
        raise RuntimeError(
            f"Interface {interface} is not in monitor mode."
        )


def enable_monitor_mode(interface: str) -> str:
    """Enable monitor mode and return the monitor interface name."""
    for command_name in ("iwconfig", "airmon-ng"):
        _require_command(command_name)

    _run_command(
        ["airmon-ng", "check", "kill"],
        check=False,
    )

    try:
        result = _run_command(
            ["airmon-ng", "start", interface]
        )
    except subprocess.CalledProcessError as command_error:
        details = (
            command_error.stderr.strip()
            or command_error.stdout.strip()
        )

        raise RuntimeError(
            f"Could not enable monitor mode for {interface}: {details}"
        ) from command_error

    monitor_interface = _parse_monitor_interface(
        result.stdout,
        interface,
    )
    _verify_monitor_mode(monitor_interface)

    return monitor_interface


def restore_managed_mode(interface: str) -> None:
    """Disable monitor mode and restart normal WiFi services."""
    try:
        result = _run_command(
            ["airmon-ng", "stop", interface],
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        print(
            f"Warning: restoring {interface} timed out after 15 seconds.",
            file=sys.stderr,
        )
    else:
        if result.returncode != 0:
            details = result.stderr.strip() or result.stdout.strip()
            print(
                f"Warning: could not restore {interface}: {details}",
                file=sys.stderr,
            )

    for service_name in ("NetworkManager", "wpa_supplicant"):
        try:
            _run_command(
                ["systemctl", "start", service_name],
                check=False,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            print(
                f"Warning: starting {service_name} timed out.",
                file=sys.stderr,
            )


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
        self.output_path = Path(output_path)
        self.logger = PacketCSVLogger(self.output_path)
        self.status_path = (
            self.output_path.parent / "capture_status.json"
        )
        self.recent_packets: Deque[PacketAnalysis] = deque(
            maxlen=MAX_VISIBLE_ROWS
        )
        self.packet_count = 0
        self.started_at = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.last_packet_at: str | None = None
        self._last_status_write = 0.0

    def start(self) -> None:
        print(
            f"Starting live packet capture on {self.interface}. "
            "Press Ctrl+C to stop."
        )

        self._write_runtime_status(
            state="capturing",
            force=True,
        )

        while not self.stop_requested:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                timeout=1,
            )

            self._write_runtime_status(
                state="capturing",
            )

        self._write_runtime_status(
            state="stopping",
            force=True,
        )

    def request_stop(self, _signum: int, _frame: Any) -> None:
        self.stop_requested = True

    def _write_runtime_status(
        self,
        state: str,
        force: bool = False,
    ) -> None:
        """Atomically save lightweight live capture progress."""
        now_monotonic = time.monotonic()

        if (
            not force
            and (
                now_monotonic - self._last_status_write
                < STATUS_WRITE_INTERVAL_SECONDS
            )
        ):
            return

        self.status_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        payload = {
            "state": state,
            "interface": self.interface,
            "packet_count": self.packet_count,
            "started_at": self.started_at,
            "last_packet_at": self.last_packet_at,
            "updated_at": time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }

        temporary_path = self.status_path.with_suffix(
            self.status_path.suffix + ".tmp"
        )

        temporary_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

        temporary_path.replace(self.status_path)
        self._last_status_write = now_monotonic

    def _handle_packet(self, packet: Any) -> None:
        analysis = self.analyzer.analyze_packet(packet)
        if analysis is None:
            return

        self.logger.log_packet(analysis)

        self.packet_count += 1
        self.last_packet_at = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        self._write_runtime_status(
            state="capturing",
        )

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
    parser = argparse.ArgumentParser(
        description="Live 802.11 packet sniffer for Kali Linux"
    )
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help=(
            "Wireless interface, for example wlan0. "
            "Monitor mode is enabled automatically."
        ),
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
        help=(
            "Number of deauthentication frames in the time window "
            "before raising an alert."
        ),
    )
    parser.add_argument(
        "--unknown-mac-threshold",
        type=int,
        default=50,
        help=(
            "Packets from a non-BSSID source in the time window "
            "before raising an alert."
        ),
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=30,
        help="Detection time window in seconds.",
    )
    parser.add_argument(
        "--no-monitor-setup",
        action="store_true",
        help=(
            "Skip monitor-mode setup when the provided interface "
            "is already in monitor mode."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    monitor_interface = args.interface
    monitor_mode_created = False

    try:
        conf.verb = 0

        if not args.no_monitor_setup:
            monitor_interface = enable_monitor_mode(args.interface)
            monitor_mode_created = True

        monitor = LivePacketMonitor(
            interface=monitor_interface,
            output_path=args.output,
            deauth_threshold=args.deauth_threshold,
            unknown_mac_threshold=args.unknown_mac_threshold,
            window_seconds=args.window_seconds,
        )
        signal.signal(signal.SIGINT, monitor.request_stop)
        signal.signal(signal.SIGTERM, monitor.request_stop)
        monitor.start()
    except PermissionError:
        print(
            "Permission denied. Run with sudo/root privileges.",
            file=sys.stderr,
        )
        return 1
    except RuntimeError as exc:
        print(f"Monitor-mode error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Interface error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1
    finally:
        if monitor_mode_created:
            print(
                f"Restoring {monitor_interface} to managed mode..."
            )
            restore_managed_mode(monitor_interface)

    print("\nPacket capture stopped. CSV log saved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
