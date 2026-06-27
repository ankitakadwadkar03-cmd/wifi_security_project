# WiFi Real-Time Security and Signal Analyzer

Module 1 implements a real-time WiFi Network Scanner for Kali Linux.

## Features

- Detects nearby WiFi networks using a monitor-mode wireless adapter.
- Displays SSID, BSSID, channel, frequency, signal strength, and encryption type.
- Detects Open, WEP, WPA, WPA2, and best-effort WPA3 from beacon/probe-response frames.
- Refreshes scan results every 5 seconds.
- Stores scan results in a Python dictionary during execution.
- Saves the latest scan snapshot automatically to CSV.
- Prints live terminal output in table format.

## Folder Structure

```text
wifi_security_project/
    README.md
    requirements.txt
    scanner/
        wifi_scanner.py
        network_parser.py
        csv_logger.py
```

## Kali Linux Setup

Install system tools:

```bash
sudo apt update
sudo apt install -y aircrack-ng wireless-tools python3 python3-pip
```

Install Python dependency:

```bash
cd wifi_security_project
python3 -m pip install -r requirements.txt
```

Check your wireless adapter name:

```bash
iwconfig
```

Run the scanner:

```bash
sudo python3 scanner/wifi_scanner.py --interface wlan0
```

If your adapter is already in monitor mode:

```bash
sudo python3 scanner/wifi_scanner.py --interface wlan0mon --no-monitor-setup
```

The CSV file is saved by default at:

```text
scan_results/wifi_scan_results.csv
```

Use a custom CSV path:

```bash
sudo python3 scanner/wifi_scanner.py --interface wlan0 --output scan_results/lab_scan.csv
```

Stop the scanner with `Ctrl+C`.

## Notes

- Run only on networks and environments where you have permission to monitor wireless traffic.
- The adapter must support monitor mode.
- Signal strength depends on driver support for radiotap metadata.
- WPA3 detection is best effort because some access points expose mixed WPA2/WPA3 transition modes.
