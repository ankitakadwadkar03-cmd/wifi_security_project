# WiFi Real-Time Security and Signal Analyzer

A Kali Linux based WiFi security analysis project that scans nearby wireless networks, captures live WiFi packets, analyzes suspicious activity, identifies device vendors using an offline IEEE OUI database, and generates a final security report.

## Project Purpose

The purpose of this project is to help users understand the security status of nearby WiFi networks. It detects available WiFi access points, captures wireless traffic, identifies encryption type, analyzes packet activity, detects suspicious behavior, and displays the results in a terminal-based dashboard and final report.

## Main Features

* Scans nearby WiFi networks using a monitor-mode supported USB WiFi adapter.
* Performs channel-by-channel scanning for better network discovery.
* Detects SSID, BSSID, channel, frequency, signal strength, and encryption type.
* Captures live WiFi packets.
* Detects beacon, data, probe, and suspicious packet activity.
* Displays packet count and threat status for each network.
* Identifies device vendors using an offline IEEE OUI database.
* Classifies devices as Access Point or Unknown Device.
* Displays security level as SAFE, WARNING, or DANGER.
* Generates a final consolidated security report.

## Modules

### Module 1: WiFi Scanner

Location:

```text
scanner/
```

Main file:

```bash
scanner/wifi_scanner.py
```

This module scans nearby WiFi networks using a monitor-mode wireless adapter. It performs channel-by-channel scanning and saves detected networks to:

```text
scan_results/wifi_scan_results.csv
```

### Module 2: Live Packet Capture

Location:

```text
packet_capture/
```

Main file:

```bash
packet_capture/packet_sniffer.py
```

This module captures live WiFi packets and logs packet details such as packet type, source MAC, destination MAC, BSSID, signal strength, and alert status.

Output file:

```text
packet_logs/wifi_packets.csv
```

### Module 3: Security Dashboard

Location:

```text
security_dashboard/
```

Main file:

```bash
security_dashboard/dashboard.py
```

This module reads scan results and packet logs, analyzes threats, and displays a terminal dashboard with:

* SSID
* Device Type
* Vendor
* Encryption
* Packet Count
* Threat Detected
* Security Level

### Module 4: Final Security Report Generator

Location:

```text
report_generator/
```

Main file:

```bash
report_generator/security_report_generator.py
```

This module generates a final consolidated security report using scan data and packet logs.

Output file:

```text
security_reports/final_security_report.csv
```

### Vendor Lookup

Location:

```text
vendor_lookup/
```

The project uses an offline IEEE OUI database to identify device vendors from MAC address prefixes.

Example:

```text
MAC Address: 14:A7:2B:D0:EF:16
OUI Prefix : 14:A7:2B
Vendor     : currentoptronics Pvt.Ltd
```

## Folder Structure

```text
wifi_security_project/
├── scanner/
│   ├── wifi_scanner.py
│   ├── network_parser.py
│   └── csv_logger.py
├── packet_capture/
│   ├── packet_sniffer.py
│   ├── packet_logger.py
│   └── packet_analyzer.py
├── security_dashboard/
│   ├── dashboard.py
│   ├── security_score.py
│   └── threat_detector.py
├── report_generator/
│   └── security_report_generator.py
├── vendor_lookup/
│   ├── __init__.py
│   ├── vendor_lookup.py
│   └── oui.csv
├── README.md
├── DEMO_STEPS.md
├── PROJECT_NOTES.txt
└── requirements.txt
```

## Requirements

### Hardware

* Laptop running Kali Linux
* USB WiFi adapter that supports monitor mode
* Example adapter used: Qualcomm Atheros AR9271

### Software

Install required tools:

```bash
sudo apt update
sudo apt install -y aircrack-ng wireless-tools python3 python3-pip
```

Install Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## How to Run

### 1. Go to project folder

```bash
cd ~/Projects/wifi_security_project
```

### 2. Clear old generated output

```bash
sudo rm -f scan_results/wifi_scan_results.csv
sudo rm -f packet_logs/wifi_packets.csv
sudo rm -f security_reports/security_report.csv
sudo rm -f security_reports/final_security_report.csv
```

### 3. Enable monitor mode

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

Check interface:

```bash
iwconfig
```

The monitor interface should usually be:

```text
wlan0mon
```

### 4. Run Module 1 - WiFi Scanner

```bash
sudo python3 scanner/wifi_scanner.py --interface wlan0mon --no-monitor-setup
```

### 5. Run Module 2 - Live Packet Capture

```bash
sudo python3 packet_capture/packet_sniffer.py --interface wlan0mon
```

Let it run for 1-2 minutes, then stop using:

```text
Ctrl + C
```

### 6. Run Module 3 - Security Dashboard

```bash
python3 -m security_dashboard.dashboard
```

### 7. Run Module 4 - Final Security Report Generator

```bash
python3 report_generator/security_report_generator.py
```

### 8. Stop monitor mode

```bash
sudo airmon-ng stop wlan0mon
sudo service NetworkManager restart
```

## Output Files

```text
scan_results/wifi_scan_results.csv
packet_logs/wifi_packets.csv
security_reports/security_report.csv
security_reports/final_security_report.csv
```

## Demo Explanation

This project works in four stages. First, it scans nearby WiFi networks using monitor mode. Then it captures live packets from the wireless environment. Next, it analyzes the scan and packet data to detect suspicious behavior and displays the results in a security dashboard. Finally, it generates a consolidated security report with security score and risk level.

## Notes

* Use this project only in environments where you have permission to monitor wireless traffic.
* The WiFi adapter must support monitor mode.
* Packet count depends on live traffic captured during monitoring.
* Some networks may show packet count 0 if they were detected by scanning but no live data packets were captured from them.
* Vendor lookup is based on MAC address OUI prefix and may identify the manufacturer, not the exact device model.
* WPA3 detection is best effort because some routers use mixed WPA2/WPA3 transition modes.
