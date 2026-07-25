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



## Final Additional Modules

### Module 5: Rogue AP and Evil Twin Detection

Main file:

```bash
evil_twin_detection/evil_twin_detector.py
```

Detects possible rogue access points and Evil Twin indicators. It updates the final security report with `Attack_Type`.

### Module 6: Real-Time Security Monitor

Main file:

```bash
real_time_monitor/real_time_monitor.py
```

Runs the main real-time pipeline:

```text
Module 1 → Module 2 → Module 4 → Module 5 → Module 6
```

### Module 7: Security Advisor

Main file:

```bash
security_advisor/security_advisor.py
```

Generates security explanations and recommendations.

Output files:

```text
security_reports/security_advisor_report.txt
security_reports/security_advisor_report.json
```

### Module 8: Historical Trend Engine

Main file:

```bash
historical_trends/historical_trend_engine.py
```

Stores scan history in SQLite and compares current scan results with previous scans.

Output files:

```text
security_reports/history.db
security_reports/historical_trend_report.txt
security_reports/historical_trend_report.json
```

### Module 9: Alert Notification System

Main file:

```bash
alert_notification/alert_notification_system.py
```

Generates alert notifications with severity levels.

Output files:

```text
security_reports/alert_notifications.log
security_reports/alert_notifications.json
```

## Final Project Pipeline

```text
WiFi Scan
→ Packet Capture
→ Security Dashboard
→ Final Report
→ Rogue AP / Evil Twin Detection
→ Real-Time Monitor
→ Security Advisor
→ Historical Trend Analysis
→ Alert Notification System
```

## Important Demo Note

Some alerts are marked as possible rogue AP or possible Evil Twin based on suspicious indicators such as unknown BSSIDs, duplicate SSIDs, packet differences, and risk scores. These alerts are investigation indicators, not final proof of an attack.

## Web Dashboard Scanner Control

The React Dashboard can start and stop the WiFi scanner through the Flask API.

For security, Flask runs as the normal user. Root-required wireless scanning is handled by the protected systemd service:

```text
netshield-scanner.service
```

### Install the scanner service

From the project root:

```bash
chmod +x deployment/install_scanner_service.sh
./deployment/install_scanner_service.sh
```

The installer:

- Copies the scanner into `/opt/netshield-scanner/`.
- Creates a dedicated Python environment.
- Installs Scapy.
- Creates the NetShield systemd service.
- Gives the current user permission to control only that service.
- Does not enable scanning automatically at startup.

### Confirm the adapter

Attach the USB WiFi adapter to the Kali virtual machine:

```bash
lsusb
iw dev
```

The expected interface is:

```text
Interface wlan0
type managed
```

### Start the Flask backend

```bash
cd ~/Projects/wifi_security_project
source .venv/bin/activate
python api/app.py
```

### Start the React frontend

In another terminal:

```bash
cd ~/Projects/wifi_security_project/frontend
npm run dev
```

Open:

```text
http://localhost:5173
```

Go to the Dashboard and use **Start Scan** or **Stop Scan**.

During scanning, the adapter temporarily changes from `wlan0` in managed mode to `wlan0mon` in monitor mode. When scanning stops, NetShield saves the latest CSV and restores `wlan0` automatically.

### Scanner API routes

```text
GET  /api/scanner/status
POST /api/scanner/start
POST /api/scanner/stop
```

Example Start Scan request:

```json
{
  "interface": "wlan0"
}
```

## Ethical Use

Use NetShield only on wireless networks and environments that you own or have explicit permission to assess. Automated findings are investigation indicators and are not final proof of an attack.
