# WiFi Real-Time Security and Signal Analyzer - Demo Steps

## 1. Go to project folder

```bash
cd ~/Projects/wifi_security_project
```

## 2. Clear old generated output

```bash
sudo rm -f scan_results/wifi_scan_results.csv
sudo rm -f packet_logs/wifi_packets.csv
sudo rm -f security_reports/security_report.csv
```

## 3. Enable monitor mode

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

If `wlan0` does not exist, check the interface name:

```bash
iwconfig
```

## 4. Run Module 1 - WiFi Scanner

```bash
sudo python3 scanner/wifi_scanner.py --interface wlan0mon --no-monitor-setup
```

This scans nearby WiFi networks channel by channel and saves results to:

```text
scan_results/wifi_scan_results.csv
```

## 5. Run Module 2 - Live Packet Capture

```bash
sudo python3 packet_capture/packet_sniffer.py --interface wlan0mon
```

Let it run for 1-2 minutes, then stop using `Ctrl + C`.

This saves packet logs to:

```text
packet_logs/wifi_packets.csv
```

## 6. Run Module 3 - Security Dashboard

```bash
python3 -m security_dashboard.dashboard
```

The dashboard displays:

* SSID
* Device Type
* Vendor
* Encryption
* Packet Count
* Threat Detected
* Security Level


## 7. Run Module 4 - Final Security Report Generator

```bash
python3 report_generator/security_report_generator.py

## 8. Stop monitor mode after demo
```bash
sudo airmon-ng stop wlan0mon
sudo service NetworkManager restart
```

## Demo Explanation

This project scans nearby WiFi networks, captures live wireless packets, analyzes possible suspicious activity, identifies device vendors using an offline IEEE OUI database, and displays the security status in a dashboard.
