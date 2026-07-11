# WiFi Real-Time Security and Signal Analyzer - Final Demo Steps

## 1. Go to project folder

cd ~/Projects/wifi_security_project

## 2. Clear old generated output

sudo rm -f scan_results/wifi_scan_results.csv
sudo rm -f packet_logs/wifi_packets.csv
sudo rm -f security_reports/security_report.csv
sudo rm -f security_reports/final_security_report.csv
sudo rm -f security_reports/security_advisor_report.txt
sudo rm -f security_reports/security_advisor_report.json
sudo rm -f security_reports/historical_trend_report.txt
sudo rm -f security_reports/historical_trend_report.json
sudo rm -f security_reports/alert_notifications.log
sudo rm -f security_reports/alert_notifications.json

## 3. Enable monitor mode

sudo airmon-ng check kill
sudo airmon-ng start wlan0

Check interface:

iwconfig

Usually the monitor interface will be wlan0mon.

## 4. Run Module 1 - WiFi Scanner

sudo python3 scanner/wifi_scanner.py --interface wlan0mon --no-monitor-setup

Output:
scan_results/wifi_scan_results.csv

## 5. Run Module 2 - Live Packet Capture

sudo python3 packet_capture/packet_sniffer.py --interface wlan0mon

Let it run for 1-2 minutes, then stop using Ctrl + C.

Output:
packet_logs/wifi_packets.csv

## 6. Run Module 3 - Security Dashboard

python3 -m security_dashboard.dashboard

This shows SSID, device type, vendor, encryption, packet count, threat status, and security level.

## 7. Run Module 4 - Final Security Report Generator

python3 report_generator/security_report_generator.py

Output:
security_reports/final_security_report.csv

## 8. Run Module 5 - Rogue AP and Evil Twin Detection

python3 evil_twin_detection/evil_twin_detector.py

This updates the final report with Attack_Type.

## 9. Run Module 6 - Real-Time Security Monitor

sudo python3 real_time_monitor/real_time_monitor.py --once --scanner-interface wlan0mon --scanner-no-monitor-setup --packet-interface wlan0mon --scan-timeout 35 --packet-timeout 20

## 10. Run Module 7 - Security Advisor

python3 security_advisor/security_advisor.py

Outputs:
security_reports/security_advisor_report.txt
security_reports/security_advisor_report.json

## 11. Run Module 8 - Historical Trend Engine

python3 historical_trends/historical_trend_engine.py

Outputs:
security_reports/history.db
security_reports/historical_trend_report.txt
security_reports/historical_trend_report.json

## 12. Run Module 9 - Alert Notification System

python3 alert_notification/alert_notification_system.py --no-color

Outputs:
security_reports/alert_notifications.log
security_reports/alert_notifications.json

## 13. Stop monitor mode after demo

sudo airmon-ng stop wlan0mon
sudo service NetworkManager restart

## Final Demo Explanation

This project scans nearby WiFi networks, captures live wireless packets, analyzes suspicious activity, identifies device vendors, generates final reports, detects possible rogue AP and Evil Twin indicators, provides real-time monitoring, gives security recommendations, stores historical trends, and creates alert notifications.

## Important Note for Explanation

Possible rogue AP and Evil Twin alerts are investigation indicators. They are based on unknown BSSIDs, duplicate SSIDs, packet behavior, and risk scores. They are not final proof of an attack.
## Unified NetShield Backend Pipeline

The complete backend workflow can be executed using one command:

```bash
python3 netshield_pipeline.py --send-email

