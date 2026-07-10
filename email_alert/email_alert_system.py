import json
from pathlib import Path
from datetime import datetime


INPUT_FILE = Path("security_reports/pre_connect_safety_report.json")
OUTPUT_TXT = Path("security_reports/email_alert_preview.txt")
OUTPUT_JSON = Path("security_reports/email_alert_preview.json")


def load_safety_report():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}. Run pre_connect_advisor.py first."
        )

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def is_alert_required(network):
    verdict = network.get("Safety_Verdict", "").upper()
    risk_level = network.get("Risk_Level", "").upper()
    recommendation = network.get("Connect_Recommendation", "")

    return (
        verdict in ["POSSIBLE_EVIL_TWIN", "WEAK_SECURITY", "AVOID_THIS_NETWORK"]
        or risk_level == "HIGH"
        or recommendation == "Avoid This Network"
    )


def build_alert_message(alert_networks):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("NetShield Security Alert")
    lines.append("========================")
    lines.append(f"Generated At: {generated_at}")
    lines.append("")

    if not alert_networks:
        lines.append("No high-risk WiFi networks were detected.")
        lines.append("No email alert is required at this time.")
        return "\n".join(lines)

    lines.append(f"High-Risk Networks Detected: {len(alert_networks)}")
    lines.append("")

    for index, network in enumerate(alert_networks, start=1):
        lines.append(f"Alert #{index}")
        lines.append("-" * 30)
        lines.append(f"SSID                  : {network.get('SSID', 'Unknown')}")
        lines.append(f"BSSID                 : {network.get('BSSID', 'Unknown')}")
        lines.append(f"Encryption            : {network.get('Encryption', 'Unknown')}")
        lines.append(f"Signal                : {network.get('Signal', 'Unknown')}")
        lines.append(f"Safety Verdict        : {network.get('Safety_Verdict', 'Unknown')}")
        lines.append(f"Risk Level            : {network.get('Risk_Level', 'Unknown')}")
        lines.append(f"Risk Score            : {network.get('Risk_Score', 'Unknown')}")
        lines.append(f"Recommendation        : {network.get('Connect_Recommendation', 'Unknown')}")
        lines.append("")
        lines.append("Reason:")
        lines.append(network.get("Reason", "No reason available."))
        lines.append("")
        lines.append("Advice:")
        lines.append(network.get("Advice", "No advice available."))
        lines.append("")

    lines.append("Action Required:")
    lines.append("Review the detected high-risk WiFi network before allowing users to connect.")

    return "\n".join(lines)


def save_alert_json(alert_networks, message):
    data = {
        "module": "Email Alert System",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "alert_required": bool(alert_networks),
        "total_alerts": len(alert_networks),
        "alert_networks": alert_networks,
        "email_subject": "NetShield Security Alert - High Risk WiFi Detected"
        if alert_networks
        else "NetShield Security Alert - No High Risk WiFi Detected",
        "email_body": message,
    }

    with OUTPUT_JSON.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def save_alert_text(message):
    with OUTPUT_TXT.open("w", encoding="utf-8") as file:
        file.write(message)


def main():
    report = load_safety_report()
    networks = report.get("networks", [])

    alert_networks = [network for network in networks if is_alert_required(network)]
    message = build_alert_message(alert_networks)

    save_alert_text(message)
    save_alert_json(alert_networks, message)

    print("\nEmail Alert Preview Generated")
    print("-----------------------------")
    print(f"Alert Required : {'YES' if alert_networks else 'NO'}")
    print(f"Total Alerts   : {len(alert_networks)}")
    print(f"[OK] Text saved to : {OUTPUT_TXT}")
    print(f"[OK] JSON saved to : {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
