import json
import os
import smtplib
from pathlib import Path
from datetime import datetime
from email.message import EmailMessage


INPUT_FILE = Path("security_reports/pre_connect_safety_report.json")
OUTPUT_TXT = Path("security_reports/email_alert_preview.txt")
OUTPUT_JSON = Path("security_reports/email_alert_preview.json")
ENV_FILE = Path(".env")


def load_env_file():
    config = {}

    if not ENV_FILE.exists():
        return config

    with ENV_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            config[key.strip()] = value.strip()

    return config


def get_config_value(config, key, default=""):
    return os.getenv(key, config.get(key, default))


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


def save_alert_json(alert_networks, message, email_status):
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
        "email_status": email_status,
    }

    with OUTPUT_JSON.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def save_alert_text(message):
    with OUTPUT_TXT.open("w", encoding="utf-8") as file:
        file.write(message)


def send_email_alert(config, subject, body):
    email_enabled = get_config_value(config, "NETSHIELD_EMAIL_ENABLED", "false").lower()

    if email_enabled != "true":
        return "DISABLED"

    smtp_server = get_config_value(config, "NETSHIELD_SMTP_SERVER")
    smtp_port = int(get_config_value(config, "NETSHIELD_SMTP_PORT", "587"))
    sender = get_config_value(config, "NETSHIELD_EMAIL_SENDER")
    password = get_config_value(config, "NETSHIELD_EMAIL_PASSWORD")
    receiver = get_config_value(config, "NETSHIELD_EMAIL_RECEIVER")

    missing_values = []

    if not smtp_server:
        missing_values.append("NETSHIELD_SMTP_SERVER")
    if not sender:
        missing_values.append("NETSHIELD_EMAIL_SENDER")
    if not password:
        missing_values.append("NETSHIELD_EMAIL_PASSWORD")
    if not receiver:
        missing_values.append("NETSHIELD_EMAIL_RECEIVER")

    if missing_values:
        return f"FAILED - Missing values: {', '.join(missing_values)}"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = receiver
    message.set_content(body)

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as server:
            server.starttls()
            server.login(sender, password)
            server.send_message(message)

        return "SENT"

    except Exception as error:
        return f"FAILED - {error}"


def main():
    config = load_env_file()

    report = load_safety_report()
    networks = report.get("networks", [])

    alert_networks = [network for network in networks if is_alert_required(network)]
    message = build_alert_message(alert_networks)

    subject = (
        "NetShield Security Alert - High Risk WiFi Detected"
        if alert_networks
        else "NetShield Security Alert - No High Risk WiFi Detected"
    )

    save_alert_text(message)

    email_status = "NOT_REQUIRED"

    if alert_networks:
        email_status = send_email_alert(config, subject, message)

    save_alert_json(alert_networks, message, email_status)

    print("\nEmail Alert System Completed")
    print("----------------------------")
    print(f"Alert Required : {'YES' if alert_networks else 'NO'}")
    print(f"Total Alerts   : {len(alert_networks)}")
    print(f"Email Status   : {email_status}")
    print(f"[OK] Text saved to : {OUTPUT_TXT}")
    print(f"[OK] JSON saved to : {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
