import argparse
import csv
import hashlib
import json
from pathlib import Path
from datetime import datetime


DEFAULT_INPUT_REPORT = Path(
    "security_reports/trusted_baseline_report.csv"
)

DEFAULT_OUTPUT_CSV = Path(
    "security_reports/pre_connect_safety_report.csv"
)

DEFAULT_OUTPUT_JSON = Path(
    "security_reports/pre_connect_safety_report.json"
)

CURRENT_PRE_CONNECT_VERSION = "baseline-aware-v2"


def calculate_sha256(path):
    """Return SHA-256 for the Trusted Baseline source report."""

    path = Path(path)

    if (
        not path.is_file()
        or path.stat().st_size == 0
    ):
        return None

    digest = hashlib.sha256()

    with path.open("rb") as source_file:
        for chunk in iter(
            lambda: source_file.read(65536),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def clean(value):
    return str(value).strip() if value is not None else ""


def get_signal_value(signal_text):
    try:
        return int(str(signal_text).replace("dBm", "").strip())
    except ValueError:
        return None


def is_weak_encryption(encryption):
    encryption = clean(encryption).upper()

    if encryption in ["", "OPEN", "NONE", "NO ENCRYPTION"]:
        return True

    if "WEP" in encryption:
        return True

    return False


def build_reason_and_advice(row):
    ssid = clean(row.get("SSID"))
    bssid = clean(row.get("BSSID"))
    encryption = clean(row.get("Encryption"))
    baseline_status = clean(row.get("Baseline_Status")).upper()
    threat_type = clean(row.get("Threat_Type")).upper()
    severity = clean(row.get("Severity")).upper()
    confidence = clean(row.get("Confidence"))

    signal_value = get_signal_value(row.get("Signal"))

    reasons = []
    advice = []

    verdict = "USE_WITH_CAUTION"
    risk_level = "MEDIUM"
    risk_score = 55

    if (
        "POSSIBLE_EVIL_TWIN" in threat_type
        or baseline_status == "SSID_MATCH_BSSID_MISMATCH"
    ):
        verdict = "POSSIBLE_EVIL_TWIN"
        risk_level = "HIGH"
        risk_score = 90

        reasons.append(
            "SSID matches a trusted network, but the detected BSSID does not match the trusted baseline."
        )
        reasons.append(
            "This may indicate a fake access point using the same WiFi name."
        )

        advice.append("Avoid connecting until the router identity is manually verified.")
        advice.append("Compare the detected BSSID with the physical router MAC address.")

    elif is_weak_encryption(encryption):
        verdict = "WEAK_SECURITY"
        risk_level = "HIGH"
        risk_score = 85

        reasons.append(
            "The network is using open, missing, or weak encryption."
        )

        advice.append("Avoid entering passwords or sensitive information on this network.")
        advice.append("Use a trusted WPA2/WPA3 secured network instead.")

    elif baseline_status == "TRUSTED":
        verdict = "SAFE_TO_CONNECT"
        risk_level = "LOW"
        risk_score = 15

        reasons.append(
            "The network BSSID matches the trusted baseline."
        )
        reasons.append(
            "No major risk indicators were detected from the current scan."
        )

        advice.append("Safe to connect based on the current trusted baseline.")
        advice.append("Continue monitoring for unusual changes.")

    elif baseline_status == "NOT_IN_BASELINE":
        verdict = "UNKNOWN_NETWORK"
        risk_level = "MEDIUM"
        risk_score = 60

        reasons.append(
            "The network is not present in the trusted baseline."
        )
        reasons.append(
            "The ownership of this access point is not verified."
        )

        advice.append("Use this network with caution.")
        advice.append("Avoid sensitive activity unless the network owner is verified.")

    else:
        verdict = "USE_WITH_CAUTION"
        risk_level = severity if severity else "MEDIUM"
        risk_score = 55

        reasons.append(
            "The network could not be fully verified using the available baseline data."
        )

        advice.append("Use with caution and verify the network before connecting.")

    if signal_value is not None and signal_value >= -45 and verdict in [
        "UNKNOWN_NETWORK",
        "POSSIBLE_EVIL_TWIN",
        "USE_WITH_CAUTION",
    ]:
        reasons.append(
            "The signal strength is unusually strong for a network that is not fully trusted."
        )
        advice.append(
            "Be careful of nearby fake hotspot attempts with strong signal strength."
        )

    connect_recommendation = {
        "SAFE_TO_CONNECT": "Safe to Connect",
        "USE_WITH_CAUTION": "Use With Caution",
        "AVOID_THIS_NETWORK": "Avoid This Network",
        "POSSIBLE_EVIL_TWIN": "Avoid This Network",
        "WEAK_SECURITY": "Avoid This Network",
        "UNKNOWN_NETWORK": "Use With Caution",
    }.get(verdict, "Use With Caution")

    return {
        "SSID": ssid,
        "BSSID": bssid,
        "Encryption": encryption,
        "Signal": clean(row.get("Signal")),
        "Baseline_Status": baseline_status,
        "Threat_Type": threat_type,
        "Severity": severity,
        "Confidence": confidence,
        "Safety_Verdict": verdict,
        "Risk_Level": risk_level,
        "Risk_Score": risk_score,
        "Connect_Recommendation": connect_recommendation,
        "Reason": " ".join(reasons),
        "Advice": " ".join(advice),
    }


def read_input_rows(input_report):
    input_report = Path(input_report)

    if not input_report.exists():
        raise FileNotFoundError(
            f"Input file not found: {input_report}. "
            "Run trusted_baseline_checker.py first."
        )

    with input_report.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as file:
        reader = csv.DictReader(file)
        return list(reader)


def write_csv(output_csv, rows):
    output_csv = Path(output_csv)
    output_csv.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "SSID",
        "BSSID",
        "Encryption",
        "Signal",
        "Baseline_Status",
        "Threat_Type",
        "Severity",
        "Confidence",
        "Safety_Verdict",
        "Risk_Level",
        "Risk_Score",
        "Connect_Recommendation",
        "Reason",
        "Advice",
    ]

    with output_csv.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)


def write_json(
    output_json,
    rows,
    source_report_sha256,
):
    output_json = Path(output_json)
    output_json.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_networks": len(rows),
        "safe_to_connect": sum(1 for row in rows if row["Safety_Verdict"] == "SAFE_TO_CONNECT"),
        "use_with_caution": sum(1 for row in rows if row["Connect_Recommendation"] == "Use With Caution"),
        "avoid_this_network": sum(1 for row in rows if row["Connect_Recommendation"] == "Avoid This Network"),
        "possible_evil_twin": sum(1 for row in rows if row["Safety_Verdict"] == "POSSIBLE_EVIL_TWIN"),
        "weak_security": sum(1 for row in rows if row["Safety_Verdict"] == "WEAK_SECURITY"),
        "unknown_network": sum(1 for row in rows if row["Safety_Verdict"] == "UNKNOWN_NETWORK"),
    }

    data = {
        "module": "Pre-Connect WiFi Safety Advisor",
        "analysis_version":
            CURRENT_PRE_CONNECT_VERSION,
        "generated_at":
            datetime.now().isoformat(
                timespec="seconds"
            ),
        "source_trusted_baseline_report_sha256":
            source_report_sha256,
        "summary": summary,
        "networks": rows,
    }

    with output_json.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=4,
        )


def print_summary(
    rows,
    output_csv,
    output_json,
):
    print("\nPre-Connect WiFi Safety Advisor Completed")
    print("-----------------------------------------")
    print(f"Total Networks           : {len(rows)}")
    print(f"Safe to Connect          : {sum(1 for row in rows if row['Safety_Verdict'] == 'SAFE_TO_CONNECT')}")
    print(f"Use With Caution         : {sum(1 for row in rows if row['Connect_Recommendation'] == 'Use With Caution')}")
    print(f"Avoid This Network       : {sum(1 for row in rows if row['Connect_Recommendation'] == 'Avoid This Network')}")
    print(f"Possible Evil Twin       : {sum(1 for row in rows if row['Safety_Verdict'] == 'POSSIBLE_EVIL_TWIN')}")
    print(f"Weak Security            : {sum(1 for row in rows if row['Safety_Verdict'] == 'WEAK_SECURITY')}")
    print(f"Unknown Networks         : {sum(1 for row in rows if row['Safety_Verdict'] == 'UNKNOWN_NETWORK')}")
    print()
    print(f"[OK] CSV report saved to  : {output_csv}")
    print(f"[OK] JSON report saved to : {output_json}")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Generate Pre-Connect WiFi safety "
            "recommendations from a Trusted Baseline report."
        )
    )

    parser.add_argument(
        "--input-report",
        default=str(DEFAULT_INPUT_REPORT),
        help="Path to trusted_baseline_report.csv",
    )

    parser.add_argument(
        "--output-csv",
        default=str(DEFAULT_OUTPUT_CSV),
        help="Path to Pre-Connect CSV output",
    )

    parser.add_argument(
        "--output-json",
        default=str(DEFAULT_OUTPUT_JSON),
        help="Path to Pre-Connect JSON output",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    input_report = Path(
        args.input_report
    )

    output_csv = Path(
        args.output_csv
    )

    output_json = Path(
        args.output_json
    )

    source_report_sha256 = (
        calculate_sha256(
            input_report
        )
    )

    if source_report_sha256 is None:
        raise RuntimeError(
            "Trusted Baseline source report "
            "could not be fingerprinted."
        )

    input_rows = read_input_rows(
        input_report
    )

    advisor_rows = [
        build_reason_and_advice(row)
        for row in input_rows
    ]

    write_csv(
        output_csv,
        advisor_rows,
    )

    write_json(
        output_json,
        advisor_rows,
        source_report_sha256,
    )

    print_summary(
        advisor_rows,
        output_csv,
        output_json,
    )


if __name__ == "__main__":
    main()
