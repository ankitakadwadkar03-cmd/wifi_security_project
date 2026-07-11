import argparse
import subprocess
import sys
from datetime import datetime


PIPELINE_STEPS = [
    ("Trusted Baseline Check", "trusted_baseline/trusted_baseline_checker.py"),
    ("Evidence Center", "evidence_center/evidence_center.py"),
    ("Analyst Review", "analyst_review/analyst_review.py"),
    ("Pre-Connect WiFi Safety Advisor", "pre_connect_advisor/pre_connect_advisor.py"),
]


def run_script(name, script_path):
    print()
    print(f"[RUNNING] {name}")
    print("-" * 55)

    result = subprocess.run([sys.executable, script_path])

    if result.returncode != 0:
        print(f"[FAILED] {name}")
        return False

    print(f"[COMPLETED] {name}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="NetShield backend security analysis pipeline"
    )

    parser.add_argument(
        "--send-email",
        action="store_true",
        help="Send email alert if high-risk WiFi networks are detected",
    )

    args = parser.parse_args()

    print()
    print("NetShield Backend Pipeline Started")
    print("==================================")
    print(f"Started At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    for name, script_path in PIPELINE_STEPS:
        success = run_script(name, script_path)

        if not success:
            print()
            print("Pipeline stopped because a required step failed.")
            sys.exit(1)

    if args.send_email:
        success = run_script("Email Alert System", "email_alert/email_alert_system.py")

        if not success:
            print()
            print("Pipeline completed, but email alert failed.")
            sys.exit(1)
    else:
        print()
        print("[SKIPPED] Email Alert System")
        print("Use --send-email to send email alerts.")

    print()
    print("NetShield Backend Pipeline Completed")
    print("====================================")


if __name__ == "__main__":
    main()
