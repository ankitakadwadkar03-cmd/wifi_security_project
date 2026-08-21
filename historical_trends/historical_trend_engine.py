"""Historical trend and comparison engine.

Module 8 for WiFi Real-Time Security and Signal Analyzer.

Reads:
    security_reports/final_security_report.csv

Writes:
    security_reports/history.db
    security_reports/historical_trend_report.txt
    security_reports/historical_trend_report.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_REPORT_CSV = Path("security_reports/final_security_report.csv")
DEFAULT_DATABASE = Path("security_reports/history.db")
DEFAULT_TEXT_REPORT = Path("security_reports/historical_trend_report.txt")
DEFAULT_JSON_REPORT = Path("security_reports/historical_trend_report.json")

CURRENT_HISTORY_VERSION = "baseline-aware-v2"
LEGACY_HISTORY_VERSION = "legacy-pre-baseline"

REQUIRED_COLUMNS = [
    "SSID",
    "BSSID",
    "Encryption",
    "Total_Packets",
    "Suspicious_Score",
    "Risk_Level",
    "Attack_Type",
]


def initialize_database(database_path: str | Path = DEFAULT_DATABASE) -> sqlite3.Connection:
    """Create the SQLite database and required tables if they do not exist."""

    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            scan_id INTEGER,
            scan_timestamp TEXT NOT NULL,
            ssid TEXT,
            bssid TEXT,
            encryption TEXT,
            packet_count INTEGER,
            security_score INTEGER,
            risk_level TEXT,
            attack_type TEXT
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS history_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_summary (
            scan_timestamp TEXT NOT NULL,
            total_networks INTEGER,
            safe_count INTEGER,
            low_risk_count INTEGER,
            warning_count INTEGER,
            danger_count INTEGER,
            rogue_count INTEGER,
            evil_twin_count INTEGER,
            suspicious_count INTEGER DEFAULT 0,
            weak_encryption_count INTEGER DEFAULT 0,
            unknown_network_count INTEGER DEFAULT 0,
            average_security_score REAL
        )
        """
    )
    existing_summary_columns = {
        row[1]
        for row in cursor.execute(
            "PRAGMA table_info(scan_summary)"
        ).fetchall()
    }

    stored_version_row = cursor.execute(
        """
        SELECT value
        FROM history_metadata
        WHERE key = 'analysis_version'
        """
    ).fetchone()

    if stored_version_row is None:
        existing_history_count = cursor.execute(
            "SELECT COUNT(*) FROM scan_history"
        ).fetchone()[0]

        detected_version = (
            LEGACY_HISTORY_VERSION
            if existing_history_count > 0
            else CURRENT_HISTORY_VERSION
        )

        cursor.execute(
            """
            INSERT INTO history_metadata (
                key,
                value
            )
            VALUES (
                'analysis_version',
                ?
            )
            """,
            (
                detected_version,
            ),
        )

    required_summary_columns = {
        "suspicious_count":
            "INTEGER DEFAULT 0",
        "weak_encryption_count":
            "INTEGER DEFAULT 0",
        "unknown_network_count":
            "INTEGER DEFAULT 0",
    }

    for column, definition in required_summary_columns.items():
        if column not in existing_summary_columns:
            cursor.execute(
                f"ALTER TABLE scan_summary "
                f"ADD COLUMN {column} {definition}"
            )

    connection.commit()
    return connection


def get_history_version(
    connection: sqlite3.Connection,
) -> str:
    """Return the analysis version associated with stored history."""

    row = connection.execute(
        """
        SELECT value
        FROM history_metadata
        WHERE key = 'analysis_version'
        """
    ).fetchone()

    if not row:
        return "unknown"

    return str(row[0]).strip() or "unknown"


def load_current_report(report_csv: str | Path = DEFAULT_REPORT_CSV) -> list[dict[str, str]]:
    """Load current security report rows safely."""

    path = Path(report_csv)
    if not path.exists():
        print(f"[WARNING] Security report not found: {path}")
        return []

    if path.stat().st_size == 0:
        print(f"[WARNING] Security report is empty: {path}")
        return []

    try:
        with path.open("r", newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            if reader.fieldnames is None:
                print(f"[WARNING] Security report has no headers: {path}")
                return []
            return [_normalize_report_row(row) for row in reader]
    except Exception as exc:
        print(f"[WARNING] Could not read security report {path}: {exc}")
        return []


def store_scan(connection: sqlite3.Connection, current_rows: list[dict[str, str]]) -> dict[str, Any]:
    """Append a new scan snapshot and summary into SQLite history."""

    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_id = _next_scan_id(connection)
    summary = _calculate_scan_summary(current_rows)
    cursor = connection.cursor()

    for row in current_rows:
        cursor.execute(
            """
            INSERT INTO scan_history (
                scan_id, scan_timestamp, ssid, bssid, encryption, packet_count,
                security_score, risk_level, attack_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                scan_timestamp,
                row["SSID"],
                row["BSSID"],
                row["Encryption"],
                _to_int(row["Total_Packets"]),
                _to_int(row["Suspicious_Score"], default=100),
                row["Risk_Level"],
                row["Attack_Type"],
            ),
        )

    cursor.execute(
        """
        INSERT INTO scan_summary (
            scan_timestamp, total_networks, safe_count, low_risk_count,
            warning_count, danger_count, rogue_count, evil_twin_count,
            suspicious_count, weak_encryption_count,
            unknown_network_count, average_security_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_timestamp,
            summary["total_networks"],
            summary["safe_count"],
            summary["low_risk_count"],
            summary["warning_count"],
            summary["danger_count"],
            summary["rogue_count"],
            summary["evil_twin_count"],
            summary["suspicious_count"],
            summary["weak_encryption_count"],
            summary["unknown_network_count"],
            summary["average_security_score"],
        ),
    )

    connection.commit()
    return {
        "scan_id": scan_id,
        "scan_timestamp": scan_timestamp,
        "summary": summary,
    }


def compare_history(
    connection: sqlite3.Connection,
    current_scan: dict[str, Any],
) -> dict[str, Any]:
    """Compare the current scan with the previous scan in history."""

    current_scan_id = current_scan["scan_id"]

    previous_scan_id = _previous_scan_id(
        connection,
        current_scan_id,
    )

    current_rows = _load_scan_rows(
        connection,
        current_scan_id,
    )

    previous_rows = (
        _load_scan_rows(
            connection,
            previous_scan_id,
        )
        if previous_scan_id
        else []
    )

    current_summary = current_scan["summary"]

    previous_summary = (
        _load_summary_by_scan_id(
            connection,
            previous_scan_id,
        )
        if previous_scan_id
        else None
    )

    current_bssids = {
        row["bssid"]
        for row in current_rows
    }

    previous_bssids = {
        row["bssid"]
        for row in previous_rows
    }

    previous_scores = {
        row["bssid"]: row["security_score"]
        for row in previous_rows
    }

    network_trends = []

    for row in current_rows:
        bssid = row["bssid"]

        if bssid not in previous_scores:
            trend = "NEW NETWORK"

        elif (
            row["security_score"]
            > previous_scores[bssid]
        ):
            trend = "IMPROVING"

        elif (
            row["security_score"]
            < previous_scores[bssid]
        ):
            trend = "DECLINING"

        else:
            trend = "STABLE"

        network_trends.append(
            {
                "ssid": row["ssid"],
                "bssid": bssid,
                "previous_score":
                    previous_scores.get(
                        bssid
                    ),
                "current_score":
                    row["security_score"],
                "trend": trend,
            }
        )

    if previous_summary is None:
        return {
            "has_previous_scan": False,
            "message": (
                "Historical comparison will begin "
                "from the next scan."
            ),
            "previous_scan_id": None,
            "current_scan_id":
                current_scan_id,
            "total_networks_difference": 0,
            "average_score_difference": 0,
            "rogue_count_difference": 0,
            "evil_twin_count_difference": 0,
            "suspicious_count_difference": 0,
            "weak_encryption_count_difference": 0,
            "unknown_network_count_difference": 0,
            "potential_findings_difference": 0,
            "warning_danger_difference": 0,
            "new_networks":
                sorted(current_bssids),
            "disappeared_networks": [],
            "network_trends":
                network_trends,
            "overall_trend": "STABLE",
        }

    current_warning_danger = (
        current_summary["warning_count"]
        + current_summary["danger_count"]
    )

    previous_warning_danger = (
        previous_summary["warning_count"]
        + previous_summary["danger_count"]
    )

    current_potential_findings = sum(
        current_summary[key]
        for key in (
            "rogue_count",
            "evil_twin_count",
            "suspicious_count",
            "weak_encryption_count",
            "unknown_network_count",
        )
    )

    previous_potential_findings = sum(
        previous_summary[key]
        for key in (
            "rogue_count",
            "evil_twin_count",
            "suspicious_count",
            "weak_encryption_count",
            "unknown_network_count",
        )
    )

    score_difference = round(
        current_summary[
            "average_security_score"
        ]
        - previous_summary[
            "average_security_score"
        ],
        2,
    )

    return {
        "has_previous_scan": True,
        "message": "",
        "previous_scan_id":
            previous_scan_id,
        "current_scan_id":
            current_scan_id,
        "total_networks_difference": (
            current_summary[
                "total_networks"
            ]
            - previous_summary[
                "total_networks"
            ]
        ),
        "average_score_difference":
            score_difference,
        "rogue_count_difference": (
            current_summary["rogue_count"]
            - previous_summary[
                "rogue_count"
            ]
        ),
        "evil_twin_count_difference": (
            current_summary[
                "evil_twin_count"
            ]
            - previous_summary[
                "evil_twin_count"
            ]
        ),
        "suspicious_count_difference": (
            current_summary[
                "suspicious_count"
            ]
            - previous_summary[
                "suspicious_count"
            ]
        ),
        "weak_encryption_count_difference": (
            current_summary[
                "weak_encryption_count"
            ]
            - previous_summary[
                "weak_encryption_count"
            ]
        ),
        "unknown_network_count_difference": (
            current_summary[
                "unknown_network_count"
            ]
            - previous_summary[
                "unknown_network_count"
            ]
        ),
        "potential_findings_difference": (
            current_potential_findings
            - previous_potential_findings
        ),
        "warning_danger_difference": (
            current_warning_danger
            - previous_warning_danger
        ),
        "new_networks": sorted(
            current_bssids
            - previous_bssids
        ),
        "disappeared_networks": sorted(
            previous_bssids
            - current_bssids
        ),
        "network_trends":
            network_trends,
        "overall_trend":
            _classify_overall_trend(
                score_difference,
                (
                    current_potential_findings
                    - previous_potential_findings
                ),
            ),
    }



def generate_statistics(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    """Generate statistics over all current-version historical scans."""

    cursor = connection.cursor()

    rows = cursor.execute(
        """
        SELECT
            scan_timestamp,
            ssid,
            bssid,
            security_score,
            attack_type
        FROM scan_history
        """
    ).fetchall()

    summaries = cursor.execute(
        """
        SELECT average_security_score
        FROM scan_summary
        """
    ).fetchall()

    attack_types = (
        "NORMAL",
        "ROGUE_AP",
        "EVIL_TWIN",
        "SUSPICIOUS",
        "WEAK_ENCRYPTION",
        "UNKNOWN_NETWORK",
    )

    if not rows:
        return {
            "most_frequently_detected_network":
                None,
            "most_frequent_finding":
                None,
            "most_frequent_rogue_ap":
                None,
            "most_frequent_evil_twin":
                None,
            "most_frequent_suspicious":
                None,
            "most_frequent_weak_encryption":
                None,
            "most_frequent_unknown_network":
                None,
            "highest_security_score_ever":
                None,
            "lowest_security_score_ever":
                None,
            "average_security_score": 0,
            "attack_type_counts": {
                attack_type: 0
                for attack_type
                in attack_types
            },
            "repeated_findings_by_type": {
                attack_type: 0
                for attack_type
                in attack_types
                if attack_type != "NORMAL"
            },
            "network_history": [],
        }

    bssid_counts = Counter(
        row[2]
        for row in rows
    )

    attack_type_counts = Counter(
        row[4]
        for row in rows
    )

    finding_counts = Counter(
        row[2]
        for row in rows
        if row[4] != "NORMAL"
    )

    rogue_counts = Counter(
        row[2]
        for row in rows
        if row[4] == "ROGUE_AP"
    )

    evil_twin_counts = Counter(
        row[2]
        for row in rows
        if row[4] == "EVIL_TWIN"
    )

    suspicious_counts = Counter(
        row[2]
        for row in rows
        if row[4] == "SUSPICIOUS"
    )

    weak_encryption_counts = Counter(
        row[2]
        for row in rows
        if row[4] == "WEAK_ENCRYPTION"
    )

    unknown_network_counts = Counter(
        row[2]
        for row in rows
        if row[4] == "UNKNOWN_NETWORK"
    )

    repeated_pairs = Counter(
        (
            row[2],
            row[4],
        )
        for row in rows
        if row[4] != "NORMAL"
    )

    repeated_findings_by_type = {
        attack_type: sum(
            1
            for (
                _bssid,
                stored_type,
            ), count
            in repeated_pairs.items()
            if (
                stored_type
                == attack_type
                and count > 1
            )
        )
        for attack_type
        in attack_types
        if attack_type != "NORMAL"
    }

    scores = [
        int(row[3])
        for row in rows
    ]

    summary_scores = (
        [
            float(row[0])
            for row in summaries
        ]
        if summaries
        else scores
    )

    return {
        "most_frequently_detected_network":
            _counter_top(
                bssid_counts
            ),
        "most_frequent_finding":
            _counter_top(
                finding_counts
            ),
        "most_frequent_rogue_ap":
            _counter_top(
                rogue_counts
            ),
        "most_frequent_evil_twin":
            _counter_top(
                evil_twin_counts
            ),
        "most_frequent_suspicious":
            _counter_top(
                suspicious_counts
            ),
        "most_frequent_weak_encryption":
            _counter_top(
                weak_encryption_counts
            ),
        "most_frequent_unknown_network":
            _counter_top(
                unknown_network_counts
            ),
        "highest_security_score_ever":
            max(scores),
        "lowest_security_score_ever":
            min(scores),
        "average_security_score":
            round(
                sum(summary_scores)
                / len(summary_scores),
                2,
            )
            if summary_scores
            else 0,
        "attack_type_counts": {
            attack_type:
                attack_type_counts.get(
                    attack_type,
                    0,
                )
            for attack_type
            in attack_types
        },
        "repeated_findings_by_type":
            repeated_findings_by_type,
        "network_history":
            _build_network_history(
                rows
            ),
    }



def generate_summary(
    current_scan: dict[str, Any],
    comparison: dict[str, Any],
    statistics: dict[str, Any],
) -> dict[str, Any]:
    """Build the complete trend report payload."""

    summary = current_scan["summary"]

    repeated = statistics[
        "repeated_findings_by_type"
    ]

    current_potential_findings = sum(
        summary[key]
        for key in (
            "rogue_count",
            "evil_twin_count",
            "suspicious_count",
            "weak_encryption_count",
            "unknown_network_count",
        )
    )

    return {
        "generated_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        "current_scan":
            current_scan,
        "comparison":
            comparison,
        "statistics":
            statistics,
        "executive_summary": {
            "current_scan_number":
                current_scan["scan_id"],
            "previous_scan_number":
                comparison[
                    "previous_scan_id"
                ],
            "average_security_score":
                summary[
                    "average_security_score"
                ],
            "trend":
                comparison[
                    "overall_trend"
                ],
            "potential_findings":
                current_potential_findings,
            "repeated_rogue_aps":
                repeated.get(
                    "ROGUE_AP",
                    0,
                ),
            "repeated_evil_twin_detections":
                repeated.get(
                    "EVIL_TWIN",
                    0,
                ),
            "repeated_suspicious_detections":
                repeated.get(
                    "SUSPICIOUS",
                    0,
                ),
            "repeated_weak_encryption_detections":
                repeated.get(
                    "WEAK_ENCRYPTION",
                    0,
                ),
            "repeated_unknown_network_detections":
                repeated.get(
                    "UNKNOWN_NETWORK",
                    0,
                ),
            "repeated_potential_findings":
                sum(
                    repeated.values()
                ),
            "new_networks":
                len(
                    comparison[
                        "new_networks"
                    ]
                ),
            "networks_disappeared":
                len(
                    comparison[
                        "disappeared_networks"
                    ]
                ),
        },
    }



def save_text_report(report: dict[str, Any], output_path: str | Path = DEFAULT_TEXT_REPORT) -> None:
    """Save the historical trend report as text."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_build_text_report(report), encoding="utf-8")


def save_json_report(report: dict[str, Any], output_path: str | Path = DEFAULT_JSON_REPORT) -> None:
    """Save the historical trend report as JSON."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=4), encoding="utf-8")


def print_summary(report: dict[str, Any]) -> None:
    """Print a professional trend comparison report."""

    print(_build_text_report(report))


def calculate_source_fingerprint(
    report_csv: str | Path,
) -> str | None:
    """Return SHA-256 for the exact threat report being recorded."""

    path = Path(report_csv)

    if not path.exists() or not path.is_file():
        return None

    digest = hashlib.sha256()

    try:
        with path.open("rb") as report_file:
            for chunk in iter(
                lambda: report_file.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)
    except OSError:
        return None

    return digest.hexdigest()


def get_last_source_fingerprint(
    connection: sqlite3.Connection,
) -> str | None:
    """Return the fingerprint of the last recorded threat report."""

    row = connection.execute(
        """
        SELECT value
        FROM history_metadata
        WHERE key = 'last_source_sha256'
        """
    ).fetchone()

    if not row:
        return None

    value = str(row[0]).strip()

    return value or None


def set_last_source_fingerprint(
    connection: sqlite3.Connection,
    fingerprint: str,
) -> None:
    """Remember which exact threat report produced the latest snapshot."""

    connection.execute(
        """
        INSERT INTO history_metadata (
            key,
            value
        )
        VALUES (
            'last_source_sha256',
            ?
        )
        ON CONFLICT(key)
        DO UPDATE SET
            value = excluded.value
        """,
        (
            fingerprint,
        ),
    )

    connection.commit()


def run_historical_trend_engine(
    report_csv: str | Path = DEFAULT_REPORT_CSV,
    database_path: str | Path = DEFAULT_DATABASE,
    text_output: str | Path = DEFAULT_TEXT_REPORT,
    json_output: str | Path = DEFAULT_JSON_REPORT,
) -> dict[str, Any]:
    connection = initialize_database(database_path)

    try:
        history_version = get_history_version(
            connection
        )

        if history_version != CURRENT_HISTORY_VERSION:
            print(
                "[WARNING] Historical database uses analysis version "
                f"{history_version}. Current NetShield history requires "
                f"{CURRENT_HISTORY_VERSION}."
            )
            print(
                "[WARNING] New baseline-aware scans will not be mixed "
                "with legacy threat-detection history."
            )

            return {
                "ok": False,
                "state": "legacy_history_detected",
                "history_version": history_version,
                "required_version": CURRENT_HISTORY_VERSION,
                "message": (
                    "Legacy historical data was detected. "
                    "Start a current-history database before storing "
                    "baseline-aware results."
                ),
            }

        source_fingerprint = (
            calculate_source_fingerprint(
                report_csv
            )
        )

        if source_fingerprint is None:
            print(
                "[WARNING] Threat report could not be fingerprinted. "
                "History database was not updated."
            )

            return {
                "ok": False,
                "state": "source_report_unavailable",
                "message": (
                    "Threat report could not be read for "
                    "historical analysis."
                ),
            }

        previous_fingerprint = (
            get_last_source_fingerprint(
                connection
            )
        )

        if (
            previous_fingerprint
            == source_fingerprint
        ):
            print(
                "[INFO] This exact Threat Analysis is "
                "already stored in history."
            )

            return {
                "ok": True,
                "state": "already_recorded",
                "source_report_sha256":
                    source_fingerprint,
                "message": (
                    "This exact Threat Analysis is already "
                    "recorded. No duplicate historical "
                    "snapshot was created."
                ),
            }

        current_rows = load_current_report(
            report_csv
        )

        if not current_rows:
            print(
                "[WARNING] No valid security report found. "
                "History database was not updated."
            )

            return {
                "ok": False,
                "state": "source_report_invalid",
                "message": (
                    "No valid threat-report rows were "
                    "available for historical analysis."
                ),
            }

        current_scan = store_scan(
            connection,
            current_rows,
        )

        comparison = compare_history(
            connection,
            current_scan,
        )

        statistics = generate_statistics(
            connection
        )

        report = generate_summary(
            current_scan,
            comparison,
            statistics,
        )

        report["ok"] = True
        report["state"] = "completed"
        report["history_version"] = (
            CURRENT_HISTORY_VERSION
        )
        report["source_report_sha256"] = (
            source_fingerprint
        )

        save_text_report(
            report,
            text_output,
        )

        save_json_report(
            report,
            json_output,
        )

        set_last_source_fingerprint(
            connection,
            source_fingerprint,
        )

        print_summary(report)

        print(
            f"\n[OK] History database updated: "
            f"{Path(database_path)}"
        )

        print(
            f"[OK] Text report saved to: "
            f"{Path(text_output)}"
        )

        print(
            f"[OK] JSON report saved to: "
            f"{Path(json_output)}"
        )

        return report

    finally:
        connection.close()



def _calculate_scan_summary(rows: list[dict[str, str]]) -> dict[str, Any]:
    scores = [_to_int(row["Suspicious_Score"], default=100) for row in rows]
    return {
        "total_networks": len(rows),
        "safe_count": sum(1 for row in rows if row["Risk_Level"] == "SAFE"),
        "low_risk_count": sum(1 for row in rows if row["Risk_Level"] == "LOW RISK"),
        "warning_count": sum(1 for row in rows if row["Risk_Level"] == "WARNING"),
        "danger_count": sum(1 for row in rows if row["Risk_Level"] == "DANGER"),
        "rogue_count": sum(
            1
            for row in rows
            if row["Attack_Type"] == "ROGUE_AP"
        ),
        "evil_twin_count": sum(
            1
            for row in rows
            if row["Attack_Type"] == "EVIL_TWIN"
        ),
        "suspicious_count": sum(
            1
            for row in rows
            if row["Attack_Type"] == "SUSPICIOUS"
        ),
        "weak_encryption_count": sum(
            1
            for row in rows
            if row["Attack_Type"] == "WEAK_ENCRYPTION"
        ),
        "unknown_network_count": sum(
            1
            for row in rows
            if row["Attack_Type"] == "UNKNOWN_NETWORK"
        ),
        "average_security_score": (
            round(
                sum(scores) / len(scores),
                2,
            )
            if scores
            else 0
        ),
    }


def _next_scan_id(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COALESCE(MAX(scan_id), 0) + 1 FROM scan_history").fetchone()
    return int(row[0])


def _previous_scan_id(connection: sqlite3.Connection, current_scan_id: int) -> int | None:
    row = connection.execute(
        "SELECT MAX(scan_id) FROM scan_history WHERE scan_id < ?",
        (current_scan_id,),
    ).fetchone()
    return int(row[0]) if row and row[0] is not None else None


def _load_scan_rows(connection: sqlite3.Connection, scan_id: int | None) -> list[dict[str, Any]]:
    if scan_id is None:
        return []

    rows = connection.execute(
        """
        SELECT scan_id, scan_timestamp, ssid, bssid, encryption, packet_count,
               security_score, risk_level, attack_type
        FROM scan_history
        WHERE scan_id = ?
        """,
        (scan_id,),
    ).fetchall()

    return [
        {
            "scan_id": row[0],
            "scan_timestamp": row[1],
            "ssid": row[2],
            "bssid": row[3],
            "encryption": row[4],
            "packet_count": row[5],
            "security_score": row[6],
            "risk_level": row[7],
            "attack_type": row[8],
        }
        for row in rows
    ]


def _load_summary_by_scan_id(connection: sqlite3.Connection, scan_id: int | None) -> dict[str, Any] | None:
    if scan_id is None:
        return None

    timestamp_row = connection.execute(
        "SELECT scan_timestamp FROM scan_history WHERE scan_id = ? LIMIT 1",
        (scan_id,),
    ).fetchone()
    if timestamp_row is None:
        return None

    row = connection.execute(
        """
        SELECT total_networks, safe_count, low_risk_count, warning_count,
               danger_count, rogue_count, evil_twin_count,
               suspicious_count, weak_encryption_count,
               unknown_network_count, average_security_score
        FROM scan_summary
        WHERE scan_timestamp = ?
        """,
        (timestamp_row[0],),
    ).fetchone()
    if row is None:
        return None

    return {
        "total_networks": int(row[0]),
        "safe_count": int(row[1]),
        "low_risk_count": int(row[2]),
        "warning_count": int(row[3]),
        "danger_count": int(row[4]),
        "rogue_count": int(row[5]),
        "evil_twin_count": int(row[6]),
        "suspicious_count": int(row[7] or 0),
        "weak_encryption_count": int(row[8] or 0),
        "unknown_network_count": int(row[9] or 0),
        "average_security_score": float(row[10]),
    }


def _build_network_history(rows: list[tuple[Any, ...]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[tuple[Any, ...]]] = {}
    for row in rows:
        grouped.setdefault(row[2], []).append(row)

    history = []
    for bssid, items in grouped.items():
        timestamps = [item[0] for item in items]
        scores = [int(item[3]) for item in items]
        attacks = Counter(item[4] for item in items)
        ssid = Counter(item[1] for item in items).most_common(1)[0][0]
        history.append(
            {
                "ssid": ssid,
                "bssid": bssid,
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
                "appearances": len(items),
                "highest_security_score": max(scores),
                "lowest_security_score": min(scores),
                "most_common_attack_type": attacks.most_common(1)[0][0],
            }
        )

    return sorted(history, key=lambda item: (-item["appearances"], item["bssid"]))


def _build_text_report(
    report: dict[str, Any],
) -> str:
    executive = report[
        "executive_summary"
    ]

    comparison = report[
        "comparison"
    ]

    current_summary = report[
        "current_scan"
    ]["summary"]

    statistics = report[
        "statistics"
    ]

    attack_counts = statistics[
        "attack_type_counts"
    ]

    lines = [
        "=====================================",
        "Historical Trend Summary",
        "=====================================",
        (
            "Generated At              : "
            f"{report['generated_at']}"
        ),
        (
            "Current Scan Number       : "
            f"{executive['current_scan_number']}"
        ),
        (
            "Previous Scan Number      : "
            f"{executive['previous_scan_number']}"
        ),
        (
            "Current Average Score     : "
            f"{current_summary['average_security_score']}"
        ),
        (
            "Potential Findings        : "
            f"{executive['potential_findings']}"
        ),
        (
            "Trend                     : "
            f"{executive['trend']}"
        ),
        "",
    ]

    if not comparison[
        "has_previous_scan"
    ]:
        lines.append(
            comparison["message"]
        )

        lines.append("")

    lines.extend(
        [
            (
                "Total Network Difference  : "
                f"{comparison['total_networks_difference']}"
            ),
            (
                "Average Score Difference  : "
                f"{comparison['average_score_difference']}"
            ),
            (
                "Potential Finding Change  : "
                f"{comparison['potential_findings_difference']}"
            ),
            (
                "Rogue AP Difference       : "
                f"{comparison['rogue_count_difference']}"
            ),
            (
                "Evil Twin Difference      : "
                f"{comparison['evil_twin_count_difference']}"
            ),
            (
                "Suspicious Difference     : "
                f"{comparison['suspicious_count_difference']}"
            ),
            (
                "Weak Encryption Difference: "
                f"{comparison['weak_encryption_count_difference']}"
            ),
            (
                "Unknown Network Difference: "
                f"{comparison['unknown_network_count_difference']}"
            ),
            (
                "Warning/Danger Difference : "
                f"{comparison['warning_danger_difference']}"
            ),
            (
                "New Networks              : "
                f"{len(comparison['new_networks'])}"
            ),
            (
                "Disappeared Networks      : "
                f"{len(comparison['disappeared_networks'])}"
            ),
            "",
            "Repeated Findings:",
            (
                "Repeated Rogue AP         : "
                f"{executive['repeated_rogue_aps']}"
            ),
            (
                "Repeated Evil Twin        : "
                f"{executive['repeated_evil_twin_detections']}"
            ),
            (
                "Repeated Suspicious       : "
                f"{executive['repeated_suspicious_detections']}"
            ),
            (
                "Repeated Weak Encryption  : "
                f"{executive['repeated_weak_encryption_detections']}"
            ),
            (
                "Repeated Unknown Network  : "
                f"{executive['repeated_unknown_network_detections']}"
            ),
            "",
            "Historical Classification Counts:",
            (
                "Normal                    : "
                f"{attack_counts['NORMAL']}"
            ),
            (
                "Rogue AP                  : "
                f"{attack_counts['ROGUE_AP']}"
            ),
            (
                "Evil Twin                 : "
                f"{attack_counts['EVIL_TWIN']}"
            ),
            (
                "Suspicious                : "
                f"{attack_counts['SUSPICIOUS']}"
            ),
            (
                "Weak Encryption           : "
                f"{attack_counts['WEAK_ENCRYPTION']}"
            ),
            (
                "Unknown Network           : "
                f"{attack_counts['UNKNOWN_NETWORK']}"
            ),
            "",
            "Historical Statistics:",
            (
                "Most Frequently Detected  : "
                f"{_format_counter_result(statistics['most_frequently_detected_network'])}"
            ),
            (
                "Most Frequent Finding     : "
                f"{_format_counter_result(statistics['most_frequent_finding'])}"
            ),
            (
                "Most Frequent Rogue AP    : "
                f"{_format_counter_result(statistics['most_frequent_rogue_ap'])}"
            ),
            (
                "Most Frequent Evil Twin   : "
                f"{_format_counter_result(statistics['most_frequent_evil_twin'])}"
            ),
            (
                "Most Frequent Suspicious  : "
                f"{_format_counter_result(statistics['most_frequent_suspicious'])}"
            ),
            (
                "Most Frequent Weak Encrypt: "
                f"{_format_counter_result(statistics['most_frequent_weak_encryption'])}"
            ),
            (
                "Most Frequent Unknown Net : "
                f"{_format_counter_result(statistics['most_frequent_unknown_network'])}"
            ),
            (
                "Highest Score Ever        : "
                f"{statistics['highest_security_score_ever']}"
            ),
            (
                "Lowest Score Ever         : "
                f"{statistics['lowest_security_score_ever']}"
            ),
            (
                "Historical Average Score  : "
                f"{statistics['average_security_score']}"
            ),
            "",
            "Network Trends:",
        ]
    )

    if not comparison[
        "network_trends"
    ]:
        lines.append(
            "No networks were available "
            "in the current scan."
        )

    else:
        for item in comparison[
            "network_trends"
        ]:
            lines.append(
                f"- {item['ssid']} "
                f"({item['bssid']}): "
                f"{item['trend']} "
                f"[previous="
                f"{item['previous_score']}, "
                f"current="
                f"{item['current_score']}]"
            )

    lines.append(
        "====================================="
    )

    return "\n".join(lines)



def _normalize_report_row(row: dict[str, str]) -> dict[str, str]:
    normalized = {}
    for column in REQUIRED_COLUMNS:
        normalized[column] = _clean_text(row.get(column), _default_for_column(column))
    normalized["Risk_Level"] = _normalize_risk_level(normalized["Risk_Level"])
    normalized["Attack_Type"] = _normalize_attack_type(normalized["Attack_Type"])
    return normalized


def _default_for_column(column: str) -> str:
    return {
        "SSID": "Unknown_Device",
        "BSSID": "Unknown",
        "Encryption": "Unknown",
        "Total_Packets": "0",
        "Suspicious_Score": "100",
        "Risk_Level": "SAFE",
        "Attack_Type": "NORMAL",
    }.get(column, "Unknown")


def _classify_overall_trend(
    score_difference: float,
    finding_difference: int = 0,
) -> str:
    """Classify trend using score and potential-finding changes."""

    if (
        score_difference > 0
        and finding_difference <= 0
    ):
        return "IMPROVING"

    if (
        score_difference < 0
        and finding_difference >= 0
    ):
        return "DECLINING"

    if (
        score_difference == 0
        and finding_difference < 0
    ):
        return "IMPROVING"

    if (
        score_difference == 0
        and finding_difference > 0
    ):
        return "DECLINING"

    if (
        score_difference > 0
        and finding_difference > 0
    ):
        return "MIXED"

    if (
        score_difference < 0
        and finding_difference < 0
    ):
        return "MIXED"

    return "STABLE"


def _counter_top(counter: Counter[str]) -> dict[str, Any] | None:
    if not counter:
        return None
    key, count = counter.most_common(1)[0]
    return {"bssid": key, "count": count}


def _format_counter_result(value: dict[str, Any] | None) -> str:
    if not value:
        return "None"
    return f"{value['bssid']} ({value['count']} times)"


def _normalize_risk_level(value: str | None) -> str:
    cleaned = " ".join(_clean_text(value, "SAFE").upper().replace("-", " ").split())
    if cleaned in {"SAFE", "LOW RISK", "WARNING", "DANGER"}:
        return cleaned
    return "SAFE"


def _normalize_attack_type(value: str | None) -> str:
    cleaned = _clean_text(value, "NORMAL").upper().replace("-", "_").replace(" ", "_")
    if cleaned in {
        "NORMAL",
        "ROGUE_AP",
        "EVIL_TWIN",
        "SUSPICIOUS",
        "WEAK_ENCRYPTION",
        "UNKNOWN_NETWORK",
    }:
        return cleaned
    return "NORMAL"


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _clean_text(value: object, default: str) -> str:
    cleaned = str(value).strip()
    if not cleaned or cleaned.lower() in {"nan", "none", "null"}:
        return default
    return cleaned


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Store and compare WiFi security history.")
    parser.add_argument("--report-csv", default=str(DEFAULT_REPORT_CSV), help="Final security report CSV path.")
    parser.add_argument("--database", default=str(DEFAULT_DATABASE), help="SQLite history database path.")
    parser.add_argument("--text-output", default=str(DEFAULT_TEXT_REPORT), help="Text trend report output path.")
    parser.add_argument("--json-output", default=str(DEFAULT_JSON_REPORT), help="JSON trend report output path.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    run_historical_trend_engine(
        report_csv=args.report_csv,
        database_path=args.database,
        text_output=args.text_output,
        json_output=args.json_output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
