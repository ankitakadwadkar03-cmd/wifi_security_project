"""Security level scoring for detected WiFi threats."""

from __future__ import annotations

from security_dashboard.threat_detector import NetworkThreatSummary


def assign_security_score(summary: NetworkThreatSummary) -> str:
    threat = summary.threat_detected.strip().lower()
    encryption = summary.encryption.strip().lower()

    if threat in {"deauthentication attack", "unknown mac flooding"}:
        return "DANGER"
    if summary.deauth_count >= 10:
        return "DANGER"
    if threat in {"unsecured network", "weak encryption", "suspicious packet behavior"}:
        return "WARNING"
    if encryption in {"open", "wep"}:
        return "WARNING"
    return "SAFE"
