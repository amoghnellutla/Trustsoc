"""
Slack / Discord webhook notifications.

Sends alerts to a Slack or Discord channel when:
  - An alert risk_score >= HIGH_RISK_THRESHOLD
  - A new Incident is created by the correlation engine

Config:
  SLACK_WEBHOOK_URL  — Incoming Webhook URL from Slack or Discord
                       (Discord: append /slack to your webhook URL)
                       Set to empty string to disable silently.

Slack webhook docs:  https://api.slack.com/messaging/webhooks
Discord webhook docs: https://discord.com/developers/docs/resources/webhook#execute-slackcompatible-webhook
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

from app.config import settings

log = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high":     ":orange_circle:",
    "medium":   ":yellow_circle:",
    "low":      ":white_circle:",
}

PATTERN_EMOJI = {
    "brute_force":          ":key:",
    "lateral_movement":     ":arrows_counterclockwise:",
    "privilege_escalation": ":arrow_up:",
}


def _post(payload: Dict[str, Any]) -> None:
    """POST a Slack-compatible JSON payload to the configured webhook URL."""
    webhook_url = getattr(settings, "SLACK_WEBHOOK_URL", None)
    if not webhook_url:
        return

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status not in (200, 204):
                log.warning("Slack webhook returned status %d", resp.status)
    except urllib.error.URLError as exc:
        log.warning("Slack notification failed: %s", exc)


def notify_high_risk_alert(
    alert_id: str,
    title: str,
    risk_score: int,
    severity: str,
    source_host: Optional[str],
    source_ip: Optional[str],
    mitre_techniques: Optional[list],
    explanation: Optional[str],
) -> None:
    """Send a Slack notification for a high-risk alert."""
    emoji = SEVERITY_EMOJI.get(severity.lower(), ":white_circle:")
    techniques_str = ", ".join(mitre_techniques) if mitre_techniques else "—"
    host_str = source_host or source_ip or "unknown"

    payload = {
        "text": f"{emoji} *TrustSOC High-Risk Alert* — Risk Score: *{risk_score}/100*",
        "attachments": [
            {
                "color": "#FF0000" if risk_score >= 80 else "#FF8C00",
                "fields": [
                    {"title": "Alert",       "value": title,           "short": False},
                    {"title": "Source",      "value": host_str,        "short": True},
                    {"title": "Severity",    "value": severity.upper(), "short": True},
                    {"title": "Risk Score",  "value": str(risk_score), "short": True},
                    {"title": "MITRE",       "value": techniques_str,  "short": True},
                    {"title": "Explanation", "value": explanation or "—", "short": False},
                ],
                "footer": f"Alert ID: {alert_id[:8]}... | TrustSOC",
                "ts": None,
            }
        ],
    }
    _post(payload)
    log.info("Slack: notified high-risk alert %s (score=%d)", alert_id, risk_score)


def notify_new_incident(
    incident_id: str,
    title: str,
    pattern_type: str,
    severity: str,
    alert_count: int,
    mitre_tactics: list,
    mitre_techniques: list,
) -> None:
    """Send a Slack notification when a new incident is created."""
    emoji = PATTERN_EMOJI.get(pattern_type, ":warning:")
    sev_emoji = SEVERITY_EMOJI.get(severity.lower(), ":white_circle:")
    tactics_str = ", ".join(mitre_tactics) if mitre_tactics else "—"
    techniques_str = ", ".join(mitre_techniques) if mitre_techniques else "—"

    payload = {
        "text": f"{emoji} {sev_emoji} *TrustSOC Incident Detected* — {title}",
        "attachments": [
            {
                "color": "#8B0000" if severity == "critical" else "#FF4500",
                "fields": [
                    {"title": "Pattern",    "value": pattern_type.replace("_", " ").title(), "short": True},
                    {"title": "Severity",   "value": severity.upper(),   "short": True},
                    {"title": "Alerts",     "value": str(alert_count),   "short": True},
                    {"title": "Tactics",    "value": tactics_str,        "short": True},
                    {"title": "Techniques", "value": techniques_str,     "short": False},
                ],
                "footer": f"Incident ID: {incident_id[:8]}... | TrustSOC",
            }
        ],
    }
    _post(payload)
    log.info("Slack: notified new %s incident %s", pattern_type, incident_id)
