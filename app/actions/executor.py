"""
Action Executor — dispatches pending actions to real integrations.

Reads Action records with status="pending" and dispatches:
  block_ip            → Wazuh Active Response API (optional) or pfSense API (optional)
  flag_for_human_review → Slack notification + alert status update
  suppress_alert      → creates a Suppression rule automatically
  notify_security_team → Slack notification

Config (all optional — graceful skip if not set):
  WAZUH_API_URL      — e.g. https://wazuh-manager:55000
  WAZUH_API_USER     — Wazuh API username (default: wazuh)
  WAZUH_API_PASS     — Wazuh API password
  PFSENSE_API_URL    — pfSense/OPNsense API base URL
  PFSENSE_API_KEY    — pfSense API key

Called from the policy engine after policy actions are determined.
"""

import logging
import urllib.request
import urllib.error
import json
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app import models
from app.config import settings
from app.utils.evidence import create_evidence

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Wazuh Active Response
# ---------------------------------------------------------------------------

def _block_via_wazuh(ip: str, alert_id: str) -> tuple[bool, str]:
    """POST to Wazuh Active Response API to block an IP via firewall-drop."""
    wazuh_url  = getattr(settings, "WAZUH_API_URL", None)
    wazuh_user = getattr(settings, "WAZUH_API_USER", "wazuh")
    wazuh_pass = getattr(settings, "WAZUH_API_PASS", None)

    if not wazuh_url or not wazuh_pass:
        return False, "WAZUH_API_URL / WAZUH_API_PASS not configured"

    token = base64.b64encode(f"{wazuh_user}:{wazuh_pass}".encode()).decode()
    payload = json.dumps({
        "command": "firewall-drop",
        "arguments": ["-", "null", "(local_src)", "null"],
        "custom": False,
        "alert": {
            "data": {"srcip": ip},
            "id": alert_id,
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{wazuh_url.rstrip('/')}/active-response",
        data=payload,
        headers={
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status in (200, 201, 204), f"Wazuh response: {resp.status}"
    except urllib.error.URLError as exc:
        return False, f"Wazuh API error: {exc}"


def _block_via_pfsense(ip: str) -> tuple[bool, str]:
    """Block IP via pfSense/OPNsense firewall API."""
    api_url = getattr(settings, "PFSENSE_API_URL", None)
    api_key = getattr(settings, "PFSENSE_API_KEY", None)

    if not api_url or not api_key:
        return False, "PFSENSE_API_URL / PFSENSE_API_KEY not configured"

    payload = json.dumps({
        "type": "block",
        "interface": "wan",
        "src": ip,
        "dst": "any",
        "descr": f"TrustSOC auto-block {ip}",
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/api/v1/firewall/rule",
        data=payload,
        headers={
            "Authorization": api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status in (200, 201), f"pfSense response: {resp.status}"
    except urllib.error.URLError as exc:
        return False, f"pfSense API error: {exc}"


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

def execute_action(db: Session, action: models.Action) -> None:
    """
    Execute a single pending action. Updates action.status to 'executed' or 'failed'.
    Creates an evidence record regardless of outcome.
    """
    action_type = action.action_type
    action_data = action.action_data or {}
    alert_id_str = str(action.alert_id) if action.alert_id else ""

    log.info("Executing action %s (type=%s)", action.id, action_type)

    success = False
    result_note = "no handler"

    # --- block_ip ---
    if action_type in ("block_ip", "recommend_block_ip"):
        ip = action_data.get("target_ip") or action_data.get("ip")
        if not ip:
            # Try to get IP from parent alert
            if action.alert:
                ip = (action.alert.normalized_alert or {}).get("source_ip")

        if not ip:
            result_note = "No target IP found in action_data or alert"
        else:
            # Try Wazuh first, then pfSense
            wazuh_ok, wazuh_msg = _block_via_wazuh(ip, alert_id_str)
            if wazuh_ok:
                success = True
                result_note = f"Blocked via Wazuh: {wazuh_msg}"
            else:
                pf_ok, pf_msg = _block_via_pfsense(ip)
                if pf_ok:
                    success = True
                    result_note = f"Blocked via pfSense: {pf_msg}"
                else:
                    # Neither configured — record intent, don't fail silently
                    result_note = (
                        f"No firewall integration available. "
                        f"Wazuh: {wazuh_msg}. pfSense: {pf_msg}. "
                        f"Manual action required: block {ip}"
                    )
                    # Still mark as 'executed' (decision made, recommendation recorded)
                    success = True

    # --- flag_for_human_review ---
    elif action_type == "flag_for_human_review":
        from app.notifications.slack import notify_high_risk_alert
        alert = action.alert
        if alert and alert.normalized_alert:
            n = alert.normalized_alert
            notify_high_risk_alert(
                alert_id=str(alert.id),
                title=n.get("title", "Security Alert"),
                risk_score=alert.risk_score or 0,
                severity=n.get("severity", "medium"),
                source_host=n.get("source_host"),
                source_ip=n.get("source_ip"),
                mitre_techniques=None,
                explanation="Flagged for human review by policy engine",
            )
        if alert:
            alert.status = "under_review"
        success = True
        result_note = "Flagged and Slack notified"

    # --- notify_security_team ---
    elif action_type == "notify_security_team":
        from app.notifications.slack import notify_high_risk_alert
        alert = action.alert
        if alert and alert.normalized_alert:
            n = alert.normalized_alert
            notify_high_risk_alert(
                alert_id=str(alert.id),
                title=n.get("title", "Security Alert"),
                risk_score=alert.risk_score or 0,
                severity=n.get("severity", "medium"),
                source_host=n.get("source_host"),
                source_ip=n.get("source_ip"),
                mitre_techniques=None,
                explanation="Triggered by policy: notify_security_team",
            )
        success = True
        result_note = "Slack notification sent"

    # --- suppress_alert ---
    elif action_type == "suppress_alert":
        from app.services.suppression import import_rule_from_yaml
        alert = action.alert
        if alert and alert.normalized_alert:
            n = alert.normalized_alert
            rule_yaml = (
                f"rule_name: auto_suppress_{str(action.alert_id)[:8]}\n"
                f"reason: Auto-suppressed by policy engine\n"
                f"expires_after_days: 30\n"
                f"conditions:\n"
                f"  - field: normalized_alert.title\n"
                f"    operator: eq\n"
                f"    value: \"{n.get('title', '')}\"\n"
                f"  - field: normalized_alert.severity\n"
                f"    operator: eq\n"
                f"    value: \"{n.get('severity', 'low')}\"\n"
            )
            import_rule_from_yaml(db, rule_yaml, created_by="policy_engine")
            alert.status = "suppressed"
        success = True
        result_note = "Suppression rule created"

    # --- unknown ---
    else:
        result_note = f"Unknown action type: {action_type}"
        success = False

    # Update action record
    action.status = "executed" if success else "failed"
    action.executed_at = datetime.now(timezone.utc)
    action.executed_by = "trustsoc_executor"
    if action.notes:
        action.notes += f"\n{result_note}"
    else:
        action.notes = result_note

    # Set rollback deadline if configured
    if success and action_type in ("block_ip", "recommend_block_ip"):
        action.rollback_deadline = datetime.now(timezone.utc) + timedelta(
            minutes=settings.AUTO_BLOCK_DURATION_MINUTES
        )
        action.rollback_data = {"target_ip": action_data.get("target_ip", ""), "action": "unblock"}

    # Evidence record
    create_evidence(
        db=db,
        alert_id=action.alert_id,
        incident_id=action.incident_id,
        evidence_type="action_executed",
        evidence_data={
            "action_id": str(action.id),
            "action_type": action_type,
            "success": success,
            "result": result_note,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        },
        source="trustsoc_executor",
    )

    db.commit()
    log.info("Action %s %s: %s", action.id, action.status, result_note)


def execute_pending_actions(db: Session, alert_id: Optional[UUID] = None) -> int:
    """
    Execute all pending actions. If alert_id is given, only for that alert.
    Returns count of actions processed.
    """
    query = db.query(models.Action).filter(models.Action.status == "pending")
    if alert_id:
        query = query.filter(models.Action.alert_id == alert_id)

    actions = query.all()
    for action in actions:
        try:
            execute_action(db, action)
        except Exception as exc:
            log.error("Action %s failed with exception: %s", action.id, exc, exc_info=True)
            action.status = "failed"
            action.notes = str(exc)
            db.commit()

    return len(actions)
