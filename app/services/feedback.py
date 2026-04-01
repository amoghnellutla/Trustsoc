"""
Feedback processing service — auto-suppression learning.

When an analyst marks an alert as false_positive:
  1. A suppression rule is automatically proposed and created
  2. The rule matches alerts with the same title + source_host pattern
  3. Rule expires after 90 days (avoids stale suppressions)
  4. A summary of the proposed rule is returned to the analyst for transparency

This closes the feedback → learning loop, which is the core value of
"SOC automation that gets smarter over time."
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app import models
from app.utils.evidence import create_evidence

log = logging.getLogger(__name__)


def _sanitize(value: str) -> str:
    """Strip characters unsafe for YAML string values."""
    return re.sub(r'["\n\r]', " ", value).strip()


def handle_false_positive_feedback(
    db: Session,
    alert: models.Alert,
    analyst_id: Optional[str] = None,
) -> Optional[dict]:
    """
    When an alert is marked false_positive, auto-create a suppression rule
    based on the alert's title and source_host.

    Returns a dict describing the created rule, or None if skipped.
    """
    if not alert.normalized_alert:
        return None

    n = alert.normalized_alert
    title = n.get("title", "")
    source_host = n.get("source_host", "")
    severity = n.get("severity", "low")

    if not title:
        log.debug("No title on alert %s — skipping auto-suppression", alert.id)
        return None

    rule_slug = re.sub(r"[^a-z0-9]+", "_", title.lower())[:40].strip("_")
    rule_name = f"fp_auto_{rule_slug}"

    # Build YAML conditions
    conditions: list[dict] = [
        {"field": "normalized_alert.title", "operator": "eq", "value": _sanitize(title)},
    ]
    if source_host:
        conditions.append(
            {"field": "normalized_alert.source_host", "operator": "eq", "value": _sanitize(source_host)}
        )

    expires_at = datetime.now(timezone.utc) + timedelta(days=90)

    # Check if a rule with this name already exists
    existing = db.query(models.Suppression).filter(
        models.Suppression.rule_name == rule_name
    ).first()

    if existing:
        # Refresh the expiry so it stays active
        existing.expires_at = expires_at
        existing.enabled = True
        db.commit()
        log.info("Refreshed suppression rule '%s' from false-positive feedback", rule_name)
        return {
            "action": "refreshed",
            "rule_name": rule_name,
            "conditions": conditions,
            "expires_at": expires_at.isoformat(),
        }

    rule = models.Suppression(
        rule_name=rule_name,
        conditions=conditions,
        reason=(
            f"Auto-created from false-positive feedback on alert '{title}'"
            + (f" from {source_host}" if source_host else "")
            + (f" by {analyst_id}" if analyst_id else "")
        ),
        created_by=analyst_id or "analyst_feedback",
        expires_at=expires_at,
        enabled=True,
    )
    db.add(rule)
    db.flush()

    create_evidence(
        db=db,
        alert_id=alert.id,
        evidence_type="suppression_auto_created",
        evidence_data={
            "rule_name": rule_name,
            "conditions": conditions,
            "reason": rule.reason,
            "expires_at": expires_at.isoformat(),
            "source_alert_id": str(alert.id),
            "analyst_id": analyst_id or "unknown",
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
        source="trustsoc_feedback",
    )

    db.commit()
    log.info(
        "Auto-created suppression rule '%s' from false-positive on alert %s",
        rule_name, alert.id,
    )

    return {
        "action": "created",
        "rule_name": rule_name,
        "conditions": conditions,
        "expires_at": expires_at.isoformat(),
        "message": (
            f"Suppression rule '{rule_name}' created. "
            f"Future alerts matching this pattern will be suppressed for 90 days."
        ),
    }
