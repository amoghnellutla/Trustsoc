"""
Suppression Rule Engine.

Evaluates alerts against active suppression rules BEFORE enrichment runs.
If a rule matches, the alert is immediately marked "suppressed" — no API cost.

Rule conditions use the same operator syntax as the policy engine:
  gte, lte, gt, lt, eq, neq, contains, is_external, exists

Field paths supported (dot-notation into normalized_alert):
  source_system
  normalized_alert.severity
  normalized_alert.title
  normalized_alert.source_ip
  normalized_alert.source_host
  normalized_alert.user

YAML import format (community rules):
  rule_name: fp_windows_update
  reason: "Windows Update noise — safe to suppress"
  expires_after_days: 90        # optional
  conditions:
    - field: normalized_alert.title
      operator: contains
      value: "Windows Update"
    - field: normalized_alert.severity
      operator: eq
      value: low
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

import yaml
from sqlalchemy.orm import Session

from app import models
from app.utils.helpers import is_private_ip

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Condition evaluation (shared logic with policy engine)
# ---------------------------------------------------------------------------

def _get_field(alert: models.Alert, field_path: str):
    """Resolve a dot-notation field path against an alert."""
    if field_path == "source_system":
        return alert.source_system

    if field_path.startswith("normalized_alert."):
        key = field_path[len("normalized_alert."):]
        return (alert.normalized_alert or {}).get(key)

    if field_path == "risk_score":
        return alert.risk_score

    if field_path == "status":
        return alert.status

    return None


def _evaluate_condition(alert: models.Alert, condition: dict) -> bool:
    field = condition.get("field", "")
    operator = condition.get("operator", "")
    value = condition.get("value")

    actual = _get_field(alert, field)

    try:
        if operator == "eq":
            return str(actual).lower() == str(value).lower()
        if operator == "neq":
            return str(actual).lower() != str(value).lower()
        if operator == "contains":
            return value.lower() in str(actual or "").lower()
        if operator == "gte":
            return float(actual or 0) >= float(value)
        if operator == "lte":
            return float(actual or 0) <= float(value)
        if operator == "gt":
            return float(actual or 0) > float(value)
        if operator == "lt":
            return float(actual or 0) < float(value)
        if operator == "exists":
            return actual is not None
        if operator == "is_external":
            return actual is not None and not is_private_ip(str(actual))
    except (TypeError, ValueError):
        return False

    return False


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------

def check_suppression(db: Session, alert: models.Alert) -> Optional[models.Suppression]:
    """
    Check if any active suppression rule matches the alert.

    Returns the matching Suppression row, or None if no match.
    Called synchronously during alert intake (before BackgroundTasks are scheduled).
    """
    now = datetime.now(timezone.utc)
    rules: List[models.Suppression] = (
        db.query(models.Suppression)
        .filter(
            models.Suppression.enabled == True,  # noqa: E712
        )
        .all()
    )

    for rule in rules:
        # Skip expired rules
        if rule.expires_at and rule.expires_at.replace(tzinfo=timezone.utc) < now:
            continue

        conditions = rule.conditions or []
        if not conditions:
            continue

        if all(_evaluate_condition(alert, cond) for cond in conditions):
            logger.info(
                "Suppression rule '%s' matched alert %s — skipping enrichment",
                rule.rule_name, alert.id,
            )
            return rule

    return None


def apply_suppression(db: Session, alert: models.Alert, rule: models.Suppression) -> None:
    """Mark alert as suppressed and write evidence record."""
    from app.utils.evidence import create_evidence

    alert.status = "suppressed"
    create_evidence(
        db=db,
        alert_id=alert.id,
        evidence_type="suppression_applied",
        evidence_data={
            "rule_name": rule.rule_name,
            "reason": rule.reason,
            "suppressed_at": datetime.now(timezone.utc).isoformat(),
        },
        source="trustsoc_suppression",
    )
    db.commit()


# ---------------------------------------------------------------------------
# YAML rule import
# ---------------------------------------------------------------------------

def import_rule_from_yaml(db: Session, yaml_text: str, created_by: str = "api") -> models.Suppression:
    """
    Parse a YAML suppression rule and upsert it into the DB.
    If a rule with the same name already exists, it is replaced.
    """
    data = yaml.safe_load(yaml_text)

    rule_name = data.get("rule_name") or data.get("name")
    if not rule_name:
        raise ValueError("YAML rule must have a 'rule_name' field")

    conditions = data.get("conditions", [])
    if not conditions:
        raise ValueError("YAML rule must have at least one condition")

    reason = data.get("reason", "")
    expires_at = None

    expires_days = data.get("expires_after_days")
    if expires_days:
        from datetime import timedelta
        expires_at = datetime.now(timezone.utc) + timedelta(days=int(expires_days))

    # Upsert
    existing = db.query(models.Suppression).filter(models.Suppression.rule_name == rule_name).first()
    if existing:
        existing.conditions = conditions
        existing.reason = reason
        existing.expires_at = expires_at
        existing.enabled = True
        db.commit()
        db.refresh(existing)
        logger.info("Suppression rule updated: %s", rule_name)
        return existing

    rule = models.Suppression(
        rule_name=rule_name,
        conditions=conditions,
        reason=reason,
        created_by=created_by,
        expires_at=expires_at,
        enabled=True,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    logger.info("Suppression rule imported: %s", rule_name)
    return rule


def import_rule_from_url(db: Session, url: str, created_by: str = "api") -> models.Suppression:
    """Fetch a YAML rule from a URL and import it."""
    from app.config import settings
    if settings.OFFLINE_MODE:
        raise ValueError("Cannot import from URL in OFFLINE_MODE. Provide YAML text directly.")
    import requests as req
    resp = req.get(url, timeout=10)
    resp.raise_for_status()
    return import_rule_from_yaml(db, resp.text, created_by=created_by)
