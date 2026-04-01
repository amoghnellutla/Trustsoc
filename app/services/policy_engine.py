"""
Policy engine — evaluates YAML-based rules against enriched alerts.

Policies live in the policies/ directory alongside code.
They are loaded at startup and re-evaluated per alert.
The database only stores PolicyExecution records (the audit trail of what ran).

Policy YAML format:
  name: auto_block_high_risk_external_ip
  version: "1.0"
  enabled: true
  description: "Block external IPs with high risk scores"
  conditions:
    - field: risk_score
      operator: gte
      value: 80
    - field: normalized_alert.source_ip
      operator: is_external
  actions:
    - type: recommend_block_ip
      requires_approval: false
      rollback_after_minutes: 15
  explanation_template: "Alert scored {risk_score}. Policy {policy_name} triggered."
"""

import glob
import logging
import os
from typing import Any, Dict, List, Optional
from uuid import UUID

import yaml
from sqlalchemy.orm import Session

from app import models
from app.utils.guardrails import check_action_allowed

logger = logging.getLogger(__name__)

# Path to YAML policy files — relative to the project root
_POLICIES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "policies")

# In-memory policy cache (loaded at startup)
_loaded_policies: List[Dict] = []


def load_policies() -> List[Dict]:
    """Load all enabled YAML policy files from the policies/ directory."""
    global _loaded_policies
    _loaded_policies = []

    if not os.path.isdir(_POLICIES_DIR):
        logger.warning("Policies directory not found at %s", _POLICIES_DIR)
        return []

    policy_files = glob.glob(os.path.join(_POLICIES_DIR, "*.yaml")) + \
                   glob.glob(os.path.join(_POLICIES_DIR, "*.yml"))

    for path in sorted(policy_files):
        try:
            with open(path) as f:
                policy = yaml.safe_load(f)
            if policy and policy.get("enabled", True):
                _loaded_policies.append(policy)
                logger.info("Loaded policy: %s v%s", policy.get("name"), policy.get("version", "1.0"))
        except Exception as exc:
            logger.warning("Failed to load policy %s: %s", path, exc)

    logger.info("Policy engine loaded %d policies from %s", len(_loaded_policies), _POLICIES_DIR)
    return _loaded_policies


def run_policy_engine(alert_id: UUID) -> None:
    """
    Evaluate all loaded policies against an alert.
    Called as a BackgroundTask after enrichment completes.
    """
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
        if not alert:
            return
        _evaluate_policies(db, alert)
    except Exception as exc:
        logger.error("Policy engine failed for alert %s: %s", alert_id, exc, exc_info=True)
    finally:
        db.close()


def _evaluate_policies(db: Session, alert: models.Alert) -> None:
    """Evaluate all loaded policies against a single alert."""
    if not _loaded_policies:
        logger.debug("No policies loaded, skipping policy evaluation for alert %s", alert.id)
        return

    for policy in _loaded_policies:
        try:
            _evaluate_single_policy(db, alert, policy)
        except Exception as exc:
            logger.warning("Error evaluating policy '%s' for alert %s: %s", policy.get("name"), alert.id, exc)


def _evaluate_single_policy(db: Session, alert: models.Alert, policy: Dict) -> None:
    policy_name = policy.get("name", "unnamed")
    policy_version = str(policy.get("version", "1.0"))
    conditions = policy.get("conditions", [])
    actions = policy.get("actions", [])

    conditions_met = []
    conditions_failed = []

    for condition in conditions:
        result = _evaluate_condition(alert, condition)
        if result:
            conditions_met.append(condition)
        else:
            conditions_failed.append(condition)

    all_met = len(conditions_failed) == 0 and len(conditions_met) == 0 or (
        len(conditions_met) == len(conditions) and len(conditions_failed) == 0
    )
    # Re-evaluate properly
    all_met = _all_conditions_pass(alert, conditions)

    if not all_met:
        return

    # Run guardrail check for each action
    actions_determined = []
    for action in actions:
        action_type = action.get("type", "unknown")
        guardrail = check_action_allowed(db, alert, action_type)
        actions_determined.append({
            "type": action_type,
            "allowed": guardrail.allowed,
            "reason": guardrail.reason,
            "requires_approval": action.get("requires_approval", True),
            "rollback_after_minutes": action.get("rollback_after_minutes", settings_rollback()),
        })

    # Build explanation
    template = policy.get("explanation_template", "Policy {policy_name} triggered for alert {alert_id}.")
    explanation = template.format(
        policy_name=policy_name,
        alert_id=str(alert.id),
        risk_score=alert.risk_score,
        source=alert.source_system,
    )

    # Record PolicyExecution audit trail
    execution = models.PolicyExecution(
        alert_id=alert.id,
        policy_name=policy_name,
        policy_version=policy_version,
        conditions_met=[_condition_to_dict(c) for c in conditions],
        actions_determined=actions_determined,
        explanation=explanation,
    )
    db.add(execution)
    db.commit()

    logger.info(
        "Policy '%s' triggered for alert %s | actions=%d",
        policy_name, alert.id, len(actions_determined),
    )


def _all_conditions_pass(alert: models.Alert, conditions: List[Dict]) -> bool:
    """Return True only if every condition in the list evaluates to True."""
    if not conditions:
        return False
    return all(_evaluate_condition(alert, c) for c in conditions)


def _evaluate_condition(alert: models.Alert, condition: Dict) -> bool:
    """
    Evaluate a single condition against an alert.

    Supported operators:
      gte, lte, gt, lt, eq, neq, contains, is_external, exists
    """
    field = condition.get("field", "")
    operator = condition.get("operator", "eq")
    expected = condition.get("value")

    actual = _get_field_value(alert, field)

    try:
        if operator == "gte":
            return float(actual or 0) >= float(expected)
        elif operator == "lte":
            return float(actual or 0) <= float(expected)
        elif operator == "gt":
            return float(actual or 0) > float(expected)
        elif operator == "lt":
            return float(actual or 0) < float(expected)
        elif operator == "eq":
            return str(actual) == str(expected)
        elif operator == "neq":
            return str(actual) != str(expected)
        elif operator == "contains":
            return expected in str(actual or "")
        elif operator == "is_external":
            # Check that the IP is a non-private IP address
            if not actual:
                return False
            import ipaddress
            try:
                return not ipaddress.ip_address(str(actual)).is_private
            except ValueError:
                return False
        elif operator == "exists":
            return actual is not None
    except (TypeError, ValueError) as exc:
        logger.debug("Condition evaluation error (field=%s, op=%s): %s", field, operator, exc)
        return False

    return False


def _get_field_value(alert: models.Alert, field: str) -> Any:
    """
    Resolve a dot-separated field path on an alert.

    Examples:
      "risk_score"                  → alert.risk_score
      "normalized_alert.source_ip"  → alert.normalized_alert["source_ip"]
      "normalized_alert.severity"   → alert.normalized_alert["severity"]
    """
    parts = field.split(".")

    if parts[0] == "risk_score":
        return alert.risk_score
    elif parts[0] == "confidence_score":
        return float(alert.confidence_score) if alert.confidence_score else 0.0
    elif parts[0] == "source_system":
        return alert.source_system
    elif parts[0] == "status":
        return alert.status
    elif parts[0] == "normalized_alert" and len(parts) > 1 and alert.normalized_alert:
        return alert.normalized_alert.get(parts[1])
    elif parts[0] == "normalized_alert" and len(parts) == 1:
        return alert.normalized_alert

    return None


def _condition_to_dict(condition: Dict) -> Dict:
    return {
        "field": condition.get("field"),
        "operator": condition.get("operator"),
        "value": condition.get("value"),
    }


def settings_rollback() -> int:
    from app.config import settings
    return settings.AUTO_BLOCK_DURATION_MINUTES
