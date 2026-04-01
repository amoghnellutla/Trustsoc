"""
Safety guardrails for automated actions.

Every automated action must pass through these checks before execution.
Guardrails prevent TrustSOC from taking harmful actions even when policies
say to act.

Rules that can never be overridden:
- Never block internal/private IP addresses
- Never act on assets above the criticality threshold
- Respect hourly action rate limits
- Auto-block must be explicitly enabled
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging

from sqlalchemy.orm import Session

from app import models
from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class GuardrailResult:
    allowed: bool
    reason: str
    action_type: Optional[str] = None


def check_action_allowed(
    db: Session,
    alert: models.Alert,
    action_type: str,
) -> GuardrailResult:
    """
    Evaluate whether an automated action is safe to execute.

    Returns GuardrailResult(allowed=True) only when all safety checks pass.
    Always log the decision for the audit trail.
    """

    # 1. Auto-block must be globally enabled
    if action_type.startswith("block") and not settings.AUTO_BLOCK_ENABLED:
        return GuardrailResult(
            allowed=False,
            reason="Auto-block is disabled (AUTO_BLOCK_ENABLED=false)",
            action_type=action_type,
        )

    # 2. Never block private/internal IPs
    if action_type == "block_ip":
        source_ip = _get_source_ip(alert)
        if source_ip and _is_private_ip(source_ip):
            return GuardrailResult(
                allowed=False,
                reason=f"Refused to block internal IP {source_ip}",
                action_type=action_type,
            )

    # 3. Never act on high-criticality assets
    asset_criticality = _get_asset_criticality(db, alert)
    if asset_criticality is not None and asset_criticality >= settings.CRITICAL_ASSET_MIN_SCORE:
        return GuardrailResult(
            allowed=False,
            reason=f"Asset criticality {asset_criticality} >= threshold {settings.CRITICAL_ASSET_MIN_SCORE} — requires human review",
            action_type=action_type,
        )

    # 4. Enforce hourly block rate limit
    if action_type.startswith("block"):
        recent_blocks = _count_recent_blocks(db)
        if recent_blocks >= settings.MAX_BLOCKS_PER_HOUR:
            return GuardrailResult(
                allowed=False,
                reason=f"Rate limit reached: {recent_blocks}/{settings.MAX_BLOCKS_PER_HOUR} blocks in the past hour",
                action_type=action_type,
            )

    logger.info(
        "Guardrail check passed | action=%s | alert=%s",
        action_type,
        alert.id,
    )
    return GuardrailResult(allowed=True, reason="All guardrail checks passed", action_type=action_type)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_source_ip(alert: models.Alert) -> Optional[str]:
    """Extract source IP from normalized alert."""
    if not alert.normalized_alert:
        return None
    return alert.normalized_alert.get("source_ip")


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except ValueError:
        return False


def _get_asset_criticality(db: Session, alert: models.Alert) -> Optional[int]:
    """Look up asset criticality for the alert's source host."""
    if not alert.normalized_alert:
        return None
    hostname = alert.normalized_alert.get("source_host")
    if not hostname:
        return None
    asset = db.query(models.Asset).filter(models.Asset.hostname == hostname).first()
    return asset.criticality if asset else None


def _count_recent_blocks(db: Session) -> int:
    """Count block actions taken in the past hour."""
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    return (
        db.query(models.Action)
        .filter(
            models.Action.action_type.like("block%"),
            models.Action.executed_at >= one_hour_ago,
            models.Action.status == "executed",
        )
        .count()
    )
