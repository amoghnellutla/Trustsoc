"""
User behavioral risk scoring.

Tracks how many incidents and high-risk alerts a given username is involved in
over rolling time windows. Used to enrich future alerts involving the same user.

Endpoint: GET /api/v1/users/{username}/risk
Also called during enrichment to attach user context to normalized_alert.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models

log = logging.getLogger(__name__)


def get_user_risk(db: Session, username: str) -> dict:
    """
    Calculate behavioral risk for a username based on recent activity.

    Returns a dict with:
      - incident_count_7d   : incidents involving this user in last 7 days
      - alert_count_7d      : total alerts involving this user in last 7 days
      - high_risk_count_7d  : alerts with risk_score >= 70 in last 7 days
      - is_privileged        : from users_context table if populated
      - risk_level          : "low" | "medium" | "high" | "critical"
      - risk_score          : 0-100 calculated score
      - context             : stored user context record (if exists)
    """
    now = datetime.now(timezone.utc)
    window_7d = now - timedelta(days=7)
    window_30d = now - timedelta(days=30)

    # Alerts involving this user (7d)
    alerts_7d = (
        db.query(models.Alert)
        .filter(
            models.Alert.created_at >= window_7d,
            func.jsonb_extract_path_text(models.Alert.normalized_alert, "user") == username,
        )
        .all()
    )

    # Incidents involving this user (7d) — via alerts
    alert_ids_7d = [a.id for a in alerts_7d]
    incident_ids_7d: set = set()
    for a in alerts_7d:
        if a.incident_id:
            incident_ids_7d.add(str(a.incident_id))

    high_risk_7d = [a for a in alerts_7d if (a.risk_score or 0) >= 70]

    # Critical incidents (lateral movement, priv esc) — weighted higher
    critical_incidents = 0
    if incident_ids_7d:
        critical_incidents = (
            db.query(models.Incident)
            .filter(
                models.Incident.id.in_(list(incident_ids_7d)),
                models.Incident.pattern_type.in_(["lateral_movement", "privilege_escalation"]),
            )
            .count()
        )

    # 30-day trend (total incidents)
    alerts_30d = (
        db.query(models.Alert)
        .filter(
            models.Alert.created_at >= window_30d,
            func.jsonb_extract_path_text(models.Alert.normalized_alert, "user") == username,
        )
        .count()
    )

    # User context record (if populated via asset inventory)
    user_ctx = (
        db.query(models.UserContext)
        .filter(models.UserContext.username == username)
        .first()
    )

    # Calculate risk score (0–100)
    score = 0
    score += min(40, len(incident_ids_7d) * 10)       # Up to 40 pts for incidents
    score += min(20, len(high_risk_7d) * 5)            # Up to 20 pts for high-risk alerts
    score += min(30, critical_incidents * 15)          # Up to 30 pts for critical patterns
    score += min(10, max(0, len(alerts_7d) - 5) * 2)  # Up to 10 pts for alert volume
    if user_ctx and user_ctx.is_privileged:
        score = min(100, int(score * 1.25))            # Privileged users: 25% boost

    score = min(100, score)

    if score >= 70:
        risk_level = "critical"
    elif score >= 40:
        risk_level = "high"
    elif score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Update UserContext risk_score if record exists
    if user_ctx:
        user_ctx.risk_score = score
        db.commit()

    return {
        "username": username,
        "risk_score": score,
        "risk_level": risk_level,
        "incident_count_7d": len(incident_ids_7d),
        "alert_count_7d": len(alerts_7d),
        "high_risk_alert_count_7d": len(high_risk_7d),
        "critical_incident_count_7d": critical_incidents,
        "alert_count_30d": alerts_30d,
        "is_privileged": user_ctx.is_privileged if user_ctx else False,
        "department": user_ctx.department if user_ctx else None,
        "known_ips": user_ctx.known_ips if user_ctx else None,
        "calculated_at": now.isoformat(),
    }
