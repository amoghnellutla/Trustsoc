"""
Admin endpoints — operational management.

POST /api/v1/admin/digest          — send email digest now
GET  /api/v1/admin/execute-actions — run pending action executor
GET  /api/v1/users/{username}/risk — user behavioral risk score
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app import models
from app.config import settings
from app.routers.alerts import verify_api_key
from app.services.user_risk import get_user_risk

log = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# POST /admin/digest — trigger email digest
# ---------------------------------------------------------------------------
@router.post(
    "/digest",
    summary="Send email digest now",
    description="Compiles stats from the last 24h and sends a digest email to DIGEST_EMAIL_TO.",
)
def send_digest_now(
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    from app.notifications.email import send_digest, _smtp_enabled

    if not _smtp_enabled():
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email not configured. Set SMTP_USER, SMTP_PASSWORD, DIGEST_EMAIL_TO in environment.",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    alert_count = db.query(models.Alert).filter(models.Alert.created_at >= cutoff).count()
    incident_count = db.query(models.Incident).filter(models.Incident.created_at >= cutoff).count()
    high_risk_open = (
        db.query(models.Alert)
        .filter(
            models.Alert.status.in_(["enriched", "processing", "confirmed"]),
            models.Alert.risk_score >= settings.HIGH_RISK_THRESHOLD,
        )
        .count()
    )

    # Top MITRE techniques from incidents (last 7d)
    incidents_7d = (
        db.query(models.Incident)
        .filter(models.Incident.created_at >= datetime.now(timezone.utc) - timedelta(days=7))
        .all()
    )
    technique_counts: dict = {}
    for inc in incidents_7d:
        for t in (inc.mitre_techniques or []):
            technique_counts[t] = technique_counts.get(t, 0) + 1
    top_techniques = sorted(
        [{"technique": t, "count": c} for t, c in technique_counts.items()],
        key=lambda x: x["count"], reverse=True
    )[:10]

    # Recent high-risk alerts
    recent_high = (
        db.query(models.Alert)
        .filter(
            models.Alert.created_at >= cutoff,
            models.Alert.risk_score >= settings.HIGH_RISK_THRESHOLD,
        )
        .order_by(models.Alert.risk_score.desc())
        .limit(10)
        .all()
    )
    recent_high_list = [
        {
            "title": (a.normalized_alert or {}).get("title", "Unknown"),
            "score": a.risk_score,
            "host": (a.normalized_alert or {}).get("source_host", "—"),
        }
        for a in recent_high
    ]

    send_digest(
        alert_count_24h=alert_count,
        incident_count_24h=incident_count,
        high_risk_open=high_risk_open,
        top_techniques=top_techniques,
        recent_high_risk=recent_high_list,
    )

    return {
        "sent": True,
        "stats": {
            "alert_count_24h": alert_count,
            "incident_count_24h": incident_count,
            "high_risk_open": high_risk_open,
            "top_techniques": top_techniques[:5],
        },
    }


# ---------------------------------------------------------------------------
# POST /admin/execute-actions — run the action executor
# ---------------------------------------------------------------------------
@router.post(
    "/execute-actions",
    summary="Execute pending actions",
    description="Dispatches all pending Action records (block_ip, notify, suppress).",
)
def execute_pending(
    alert_id: Optional[UUID] = Query(None, description="Limit to a specific alert"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    from app.actions.executor import execute_pending_actions
    count = execute_pending_actions(db, alert_id=alert_id)
    return {"actions_processed": count}


# ---------------------------------------------------------------------------
# GET /users/{username}/risk — user behavioral risk
# ---------------------------------------------------------------------------
@router.get(
    "/users/{username}/risk",
    summary="Get user behavioral risk score",
    description=(
        "Returns a risk profile for a username based on their incident and alert history "
        "over rolling 7-day and 30-day windows."
    ),
)
def user_risk(
    username: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    return get_user_risk(db, username)
