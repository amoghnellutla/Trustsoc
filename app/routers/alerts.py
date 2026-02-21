"""
Alert endpoints - receiving and managing security alerts.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from fastapi import status as http_status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app import models, schemas
from app.utils.helpers import normalize_alert
from app.utils.evidence import create_evidence, verify_evidence_hash

logger = logging.getLogger(__name__)
router = APIRouter()

# ---------------------------------------------------------------------------
# API Key Security Scheme (shows Authorize button in Swagger)
# ---------------------------------------------------------------------------
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

def verify_api_key(x_api_key: str = Security(api_key_header)) -> str:
    if not x_api_key or x_api_key != settings.API_KEY:
        logger.warning("Invalid API key attempt")
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return x_api_key


# ---------------------------------------------------------------------------
# POST /  — create alert
# ---------------------------------------------------------------------------
@router.post(
    "",
    response_model=schemas.AlertResponse,
    status_code=http_status.HTTP_201_CREATED,
    summary="Ingest a new security alert",
)
def create_alert(
    payload: schemas.AlertCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    logger.info("Receiving alert from %s", payload.source_system)

    try:
        normalized = normalize_alert(payload.source_system, payload.alert_data)

        db_alert = models.Alert(
            external_id=payload.external_id,
            source_system=payload.source_system,
            raw_alert=payload.alert_data,
            normalized_alert=normalized,
            status="processing",
            risk_score=0,
            confidence_score=0.0,
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)

        # Evidence: receipt (audit trail)
        create_evidence(
            db=db,
            alert_id=db_alert.id,
            evidence_type="alert_received",
            evidence_data={
                "timestamp": db_alert.created_at.isoformat() if db_alert.created_at else datetime.utcnow().isoformat(),
                "source": payload.source_system,
                "external_id": payload.external_id,
                "size_bytes": len(str(payload.alert_data)),
                "iocs_extracted": normalized.get("iocs", {}),
            },
            source="trustsoc_intake",
        )

        # Returning ORM object is fine because schemas use from_attributes=True
        return db_alert

    except Exception as exc:
        db.rollback()
        logger.error("Error creating alert: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create alert",
        )


# ---------------------------------------------------------------------------
# GET /{alert_id} — alert detail
# ---------------------------------------------------------------------------
@router.get(
    "/{alert_id}",
    response_model=schemas.AlertDetail,
    summary="Get full alert details",
)
def get_alert(
    alert_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    return alert


# ---------------------------------------------------------------------------
# GET /  — list alerts
# ---------------------------------------------------------------------------
@router.get(
    "",
    response_model=List[schemas.AlertResponse],
    summary="List alerts (with optional filters)",
)
def list_alerts(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=100, description="Max results (1-100)"),
    alert_status: Optional[str] = Query(None, description="Filter by status"),
    min_risk_score: Optional[int] = Query(None, ge=0, le=100, description="Min risk score"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    query = db.query(models.Alert)

    if alert_status:
        query = query.filter(models.Alert.status == alert_status)

    if min_risk_score is not None:
        query = query.filter(models.Alert.risk_score >= min_risk_score)

    alerts = query.order_by(models.Alert.created_at.desc()).offset(skip).limit(limit).all()
    return alerts


# ---------------------------------------------------------------------------
# GET /{alert_id}/evidence — full evidence bundle
# ---------------------------------------------------------------------------
@router.get(
    "/{alert_id}/evidence",
    response_model=schemas.EvidenceBundle,
    summary="Get complete evidence bundle (the trust feature)",
)
def get_alert_evidence(
    alert_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    evidence_records = (
        db.query(models.Evidence)
        .filter(models.Evidence.alert_id == alert_id)
        .order_by(models.Evidence.collected_at)
        .all()
    )

    enrichments = (
        db.query(models.Enrichment)
        .filter(models.Enrichment.alert_id == alert_id)
        .order_by(models.Enrichment.created_at)
        .all()
    )

    actions = (
        db.query(models.Action)
        .filter(models.Action.alert_id == alert_id)
        .order_by(models.Action.executed_at)
        .all()
    )

    policies = (
        db.query(models.PolicyExecution)
        .filter(models.PolicyExecution.alert_id == alert_id)
        .order_by(models.PolicyExecution.executed_at)
        .all()
    )

    return schemas.EvidenceBundle(
        alert_id=alert.id,
        incident_id=alert.incident_id,
        raw_alert=alert.raw_alert,
        normalized_alert=alert.normalized_alert,
        risk_score=alert.risk_score,
        confidence_score=alert.confidence_score,
        status=alert.status,
        evidence_trail=[
            schemas.EvidenceResponse(
                id=e.id,
                evidence_type=e.evidence_type,
                evidence_data=e.evidence_data,
                source=e.source,
                collected_at=e.collected_at,
            )
            for e in evidence_records
        ],
        enrichments=[
            {
                "id": str(e.id),
                "type": e.enrichment_type,
                "provider": e.provider,
                "query": e.query_value,
                "result": e.result,
                "confidence": float(e.confidence_score) if e.confidence_score else None,
                "timestamp": e.created_at.isoformat() if e.created_at else None,
            }
            for e in enrichments
        ],
        actions_taken=[
            {
                "id": str(a.id),
                "action": a.action_type,
                "data": a.action_data,
                "status": a.status,
                "executed_by": a.executed_by,
                "timestamp": a.executed_at.isoformat() if a.executed_at else None,
                "rollback_available": bool(a.rollback_data),
                "rollback_deadline": a.rollback_deadline.isoformat() if a.rollback_deadline else None,
            }
            for a in actions
        ],
        policy_decisions=[
            {
                "id": str(p.id),
                "policy": p.policy_name,
                "version": p.policy_version,
                "conditions_met": p.conditions_met,
                "actions": p.actions_determined,
                "explanation": p.explanation,
                "timestamp": p.executed_at.isoformat() if p.executed_at else None,
            }
            for p in policies
        ],
        risk_explanation={
            "score": alert.risk_score,
            "confidence": float(alert.confidence_score),
            "factors": "Populated after enrichment phase (Week 2)",
            "threshold_high": settings.HIGH_RISK_THRESHOLD,
            "threshold_medium": settings.MEDIUM_RISK_THRESHOLD,
        },
    )


# ---------------------------------------------------------------------------
# GET /{alert_id}/evidence/verify — integrity check (tamper detection)
# ---------------------------------------------------------------------------
@router.get(
    "/{alert_id}/evidence/verify",
    response_model=List[schemas.EvidenceVerifyResponse],
    summary="Verify evidence integrity (tamper detection)",
)
def verify_evidence(
    alert_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    evidence_records = (
        db.query(models.Evidence)
        .filter(models.Evidence.alert_id == alert_id)
        .order_by(models.Evidence.collected_at)
        .all()
    )

    results: List[schemas.EvidenceVerifyResponse] = []
    for ev in evidence_records:
        stored_hash = ev.hash or ""
        computed_hash, is_valid = verify_evidence_hash(ev.evidence_data, stored_hash)

        results.append(
            schemas.EvidenceVerifyResponse(
                evidence_id=ev.id,
                stored_hash=stored_hash,
                computed_hash=computed_hash,
                is_valid=is_valid,
                verified_at=datetime.utcnow(),
                message="Evidence integrity verified" if is_valid else "Evidence hash mismatch — possible tampering",
            )
        )

    return results


# ---------------------------------------------------------------------------
# POST /{alert_id}/feedback — analyst feedback (learning loop)
# ---------------------------------------------------------------------------
@router.post(
    "/{alert_id}/feedback",
    response_model=schemas.FeedbackResponse,
    status_code=http_status.HTTP_201_CREATED,
    summary="Submit analyst feedback (learning loop)",
)
def add_feedback(
    alert_id: UUID,
    feedback: schemas.FeedbackCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    db_feedback = models.Feedback(
        alert_id=alert_id,
        feedback_type=feedback.feedback_type,
        notes=feedback.notes,
        analyst_id=feedback.analyst_id,
    )
    db.add(db_feedback)

    # Update alert status based on feedback
    status_map = {
        "true_positive": "confirmed",
        "false_positive": "false_positive",
        "benign": "suppressed",
        "needs_more_data": "under_review",
    }
    alert.status = status_map.get(feedback.feedback_type, alert.status)

    db.commit()
    db.refresh(db_feedback)
    return db_feedback


