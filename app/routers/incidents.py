"""
Incident endpoints — viewing and managing correlated alert groups.
Incidents are created automatically by the correlation engine.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from fastapi import status as http_status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app import models, schemas
from app.utils.evidence import create_evidence
from app.services.narrative import generate_incident_narrative

router = APIRouter()

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


def verify_api_key(x_api_key: str = Security(api_key_header)) -> str:
    if not x_api_key or x_api_key != settings.API_KEY:
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return x_api_key


# ---------------------------------------------------------------------------
# GET /  — list incidents
# ---------------------------------------------------------------------------
@router.get(
    "",
    response_model=List[schemas.IncidentResponse],
    summary="List incidents (auto-created by correlation engine)",
)
def list_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status (open, closed)"),
    pattern_type: Optional[str] = Query(None, description="Filter by pattern type"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    query = db.query(models.Incident)

    if severity:
        query = query.filter(models.Incident.severity == severity)
    if status:
        query = query.filter(models.Incident.status == status)
    if pattern_type:
        query = query.filter(models.Incident.pattern_type == pattern_type)

    return query.order_by(models.Incident.created_at.desc()).offset(skip).limit(limit).all()


# ---------------------------------------------------------------------------
# GET /{incident_id}  — incident detail
# ---------------------------------------------------------------------------
@router.get(
    "/{incident_id}",
    response_model=schemas.IncidentDetail,
    summary="Get full incident details with linked alerts",
)
def get_incident(
    incident_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    return schemas.IncidentDetail(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        pattern_type=incident.pattern_type,
        severity=incident.severity,
        status=incident.status,
        mitre_tactics=incident.mitre_tactics,
        mitre_techniques=incident.mitre_techniques,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        closed_at=incident.closed_at,
        alert_count=len(incident.alerts),
        alerts=incident.alerts,
    )


# ---------------------------------------------------------------------------
# GET /{incident_id}/timeline  — chronological event timeline
# ---------------------------------------------------------------------------
@router.get(
    "/{incident_id}/timeline",
    response_model=List[schemas.TimelineEvent],
    summary="Chronological timeline of all events in the incident",
)
def get_incident_timeline(
    incident_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    timeline: List[schemas.TimelineEvent] = []

    # Incident-level evidence
    for ev in incident.evidence:
        timeline.append(schemas.TimelineEvent(
            timestamp=ev.collected_at,
            event_type=ev.evidence_type,
            source=ev.source or "trustsoc",
            summary=_summarize_evidence(ev),
            evidence_id=ev.id,
            data=ev.evidence_data,
        ))

    # Alert-level events (receipt + enrichment)
    for alert in incident.alerts:
        for ev in (
            db.query(models.Evidence)
            .filter(models.Evidence.alert_id == alert.id)
            .order_by(models.Evidence.collected_at)
            .all()
        ):
            timeline.append(schemas.TimelineEvent(
                timestamp=ev.collected_at,
                event_type=ev.evidence_type,
                source=ev.source or "trustsoc",
                summary=_summarize_evidence(ev, alert=alert),
                alert_id=alert.id,
                evidence_id=ev.id,
                data=ev.evidence_data,
            ))

        # Policy decisions
        for pe in alert.policy_executions:
            timeline.append(schemas.TimelineEvent(
                timestamp=pe.executed_at,
                event_type="policy_executed",
                source="trustsoc_policy_engine",
                summary=f"Policy '{pe.policy_name}' triggered — {pe.explanation or ''}",
                alert_id=alert.id,
                data={"policy": pe.policy_name, "actions": pe.actions_determined},
            ))

    # Sort by timestamp ascending
    timeline.sort(key=lambda e: e.timestamp or datetime.min)
    return timeline


# ---------------------------------------------------------------------------
# GET /{incident_id}/evidence  — aggregate evidence bundle
# ---------------------------------------------------------------------------
@router.get(
    "/{incident_id}/evidence",
    summary="Aggregate evidence across all alerts in the incident",
)
def get_incident_evidence(
    incident_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    all_evidence = list(incident.evidence)
    for alert in incident.alerts:
        all_evidence.extend(
            db.query(models.Evidence)
            .filter(models.Evidence.alert_id == alert.id)
            .all()
        )

    all_enrichments = []
    for alert in incident.alerts:
        all_enrichments.extend(alert.enrichments)

    return {
        "incident_id": str(incident.id),
        "title": incident.title,
        "pattern_type": incident.pattern_type,
        "severity": incident.severity,
        "mitre_tactics": incident.mitre_tactics,
        "mitre_techniques": incident.mitre_techniques,
        "alert_count": len(incident.alerts),
        "evidence_count": len(all_evidence),
        "evidence_trail": [
            {
                "id": str(e.id),
                "type": e.evidence_type,
                "source": e.source,
                "alert_id": str(e.alert_id) if e.alert_id else None,
                "timestamp": e.collected_at.isoformat() if e.collected_at else None,
                "hash": e.hash,
            }
            for e in sorted(all_evidence, key=lambda x: x.collected_at or datetime.min)
        ],
        "enrichments": [
            {
                "provider": e.provider,
                "type": e.enrichment_type,
                "query": e.query_value,
                "result": e.result,
                "alert_id": str(e.alert_id),
            }
            for e in all_enrichments
        ],
    }


# ---------------------------------------------------------------------------
# POST /{incident_id}/feedback  — analyst feedback
# ---------------------------------------------------------------------------
@router.post(
    "/{incident_id}/feedback",
    response_model=schemas.FeedbackResponse,
    status_code=http_status.HTTP_201_CREATED,
    summary="Submit analyst feedback on an incident",
)
def add_incident_feedback(
    incident_id: UUID,
    feedback: schemas.FeedbackCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    db_feedback = models.Feedback(
        incident_id=incident_id,
        feedback_type=feedback.feedback_type,
        notes=feedback.notes,
        analyst_id=feedback.analyst_id,
    )
    db.add(db_feedback)

    # Update incident status based on feedback
    if feedback.feedback_type == "false_positive":
        incident.status = "false_positive"
    elif feedback.feedback_type == "true_positive":
        incident.status = "confirmed"
        if not incident.closed_at:
            incident.closed_at = datetime.utcnow()

    # Audit trail
    create_evidence(
        db=db,
        incident_id=incident_id,
        evidence_type="analyst_feedback",
        evidence_data={
            "feedback_type": feedback.feedback_type,
            "analyst_id": feedback.analyst_id,
            "notes": feedback.notes,
            "timestamp": datetime.utcnow().isoformat(),
        },
        source="trustsoc_feedback",
    )

    db.commit()
    db.refresh(db_feedback)
    return db_feedback


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

import logging
_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# POST /{incident_id}/narrative — generate LLM narrative
# ---------------------------------------------------------------------------
@router.post(
    "/{incident_id}/narrative",
    response_model=schemas.NarrativeResponse,
    status_code=http_status.HTTP_201_CREATED,
    summary="Generate LLM investigation narrative for an incident",
)
def create_incident_narrative(
    incident_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found")
    try:
        return generate_incident_narrative(db, incident_id)
    except Exception as exc:
        _logger.error("Narrative generation failed incident_id=%s: %s", incident_id, exc, exc_info=True)
        raise HTTPException(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Narrative generation failed")


# ---------------------------------------------------------------------------
# GET /{incident_id}/narrative — retrieve existing narrative
# ---------------------------------------------------------------------------
@router.get(
    "/{incident_id}/narrative",
    response_model=schemas.NarrativeResponse,
    summary="Get existing LLM narrative for an incident",
)
def get_incident_narrative(
    incident_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    narrative = (
        db.query(models.Narrative)
        .filter(models.Narrative.incident_id == incident_id)
        .order_by(models.Narrative.created_at.desc())
        .first()
    )
    if not narrative:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="No narrative yet. POST to generate one.",
        )
    return narrative


# ---------------------------------------------------------------------------

def _summarize_evidence(ev: models.Evidence, alert: Optional[models.Alert] = None) -> str:
    """Generate a human-readable one-line summary for a timeline event."""
    summaries = {
        "alert_received": lambda d: f"Alert received from {d.get('source', 'unknown')} — {d.get('iocs_extracted', {}).get('ips', [])}",
        "enrichment_completed": lambda d: f"Enrichment complete: risk={d.get('risk_score', 0)}, confidence={d.get('confidence', 0):.2f}",
        "correlation_detected": lambda d: f"Correlated as '{d.get('pattern_type', 'unknown')}' with {d.get('alert_count', 0)} alerts",
        "analyst_feedback": lambda d: f"Analyst {d.get('analyst_id', 'unknown')} marked as {d.get('feedback_type', 'unknown')}",
    }
    handler = summaries.get(ev.evidence_type)
    if handler:
        try:
            return handler(ev.evidence_data or {})
        except Exception:
            pass
    return f"{ev.evidence_type} from {ev.source or 'trustsoc'}"
