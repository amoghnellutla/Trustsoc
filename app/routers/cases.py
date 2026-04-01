"""
Case management endpoints — analyst workspace wrapping one or more incidents.

POST /api/v1/cases                    create case
GET  /api/v1/cases                    list cases
GET  /api/v1/cases/{id}               full case detail
PATCH /api/v1/cases/{id}              update status / assignee / title
POST /api/v1/cases/{id}/incidents     link incident(s) to case
DELETE /api/v1/cases/{id}/incidents/{incident_id}  unlink incident
POST /api/v1/cases/{id}/notes         add analyst note
GET  /api/v1/cases/{id}/export        JSON compliance bundle (legal/handoff)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from fastapi import status as http_status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app import models, schemas

logger = logging.getLogger(__name__)
router = APIRouter()

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


def verify_api_key(x_api_key: str = Security(api_key_header)) -> str:
    if not x_api_key or x_api_key != settings.API_KEY:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return x_api_key


def _get_case_or_404(db: Session, case_id: UUID) -> models.Case:
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return case


def _case_response(case: models.Case) -> schemas.CaseResponse:
    return schemas.CaseResponse(
        id=case.id,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        assigned_to=case.assigned_to,
        created_by=case.created_by,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        tags=case.tags,
        incident_count=len(case.incidents),
        note_count=len(case.notes),
    )


# ---------------------------------------------------------------------------
# POST / — create case
# ---------------------------------------------------------------------------
@router.post("", response_model=schemas.CaseResponse, status_code=http_status.HTTP_201_CREATED, summary="Create a new case")
def create_case(
    payload: schemas.CaseCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    case = models.Case(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        assigned_to=payload.assigned_to,
        created_by=payload.created_by,
        tags=payload.tags,
        status="open",
    )
    db.add(case)
    db.flush()  # get ID before linking incidents

    for inc_id in payload.incident_ids:
        incident = db.query(models.Incident).filter(models.Incident.id == inc_id).first()
        if incident:
            case.incidents.append(incident)

    db.commit()
    db.refresh(case)
    logger.info("Case created: %s (%s)", case.id, case.title)
    return _case_response(case)


# ---------------------------------------------------------------------------
# GET / — list cases
# ---------------------------------------------------------------------------
@router.get("", response_model=List[schemas.CaseResponse], summary="List cases")
def list_cases(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None, description="open | in_progress | closed"),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    query = db.query(models.Case)
    if status:
        query = query.filter(models.Case.status == status)
    if severity:
        query = query.filter(models.Case.severity == severity)
    if assigned_to:
        query = query.filter(models.Case.assigned_to == assigned_to)
    cases = query.order_by(models.Case.created_at.desc()).offset(skip).limit(limit).all()
    return [_case_response(c) for c in cases]


# ---------------------------------------------------------------------------
# GET /{id} — full case detail
# ---------------------------------------------------------------------------
@router.get("/{case_id}", response_model=schemas.CaseDetail, summary="Get full case detail")
def get_case(
    case_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    case = _get_case_or_404(db, case_id)
    return schemas.CaseDetail(
        id=case.id,
        title=case.title,
        description=case.description,
        status=case.status,
        severity=case.severity,
        assigned_to=case.assigned_to,
        created_by=case.created_by,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        tags=case.tags,
        incidents=case.incidents,
        notes=case.notes,
    )


# ---------------------------------------------------------------------------
# PATCH /{id} — update status / assignee / title
# ---------------------------------------------------------------------------
@router.patch("/{case_id}", response_model=schemas.CaseResponse, summary="Update case (status, assignee, title)")
def update_case(
    case_id: UUID,
    updates: Dict[str, Any],
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    case = _get_case_or_404(db, case_id)
    allowed = {"title", "description", "status", "severity", "assigned_to", "tags"}
    for key, val in updates.items():
        if key in allowed:
            setattr(case, key, val)

    if updates.get("status") == "closed" and not case.closed_at:
        case.closed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(case)
    return _case_response(case)


# ---------------------------------------------------------------------------
# POST /{id}/incidents — link incident(s) to case
# ---------------------------------------------------------------------------
@router.post("/{case_id}/incidents", response_model=schemas.CaseResponse, summary="Link incidents to case")
def add_incidents(
    case_id: UUID,
    incident_ids: List[UUID],
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    case = _get_case_or_404(db, case_id)
    existing_ids = {inc.id for inc in case.incidents}
    for inc_id in incident_ids:
        if inc_id in existing_ids:
            continue
        incident = db.query(models.Incident).filter(models.Incident.id == inc_id).first()
        if incident:
            case.incidents.append(incident)
    db.commit()
    db.refresh(case)
    return _case_response(case)


# ---------------------------------------------------------------------------
# DELETE /{id}/incidents/{incident_id} — unlink incident
# ---------------------------------------------------------------------------
@router.delete("/{case_id}/incidents/{incident_id}", response_model=schemas.CaseResponse, summary="Unlink incident from case")
def remove_incident(
    case_id: UUID,
    incident_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    case = _get_case_or_404(db, case_id)
    case.incidents = [inc for inc in case.incidents if inc.id != incident_id]
    db.commit()
    db.refresh(case)
    return _case_response(case)


# ---------------------------------------------------------------------------
# POST /{id}/notes — add analyst note
# ---------------------------------------------------------------------------
@router.post("/{case_id}/notes", response_model=schemas.CaseNoteResponse, status_code=http_status.HTTP_201_CREATED, summary="Add analyst note to case")
def add_note(
    case_id: UUID,
    payload: schemas.CaseNoteCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    _get_case_or_404(db, case_id)
    note = models.CaseNote(case_id=case_id, content=payload.content, author=payload.author)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


# ---------------------------------------------------------------------------
# GET /{id}/export — JSON compliance bundle
# ---------------------------------------------------------------------------
@router.get("/{case_id}/export", summary="Export case as JSON compliance bundle")
def export_case(
    case_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    """
    Returns a self-contained JSON document suitable for legal handoff,
    compliance audit, or incident response documentation.
    Includes: case metadata, all linked incidents, all alert evidence,
    all enrichments, all policy decisions, and analyst notes.
    """
    case = _get_case_or_404(db, case_id)

    incidents_data = []
    for incident in case.incidents:
        alerts_data = []
        for alert in incident.alerts:
            evidence = (
                db.query(models.Evidence)
                .filter(models.Evidence.alert_id == alert.id)
                .order_by(models.Evidence.collected_at)
                .all()
            )
            enrichments = (
                db.query(models.Enrichment)
                .filter(models.Enrichment.alert_id == alert.id)
                .all()
            )
            policies = (
                db.query(models.PolicyExecution)
                .filter(models.PolicyExecution.alert_id == alert.id)
                .all()
            )
            alerts_data.append({
                "id": str(alert.id),
                "source_system": alert.source_system,
                "external_id": alert.external_id,
                "normalized_alert": alert.normalized_alert,
                "risk_score": alert.risk_score,
                "confidence_score": float(alert.confidence_score or 0),
                "status": alert.status,
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
                "evidence_trail": [
                    {
                        "type": e.evidence_type,
                        "source": e.source,
                        "hash": e.hash,
                        "data": e.evidence_data,
                        "collected_at": e.collected_at.isoformat() if e.collected_at else None,
                    }
                    for e in evidence
                ],
                "enrichments": [
                    {
                        "provider": e.provider,
                        "type": e.enrichment_type,
                        "ioc": e.query_value,
                        "result": e.result,
                        "cost_usd": float(e.cost_usd or 0),
                    }
                    for e in enrichments
                ],
                "policy_decisions": [
                    {
                        "policy": p.policy_name,
                        "conditions_met": p.conditions_met,
                        "actions": p.actions_determined,
                        "explanation": p.explanation,
                        "executed_at": p.executed_at.isoformat() if p.executed_at else None,
                    }
                    for p in policies
                ],
            })

        incidents_data.append({
            "id": str(incident.id),
            "title": incident.title,
            "pattern_type": incident.pattern_type,
            "severity": incident.severity,
            "status": incident.status,
            "mitre_tactics": incident.mitre_tactics,
            "mitre_techniques": incident.mitre_techniques,
            "created_at": incident.created_at.isoformat() if incident.created_at else None,
            "alerts": alerts_data,
        })

    bundle = {
        "export_version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "case": {
            "id": str(case.id),
            "title": case.title,
            "description": case.description,
            "status": case.status,
            "severity": case.severity,
            "assigned_to": case.assigned_to,
            "created_by": case.created_by,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "tags": case.tags,
        },
        "incidents": incidents_data,
        "analyst_notes": [
            {
                "author": n.author,
                "content": n.content,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in case.notes
        ],
        "summary": {
            "total_incidents": len(incidents_data),
            "total_alerts": sum(len(i["alerts"]) for i in incidents_data),
            "total_evidence_records": sum(
                len(a["evidence_trail"]) for i in incidents_data for a in i["alerts"]
            ),
        },
    }

    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": f'attachment; filename="case_{case_id}_export.json"'},
    )
