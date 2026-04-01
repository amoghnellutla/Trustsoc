"""
Suppression rule endpoints.

GET  /api/v1/suppressions            — list all rules
POST /api/v1/suppressions            — create rule manually
GET  /api/v1/suppressions/{id}       — get single rule
PUT  /api/v1/suppressions/{id}/toggle — enable/disable
DELETE /api/v1/suppressions/{id}     — delete rule
POST /api/v1/suppressions/import     — import from YAML text body
POST /api/v1/suppressions/import-url — fetch + import from URL
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Security
from fastapi import status as http_status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app import models, schemas
from app.services.suppression import import_rule_from_yaml, import_rule_from_url

logger = logging.getLogger(__name__)
router = APIRouter()

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


def verify_api_key(x_api_key: str = Security(api_key_header)) -> str:
    if not x_api_key or x_api_key != settings.API_KEY:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return x_api_key


# ---------------------------------------------------------------------------
# GET / — list suppression rules
# ---------------------------------------------------------------------------
@router.get("", response_model=List[schemas.SuppressionResponse], summary="List suppression rules")
def list_suppressions(
    enabled_only: bool = Query(True, description="Only return enabled rules"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    query = db.query(models.Suppression)
    if enabled_only:
        query = query.filter(models.Suppression.enabled == True)  # noqa: E712
    return query.order_by(models.Suppression.created_at.desc()).offset(skip).limit(limit).all()


# ---------------------------------------------------------------------------
# POST / — create rule manually
# ---------------------------------------------------------------------------
@router.post("", response_model=schemas.SuppressionResponse, status_code=http_status.HTTP_201_CREATED, summary="Create suppression rule")
def create_suppression(
    payload: schemas.SuppressionCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    # Check for duplicate name
    if db.query(models.Suppression).filter(models.Suppression.rule_name == payload.rule_name).first():
        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail=f"Suppression rule '{payload.rule_name}' already exists. Use import to update.",
        )

    expires_at = None
    if payload.expires_after_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_after_days)

    rule = models.Suppression(
        rule_name=payload.rule_name,
        conditions=[c.model_dump() for c in payload.conditions],
        reason=payload.reason,
        created_by="api",
        expires_at=expires_at,
        enabled=True,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    logger.info("Suppression rule created: %s", rule.rule_name)
    return rule


# ---------------------------------------------------------------------------
# GET /{id} — single rule
# ---------------------------------------------------------------------------
@router.get("/{rule_id}", response_model=schemas.SuppressionResponse, summary="Get suppression rule")
def get_suppression(
    rule_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    rule = db.query(models.Suppression).filter(models.Suppression.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return rule


# ---------------------------------------------------------------------------
# PUT /{id}/toggle — enable / disable
# ---------------------------------------------------------------------------
@router.put("/{rule_id}/toggle", response_model=schemas.SuppressionResponse, summary="Toggle suppression rule on/off")
def toggle_suppression(
    rule_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    rule = db.query(models.Suppression).filter(models.Suppression.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Rule not found")
    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)
    logger.info("Suppression rule '%s' toggled to enabled=%s", rule.rule_name, rule.enabled)
    return rule


# ---------------------------------------------------------------------------
# DELETE /{id}
# ---------------------------------------------------------------------------
@router.delete("/{rule_id}", status_code=http_status.HTTP_204_NO_CONTENT, summary="Delete suppression rule")
def delete_suppression(
    rule_id: UUID,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    rule = db.query(models.Suppression).filter(models.Suppression.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Rule not found")
    db.delete(rule)
    db.commit()
    logger.info("Suppression rule deleted: %s", rule_id)


# ---------------------------------------------------------------------------
# POST /import — import from raw YAML text
# ---------------------------------------------------------------------------
@router.post(
    "/import",
    response_model=schemas.SuppressionResponse,
    status_code=http_status.HTTP_201_CREATED,
    summary="Import suppression rule from YAML text",
)
def import_yaml_body(
    yaml_text: str = Body(..., media_type="text/plain", description="Raw YAML rule text"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    try:
        return import_rule_from_yaml(db, yaml_text, created_by="api_import")
    except ValueError as exc:
        raise HTTPException(status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.error("YAML import failed: %s", exc)
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=f"Invalid YAML: {exc}")


# ---------------------------------------------------------------------------
# POST /import-url — fetch from URL + import
# ---------------------------------------------------------------------------
@router.post(
    "/import-url",
    response_model=schemas.SuppressionResponse,
    status_code=http_status.HTTP_201_CREATED,
    summary="Import suppression rule from a URL (community rules hub)",
)
def import_from_url(
    payload: schemas.SuppressionImportRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    try:
        return import_rule_from_url(db, payload.url, created_by="url_import")
    except ValueError as exc:
        raise HTTPException(status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except Exception as exc:
        logger.error("URL import failed url=%s: %s", payload.url, exc)
        raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail=f"Import failed: {exc}")
