"""
IOC Export router — STIX2 format.

GET /api/v1/export/stix2
  Exports all confirmed true-positive IOCs as a STIX2 bundle.
  Teams can import this into MISP, OpenCTI, or any STIX2-compatible platform.

Uses stdlib json only (no stix2 library dependency) for portability.
Output conforms to STIX 2.1 bundle format.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.routers.alerts import verify_api_key

log = logging.getLogger(__name__)
router = APIRouter()

STIX_SPEC_VERSION = "2.1"


def _make_stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid4()}"


def _ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ip_indicator(ip: str, alert_id: str, created: datetime) -> Dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": _make_stix_id("indicator"),
        "created": _ts(created),
        "modified": _ts(created),
        "name": f"Malicious IP: {ip}",
        "description": f"Confirmed malicious IP from TrustSOC alert {alert_id[:8]}",
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "pattern_type": "stix",
        "valid_from": _ts(created),
        "labels": ["malicious-activity"],
        "confidence": 75,
    }


def _domain_indicator(domain: str, alert_id: str, created: datetime) -> Dict[str, Any]:
    return {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": _make_stix_id("indicator"),
        "created": _ts(created),
        "modified": _ts(created),
        "name": f"Malicious Domain: {domain}",
        "description": f"Confirmed malicious domain from TrustSOC alert {alert_id[:8]}",
        "pattern": f"[domain-name:value = '{domain}']",
        "pattern_type": "stix",
        "valid_from": _ts(created),
        "labels": ["malicious-activity"],
        "confidence": 70,
    }


def _hash_indicator(hash_val: str, alert_id: str, created: datetime) -> Dict[str, Any]:
    hash_type = "SHA-256" if len(hash_val) == 64 else "MD5" if len(hash_val) == 32 else "SHA-1"
    return {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": _make_stix_id("indicator"),
        "created": _ts(created),
        "modified": _ts(created),
        "name": f"Malicious File Hash: {hash_val[:16]}...",
        "description": f"Confirmed malicious file hash from TrustSOC alert {alert_id[:8]}",
        "pattern": f"[file:hashes.'{hash_type}' = '{hash_val}']",
        "pattern_type": "stix",
        "valid_from": _ts(created),
        "labels": ["malicious-activity"],
        "confidence": 85,
    }


@router.get(
    "/stix2",
    summary="Export confirmed IOCs as STIX2 bundle",
    description=(
        "Exports all IOCs from true-positive alerts as a STIX 2.1 bundle. "
        "Import into MISP, OpenCTI, or any STIX2-compatible threat intel platform."
    ),
)
def export_stix2(
    days: int = Query(30, ge=1, le=365, description="Include alerts from last N days"),
    min_risk_score: int = Query(70, ge=0, le=100, description="Minimum risk score"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key),
):
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # True-positive alerts only
    alerts = (
        db.query(models.Alert)
        .filter(
            models.Alert.status == "confirmed",
            models.Alert.risk_score >= min_risk_score,
            models.Alert.created_at >= cutoff,
        )
        .all()
    )

    indicators: List[Dict[str, Any]] = []
    seen: set = set()

    for alert in alerts:
        iocs = (alert.normalized_alert or {}).get("iocs", {})
        alert_id = str(alert.id)
        created = alert.created_at or datetime.now(timezone.utc)

        for ip in iocs.get("ip", []):
            if ip and ip not in seen:
                indicators.append(_ip_indicator(ip, alert_id, created))
                seen.add(ip)

        for domain in iocs.get("domain", []):
            if domain and domain not in seen:
                indicators.append(_domain_indicator(domain, alert_id, created))
                seen.add(domain)

        for h in iocs.get("hash", []):
            if h and h not in seen:
                indicators.append(_hash_indicator(h, alert_id, created))
                seen.add(h)

    now = datetime.now(timezone.utc)
    bundle = {
        "type": "bundle",
        "id": _make_stix_id("bundle"),
        "spec_version": STIX_SPEC_VERSION,
        "created": _ts(now),
        "objects": indicators,
    }

    log.info("STIX2 export: %d indicators from %d true-positive alerts", len(indicators), len(alerts))

    return JSONResponse(
        content=bundle,
        headers={
            "Content-Disposition": f"attachment; filename=trustsoc_iocs_{now.strftime('%Y%m%d')}.json",
            "Content-Type": "application/json",
        },
    )
