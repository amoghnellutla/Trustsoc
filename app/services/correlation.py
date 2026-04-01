"""
Alert correlation engine.

Groups related alerts into incidents by detecting attack patterns.
Runs after enrichment completes for each alert.

Patterns detected:
  - brute_force: Many failed-auth alerts from same source IP in time window
  - lateral_movement: Same user account seen on multiple hosts in time window
  - privilege_escalation: Process execution followed by new admin account on same host

Each detected pattern creates (or updates) an Incident and links alerts via incident_id.
MITRE ATT&CK techniques are automatically mapped to each pattern.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.config import settings
from app.utils.evidence import create_evidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings per pattern
# ---------------------------------------------------------------------------

PATTERN_MITRE_MAP: Dict[str, Dict] = {
    "brute_force": {
        "tactics": ["Credential Access", "Initial Access"],
        "techniques": ["T1110", "T1110.001", "T1110.003"],
        "description": "Repeated authentication failures suggest a brute-force or password-spray attack.",
    },
    "lateral_movement": {
        "tactics": ["Lateral Movement"],
        "techniques": ["T1021", "T1021.001", "T1021.002", "T1078"],
        "description": "Same account accessed multiple hosts — possible lateral movement after initial compromise.",
    },
    "privilege_escalation": {
        "tactics": ["Privilege Escalation", "Persistence"],
        "techniques": ["T1078", "T1136", "T1136.001"],
        "description": "Suspicious process execution followed by new privileged account creation.",
    },
}

SEVERITY_MAP = {
    "brute_force": "high",
    "lateral_movement": "critical",
    "privilege_escalation": "critical",
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_correlation_pipeline(alert_id: UUID) -> None:
    """
    Check whether a newly enriched alert should be correlated into an incident.
    Called as a BackgroundTask after enrichment completes.
    """
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
        if not alert:
            return
        _run_patterns(db, alert)
    except Exception as exc:
        logger.error("Correlation pipeline failed for alert %s: %s", alert_id, exc, exc_info=True)
    finally:
        db.close()


def _run_patterns(db: Session, alert: models.Alert) -> None:
    """Run all pattern detectors against the alert."""
    _detect_brute_force(db, alert)
    _detect_lateral_movement(db, alert)
    _detect_privilege_escalation(db, alert)


# ---------------------------------------------------------------------------
# Pattern detectors
# ---------------------------------------------------------------------------

def _detect_brute_force(db: Session, alert: models.Alert) -> None:
    """
    Brute force: >= MIN_ALERTS_FOR_INCIDENT failed-auth alerts from the same
    source IP within the correlation time window.
    """
    if not alert.normalized_alert:
        return
    source_ip = alert.normalized_alert.get("source_ip")
    if not source_ip:
        return

    # Keywords that indicate authentication failures
    title = (alert.normalized_alert.get("title") or "").lower()
    auth_keywords = ["failed", "brute", "authentication failure", "invalid password", "login failed", "ssh"]
    if not any(kw in title for kw in auth_keywords):
        return

    window_start = datetime.now(timezone.utc) - timedelta(minutes=settings.CORRELATION_TIME_WINDOW_MINUTES)

    related = (
        db.query(models.Alert)
        .filter(
            models.Alert.created_at >= window_start,
            models.Alert.id != alert.id,
            func.jsonb_extract_path_text(models.Alert.normalized_alert, "source_ip") == source_ip,
        )
        .all()
    )

    all_alerts = [alert] + related
    if len(all_alerts) < settings.MIN_ALERTS_FOR_INCIDENT:
        return

    _create_or_update_incident(
        db=db,
        alerts=all_alerts,
        pattern_type="brute_force",
        title=f"Brute Force Attack from {source_ip}",
        description=f"Detected {len(all_alerts)} authentication failure alerts from {source_ip} within {settings.CORRELATION_TIME_WINDOW_MINUTES} minutes.",
    )


def _detect_lateral_movement(db: Session, alert: models.Alert) -> None:
    """
    Lateral movement: same user account seen on >= 2 different hosts within time window.
    """
    if not alert.normalized_alert:
        return
    user = alert.normalized_alert.get("user")
    source_host = alert.normalized_alert.get("source_host")
    if not user or not source_host:
        return

    window_start = datetime.now(timezone.utc) - timedelta(minutes=settings.CORRELATION_TIME_WINDOW_MINUTES)

    related = (
        db.query(models.Alert)
        .filter(
            models.Alert.created_at >= window_start,
            models.Alert.id != alert.id,
            func.jsonb_extract_path_text(models.Alert.normalized_alert, "user") == user,
        )
        .all()
    )

    # Collect distinct hosts
    hosts = {source_host}
    for r in related:
        if r.normalized_alert:
            h = r.normalized_alert.get("source_host")
            if h:
                hosts.add(h)

    if len(hosts) < 2:
        return

    all_alerts = [alert] + related
    _create_or_update_incident(
        db=db,
        alerts=all_alerts,
        pattern_type="lateral_movement",
        title=f"Lateral Movement by {user}",
        description=f"Account '{user}' accessed {len(hosts)} different hosts ({', '.join(sorted(hosts))}) within {settings.CORRELATION_TIME_WINDOW_MINUTES} minutes.",
    )


def _detect_privilege_escalation(db: Session, alert: models.Alert) -> None:
    """
    Privilege escalation: process execution alert followed by admin account creation
    on the same host within the time window.
    """
    if not alert.normalized_alert:
        return

    title = (alert.normalized_alert.get("title") or "").lower()
    source_host = alert.normalized_alert.get("source_host")
    if not source_host:
        return

    # This alert must look like privilege escalation or admin account creation
    privesc_keywords = ["admin", "privilege", "escalation", "mimikatz", "new user", "account created", "net user"]
    if not any(kw in title for kw in privesc_keywords):
        return

    window_start = datetime.now(timezone.utc) - timedelta(minutes=settings.CORRELATION_TIME_WINDOW_MINUTES)

    # Look for a preceding process execution alert on the same host
    related = (
        db.query(models.Alert)
        .filter(
            models.Alert.created_at >= window_start,
            models.Alert.id != alert.id,
            func.jsonb_extract_path_text(models.Alert.normalized_alert, "source_host") == source_host,
        )
        .all()
    )

    exec_keywords = ["execution", "process", "powershell", "cmd", "shell", "script"]
    exec_related = [
        r for r in related
        if r.normalized_alert and any(
            kw in (r.normalized_alert.get("title") or "").lower()
            for kw in exec_keywords
        )
    ]

    if not exec_related:
        return

    all_alerts = [alert] + exec_related
    _create_or_update_incident(
        db=db,
        alerts=all_alerts,
        pattern_type="privilege_escalation",
        title=f"Privilege Escalation on {source_host}",
        description=f"Detected suspicious process execution followed by privileged account activity on {source_host}.",
    )


# ---------------------------------------------------------------------------
# Incident management
# ---------------------------------------------------------------------------

def _create_or_update_incident(
    db: Session,
    alerts: List[models.Alert],
    pattern_type: str,
    title: str,
    description: str,
) -> models.Incident:
    """
    Create a new incident or attach alerts to an existing one with the same pattern
    on the same hosts within the time window.
    """
    mitre = PATTERN_MITRE_MAP.get(pattern_type, {})

    # Check if any of these alerts already belong to an incident of the same pattern
    existing_incident: Optional[models.Incident] = None
    for a in alerts:
        if a.incident_id:
            inc = db.query(models.Incident).filter(models.Incident.id == a.incident_id).first()
            if inc and inc.pattern_type == pattern_type and inc.status == "open":
                existing_incident = inc
                break

    if existing_incident:
        incident = existing_incident
        logger.info("Attaching %d alerts to existing incident %s", len(alerts), incident.id)
    else:
        incident = models.Incident(
            title=title,
            description=description,
            pattern_type=pattern_type,
            severity=SEVERITY_MAP.get(pattern_type, "high"),
            status="open",
            mitre_tactics=mitre.get("tactics", []),
            mitre_techniques=mitre.get("techniques", []),
        )
        db.add(incident)
        db.flush()  # Get incident.id
        logger.info("Created new %s incident %s with %d alerts", pattern_type, incident.id, len(alerts))

    # Link all unlinked alerts to this incident
    for a in alerts:
        if not a.incident_id:
            a.incident_id = incident.id

    db.flush()

    # Create incident-level evidence record
    create_evidence(
        db=db,
        incident_id=incident.id,
        evidence_type="correlation_detected",
        evidence_data={
            "pattern_type": pattern_type,
            "alert_count": len(alerts),
            "alert_ids": [str(a.id) for a in alerts],
            "mitre_tactics": mitre.get("tactics", []),
            "mitre_techniques": mitre.get("techniques", []),
            "detected_at": datetime.now(timezone.utc).isoformat(),
        },
        source="trustsoc_correlation",
    )

    db.commit()
    return incident
