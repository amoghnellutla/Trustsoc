"""
Evidence collection and integrity verification utilities.

This module guarantees:
- Every decision leaves an audit trail
- Every evidence record is cryptographically verifiable
"""

from sqlalchemy.orm import Session
from uuid import UUID
from typing import Any, Dict, Optional, Tuple
from app import models
from app.utils.helpers import hash_data
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Create Evidence (Audit Trail)
# ----------------------------------------------------------------------------

def create_evidence(
    db: Session,
    evidence_type: str,
    evidence_data: Dict[str, Any],
    source: str,
    alert_id: Optional[UUID] = None,
    incident_id: Optional[UUID] = None
) -> models.Evidence:
    """
    Create an immutable evidence record with SHA256 integrity hash.

    Every meaningful action in TrustSOC should call this function.

    This ensures:
    - Chain-of-custody tracking
    - Compliance auditability
    - Legal defensibility
    """

    if not evidence_data:
        logger.warning("Attempting to create empty evidence record")

    # Compute integrity hash
    data_hash = hash_data(evidence_data)

    evidence = models.Evidence(
        alert_id=alert_id,
        incident_id=incident_id,
        evidence_type=evidence_type,
        evidence_data=evidence_data,
        source=source,
        hash=data_hash
    )

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    logger.info(
        "Evidence created | type=%s | source=%s | id=%s | hash=%s",
        evidence_type,
        source,
        evidence.id,
        data_hash[:12]
    )

    return evidence


# ----------------------------------------------------------------------------
# Verify Evidence Integrity
# ----------------------------------------------------------------------------

def verify_evidence_hash(
    evidence_data: Dict[str, Any],
    stored_hash: Optional[str]
) -> Tuple[str, bool]:
    """
    Recompute SHA256 hash of evidence_data and compare to stored_hash.

    Returns:
        (computed_hash, is_valid)

        is_valid=True   → evidence untampered
        is_valid=False  → mismatch detected (possible tampering)
    """

    computed_hash = hash_data(evidence_data)

    if not stored_hash:
        logger.warning("Stored hash missing during verification")
        return computed_hash, False

    is_valid = computed_hash == stored_hash

    if not is_valid:
        logger.error(
            "Evidence hash mismatch detected! stored=%s computed=%s",
            stored_hash[:12],
            computed_hash[:12]
        )

    return computed_hash, is_valid
