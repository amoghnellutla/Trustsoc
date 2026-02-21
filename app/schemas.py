"""
Pydantic schemas for API requests and responses.
These validate incoming data and format outgoing data.
Pydantic v2 compatible (no class-based Config).
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Any, Dict, List, Optional
from datetime import datetime
from uuid import UUID
from decimal import Decimal


# ============================================================================
# ALERT SCHEMAS
# ============================================================================

class AlertCreate(BaseModel):
    """Schema for creating a new alert"""
    source_system: str = Field(..., description="Source system: wazuh, splunk, elastic, etc.")
    external_id: Optional[str] = Field(None, description="ID from source system")
    alert_data: Dict[str, Any] = Field(..., description="Raw alert payload")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_system": "wazuh",
                "external_id": "test-001",
                "alert_data": {
                    "rule": {"description": "Mimikatz detected", "level": 12},
                    "agent": {"name": "windows-01", "ip": "192.168.1.100"},
                    "full_log": "Process mimikatz.exe executed by user john.doe",
                    "timestamp": "2024-01-07T10:30:00Z",
                },
            }
        }
    )


class AlertResponse(BaseModel):
    """Minimal alert representation for list views"""
    id: UUID
    external_id: Optional[str]
    source_system: str
    risk_score: int
    confidence_score: Decimal
    status: str
    incident_id: Optional[UUID]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertDetail(BaseModel):
    """Full alert with raw and normalized data"""
    id: UUID
    external_id: Optional[str]
    source_system: str
    raw_alert: Dict[str, Any]
    normalized_alert: Optional[Dict[str, Any]]
    risk_score: int
    confidence_score: Decimal
    status: str
    incident_id: Optional[UUID]
    created_at: datetime
    updated_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# INCIDENT SCHEMAS
# ============================================================================

class IncidentCreate(BaseModel):
    """Schema for creating an incident"""
    title: str
    description: Optional[str] = None
    pattern_type: Optional[str] = None
    severity: str = "medium"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "Brute Force Attack on john.doe",
                "description": "Multiple failed logins followed by success",
                "pattern_type": "brute_force",
                "severity": "high",
            }
        }
    )


class IncidentResponse(BaseModel):
    """Schema for incident in responses"""
    id: UUID
    title: str
    pattern_type: Optional[str]
    severity: str
    status: str
    mitre_tactics: Optional[Dict[str, Any]]
    mitre_techniques: Optional[Dict[str, Any]]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# EVIDENCE SCHEMAS
# ============================================================================

class EvidenceCreate(BaseModel):
    """Schema for creating evidence (not used by API yet, but useful later)"""
    alert_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    evidence_type: str
    evidence_data: Dict[str, Any]
    source: str


class EvidenceResponse(BaseModel):
    """Single evidence record"""
    id: UUID
    evidence_type: str
    evidence_data: Dict[str, Any]
    source: str
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceBundle(BaseModel):
    """
    Complete evidence bundle for an alert or incident.
    Core trust feature: shows how decisions were made and the audit trail.
    """
    alert_id: Optional[UUID]
    incident_id: Optional[UUID]
    raw_alert: Optional[Dict[str, Any]]
    normalized_alert: Optional[Dict[str, Any]]
    risk_score: int
    confidence_score: Decimal
    status: str
    evidence_trail: List[EvidenceResponse]
    enrichments: List[Dict[str, Any]]
    actions_taken: List[Dict[str, Any]]
    policy_decisions: List[Dict[str, Any]]
    risk_explanation: Dict[str, Any]


class EvidenceVerifyResponse(BaseModel):
    """Result of evidence integrity verification"""
    evidence_id: UUID
    stored_hash: str
    computed_hash: str
    is_valid: bool
    verified_at: datetime
    message: str


# ============================================================================
# ENRICHMENT SCHEMAS
# ============================================================================

class EnrichmentCreate(BaseModel):
    alert_id: UUID
    enrichment_type: str
    provider: str
    query_value: str
    result: Dict[str, Any]
    confidence_score: Optional[Decimal] = None


class EnrichmentResponse(BaseModel):
    id: UUID
    enrichment_type: str
    provider: str
    query_value: Optional[str]
    result: Dict[str, Any]
    confidence_score: Optional[Decimal]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# ACTION SCHEMAS
# ============================================================================

class ActionCreate(BaseModel):
    alert_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    action_type: str
    action_data: Dict[str, Any]
    rollback_data: Optional[Dict[str, Any]] = None


class ActionResponse(BaseModel):
    id: UUID
    action_type: str
    status: str
    executed_by: Optional[str]
    executed_at: Optional[datetime]
    rollback_deadline: Optional[datetime]
    notes: Optional[str]

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# FEEDBACK SCHEMAS
# ============================================================================

class FeedbackCreate(BaseModel):
    """Analyst feedback on an alert"""
    alert_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    feedback_type: str = Field(
        ...,
        pattern="^(true_positive|false_positive|benign|needs_more_data)$",
        description="One of: true_positive, false_positive, benign, needs_more_data",
    )
    notes: Optional[str] = None
    analyst_id: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "feedback_type": "false_positive",
                "notes": "Normal Windows Update process",
                "analyst_id": "john.analyst",
            }
        }
    )


class FeedbackResponse(BaseModel):
    id: UUID
    feedback_type: str
    notes: Optional[str]
    analyst_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# ASSET SCHEMAS
# ============================================================================

class AssetCreate(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    asset_type: Optional[str] = None
    criticality: int = Field(5, ge=1, le=10, description="Criticality 1-10 (10 = most critical)")
    owner: Optional[str] = None
    location: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None


class AssetResponse(BaseModel):
    id: UUID
    hostname: str
    ip_address: Optional[str]
    asset_type: Optional[str]
    criticality: int
    owner: Optional[str]
    location: Optional[str]

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# STATISTICS SCHEMAS
# ============================================================================

class DashboardStats(BaseModel):
    total_alerts_24h: int
    total_incidents_24h: int
    critical_alerts: int
    high_risk_alerts: int
    medium_risk_alerts: int
    low_risk_alerts: int
    alerts_by_status: Dict[str, int]
    incidents_by_severity: Dict[str, int]
    top_attack_patterns: List[Dict[str, Any]]
    avg_response_time_minutes: Optional[float] = None

