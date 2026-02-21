"""
Database models - represent tables in database
"""
from sqlalchemy import Column, String, Integer, DateTime, JSON, ForeignKey, Boolean, DECIMAL, Text
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base
import uuid

class Alert(Base):
    """
    Stores incoming security alerts
    """
    __tablename__ = "alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    external_id = Column(String(255), unique=True, index=True)
    source_system = Column(String(100), nullable=False)
    raw_alert = Column(JSONB, nullable=False)
    normalized_alert = Column(JSONB)
    risk_score = Column(Integer, default=0)
    confidence_score = Column(DECIMAL(3, 2), default=0.0)
    status = Column(String(50), default="new", index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    evidence = relationship("Evidence", back_populates="alert", cascade="all, delete-orphan")
    enrichments = relationship("Enrichment", back_populates="alert", cascade="all, delete-orphan")
    actions = relationship("Action", back_populates="alert")
    feedback = relationship("Feedback", back_populates="alert")
    incident = relationship("Incident", back_populates="alerts")
    policy_executions = relationship("PolicyExecution", back_populates="alert")


class Incident(Base):
    """
    Groups related alerts into incidents
    """
    __tablename__ = "incidents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    pattern_type = Column(String(100))  # brute_force, lateral_movement, etc.
    severity = Column(String(50), default="medium", index=True)
    status = Column(String(50), default="open", index=True)
    mitre_tactics = Column(JSONB)
    mitre_techniques = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    closed_at = Column(DateTime(timezone=True))
    
    # Relationships
    alerts = relationship("Alert", back_populates="incident")
    evidence = relationship("Evidence", back_populates="incident")
    actions = relationship("Action", back_populates="incident")
    feedback = relationship("Feedback", back_populates="incident")


class Evidence(Base):
    """
    Stores evidence for audit trail - THE TRUST FEATURE!
    """
    __tablename__ = "evidence"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    evidence_type = Column(String(100), nullable=False)
    evidence_data = Column(JSONB, nullable=False)
    source = Column(String(255))
    hash = Column(String(64))  # SHA256 hash of evidence for integrity
    collected_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    alert = relationship("Alert", back_populates="evidence")
    incident = relationship("Incident", back_populates="evidence")


class Enrichment(Base):
    """
    Stores threat intelligence enrichment results
    """
    __tablename__ = "enrichments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False, index=True)
    enrichment_type = Column(String(100), nullable=False)  # ip_reputation, file_hash, etc.
    provider = Column(String(100), nullable=False)  # virustotal, abuseipdb, etc.
    query_value = Column(String(255))  # what we looked up
    result = Column(JSONB, nullable=False)
    confidence_score = Column(DECIMAL(3, 2))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    alert = relationship("Alert", back_populates="enrichments")


class Action(Base):
    """
    Stores actions taken (blocks, isolations, etc.)
    """
    __tablename__ = "actions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    action_type = Column(String(100), nullable=False)  # block_ip, quarantine_file, etc.
    action_data = Column(JSONB)
    status = Column(String(50), default="pending")
    executed_by = Column(String(255))
    executed_at = Column(DateTime(timezone=True))
    rollback_data = Column(JSONB)  # How to undo this action
    rollback_deadline = Column(DateTime(timezone=True))  # When it auto-expires
    notes = Column(Text)
    
    # Relationships
    alert = relationship("Alert", back_populates="actions")
    incident = relationship("Incident", back_populates="actions")


class Asset(Base):
    """
    Stores information about assets (computers, servers)
    """
    __tablename__ = "assets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(INET, index=True)
    asset_type = Column(String(100))  # workstation, server, database, etc.
    criticality = Column(Integer, default=5)  # 1-10 scale
    owner = Column(String(255))
    location = Column(String(255))
    tags = Column(JSONB)
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class UserContext(Base):
    """
    Stores information about users (employees, accounts)
    """
    __tablename__ = "users_context"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255))
    is_privileged = Column(Boolean, default=False)
    department = Column(String(100))
    risk_score = Column(Integer, default=0)
    known_ips = Column(JSONB)  # IPs this user normally uses
    known_locations = Column(JSONB)  # Locations this user normally logs in from
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Feedback(Base):
    """
    Stores analyst feedback - THE LEARNING FEATURE!
    """
    __tablename__ = "feedback"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    feedback_type = Column(String(50), nullable=False)  # true_positive, false_positive, benign
    notes = Column(Text)
    analyst_id = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    alert = relationship("Alert", back_populates="feedback")
    incident = relationship("Incident", back_populates="feedback")


class Suppression(Base):
    """
    Stores suppression rules learned from feedback
    """
    __tablename__ = "suppressions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_name = Column(String(255), nullable=False)
    conditions = Column(JSONB, nullable=False)
    reason = Column(Text)
    created_by = Column(String(255))
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    enabled = Column(Boolean, default=True)


class PolicyExecution(Base):
    """
    Stores which policy/rule made a decision
    """
    __tablename__ = "policy_executions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), index=True)
    policy_name = Column(String(255), nullable=False)
    policy_version = Column(String(50))
    conditions_met = Column(JSONB)
    actions_determined = Column(JSONB)
    explanation = Column(Text)
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    alert = relationship("Alert", back_populates="policy_executions")