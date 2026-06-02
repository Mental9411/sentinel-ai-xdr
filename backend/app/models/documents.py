"""MongoDB documents (Beanie ODM)."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from beanie import Document, Indexed
from pydantic import Field

from backend.app.models.enums import (
    AlertSeverity,
    AlertStatus,
    EntityType,
    EventSource,
    ThreatCategory,
    UserRole,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Document):
    id: UUID = Field(default_factory=uuid4)
    email: Indexed(str, unique=True)
    username: Indexed(str, unique=True)
    hashed_password: str
    full_name: Optional[str] = None
    department: Optional[str] = None
    role: UserRole = UserRole.READ_ONLY
    is_active: bool = True
    is_verified: bool = False
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    class Settings:
        name = "users"


class UserSession(Document):
    id: UUID = Field(default_factory=uuid4)
    user_id: UUID
    token_jti: Indexed(str, unique=True)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    expires_at: datetime
    is_revoked: bool = False
    created_at: datetime = Field(default_factory=utcnow)

    class Settings:
        name = "user_sessions"


class Invitation(Document):
    id: UUID = Field(default_factory=uuid4)
    email: Indexed(str)
    role: UserRole = UserRole.SECURITY_ANALYST
    token: Indexed(str, unique=True)
    invited_by: UUID
    expires_at: datetime
    accepted_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)

    class Settings:
        name = "invitations"


class SecurityEvent(Document):
    id: UUID = Field(default_factory=uuid4)
    source: EventSource
    event_type: str
    event_timestamp: datetime = Field(default_factory=utcnow)
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    severity: str = "informational"
    raw_log: Optional[str] = None
    normalized_data: Dict[str, Any] = Field(default_factory=dict)
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    ingested_at: datetime = Field(default_factory=utcnow)
    fingerprint: Optional[str] = None

    class Settings:
        name = "security_events"


class Alert(Document):
    id: UUID = Field(default_factory=uuid4)
    title: str
    description: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    threat_category: ThreatCategory = ThreatCategory.OTHER
    risk_score: float = 0.0
    confidence_score: float = 0.0
    source: str = ""
    detection_engine: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    event_ids: List[str] = Field(default_factory=list)
    ioc_matches: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    assigned_to: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    is_insider_threat: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    resolved_at: Optional[datetime] = None

    class Settings:
        name = "alerts"


class PentestDetection(Document):
    id: UUID = Field(default_factory=uuid4)
    tool_name: str
    tool_category: Optional[str] = None
    source_ip: str
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    signature: str
    confidence: float = 0.0
    severity: str = "medium"
    raw_evidence: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=utcnow)

    class Settings:
        name = "pentest_detections"


class NetworkDevice(Document):
    id: UUID = Field(default_factory=uuid4)
    ip_address: Indexed(str)
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str = "unknown"
    is_online: bool = True
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    scan_session_id: Optional[str] = None
    approved_by: Optional[UUID] = None

    class Settings:
        name = "network_devices"


class Asset(Document):
    id: UUID = Field(default_factory=uuid4)
    hostname: Optional[str] = None
    ip_address: Indexed(str, unique=True)
    mac_address: Optional[str] = None
    device_type: str = "unknown"
    operating_system: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    risk_score: float = 0.0
    department: Optional[str] = None
    owner: Optional[str] = None
    is_authorized: bool = False
    discovery_approved: bool = False
    last_seen: datetime = Field(default_factory=utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    class Settings:
        name = "assets"


class RiskScore(Document):
    id: UUID = Field(default_factory=uuid4)
    entity_type: EntityType
    entity_id: str
    risk_score: float = 0.0
    confidence: float = 0.0
    severity: str = "informational"
    threat_categories: List[str] = Field(default_factory=list)
    contributing_factors: Dict[str, Any] = Field(default_factory=dict)
    ml_ensemble_score: Optional[float] = None
    calculated_at: datetime = Field(default_factory=utcnow)

    class Settings:
        name = "risk_scores"


class AuditLog(Document):
    id: UUID = Field(default_factory=uuid4)
    user_id: Optional[UUID] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    created_at: datetime = Field(default_factory=utcnow)

    class Settings:
        name = "audit_logs"


ALL_DOCUMENTS = [
    User,
    UserSession,
    Invitation,
    SecurityEvent,
    Alert,
    PentestDetection,
    NetworkDevice,
    Asset,
    RiskScore,
    AuditLog,
]
