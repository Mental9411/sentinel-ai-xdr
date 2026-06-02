"""Alert model."""
import enum
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.types import GUID, FlexibleJSON, enum_column


class AlertSeverity(str, enum.Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class ThreatCategory(str, enum.Enum):
    INSIDER_THREAT = "insider_threat"
    MALWARE = "malware"
    NETWORK_INTRUSION = "network_intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    BRUTE_FORCE = "brute_force"
    C2_BEACON = "c2_beacon"
    PENTEST_ACTIVITY = "pentest_activity"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    OTHER = "other"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[AlertSeverity] = mapped_column(enum_column(AlertSeverity), default=AlertSeverity.MEDIUM)
    status: Mapped[AlertStatus] = mapped_column(enum_column(AlertStatus), default=AlertStatus.NEW)
    threat_category: Mapped[ThreatCategory] = mapped_column(enum_column(ThreatCategory), default=ThreatCategory.OTHER)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(50))
    detection_engine: Mapped[Optional[str]] = mapped_column(String(50))
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(20))
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(50))
    username: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    dest_ip: Mapped[Optional[str]] = mapped_column(String(45))
    event_ids: Mapped[list] = mapped_column(FlexibleJSON, default=list)
    ioc_matches: Mapped[list] = mapped_column(FlexibleJSON, default=list)
    evidence: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    assigned_to: Mapped[Optional[UUID]] = mapped_column(GUID, ForeignKey("users.id"))
    incident_id: Mapped[Optional[UUID]] = mapped_column(GUID, ForeignKey("incidents.id"))
    is_insider_threat: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
