"""IDS/IPS models."""
import enum
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.types import GUID, FlexibleJSON, enum_column


class IPSMode(str, enum.Enum):
    MONITOR = "monitor"
    PREVENTION = "prevention"


class IPSActionStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class IPSRule(Base):
    __tablename__ = "ips_rules"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(50))
    signature: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(50), default="alert")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    engine: Mapped[str] = mapped_column(String(20))
    metadata_: Mapped[dict] = mapped_column("metadata", FlexibleJSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IPSAction(Base):
    __tablename__ = "ips_actions"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    rule_id: Mapped[Optional[UUID]] = mapped_column(GUID, ForeignKey("ips_rules.id"))
    action_type: Mapped[str] = mapped_column(String(50))
    target_ip: Mapped[str] = mapped_column(String(45))
    status: Mapped[IPSActionStatus] = mapped_column(enum_column(IPSActionStatus), default=IPSActionStatus.PENDING)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_by: Mapped[Optional[UUID]] = mapped_column(GUID, ForeignKey("users.id"))
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    audit_trail: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
