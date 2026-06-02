"""Incident and investigation models."""
import enum
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.types import GUID, FlexibleJSON, enum_column


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[IncidentStatus] = mapped_column(enum_column(IncidentStatus), default=IncidentStatus.OPEN)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    assigned_to: Mapped[Optional[UUID]] = mapped_column(GUID, ForeignKey("users.id"))
    timeline: Mapped[list] = mapped_column(FlexibleJSON, default=list)
    mitre_mapping: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    created_by: Mapped[Optional[UUID]] = mapped_column(GUID, ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    query: Mapped[Optional[str]] = mapped_column(Text)
    filters: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    results: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    notes: Mapped[Optional[str]] = mapped_column(Text)
    created_by: Mapped[UUID] = mapped_column(GUID, ForeignKey("users.id"))
    incident_id: Mapped[Optional[UUID]] = mapped_column(GUID, ForeignKey("incidents.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
