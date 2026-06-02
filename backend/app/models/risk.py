"""UEBA risk and baseline models."""
import enum
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.types import GUID, FlexibleJSON, enum_column


class EntityType(str, enum.Enum):
    USER = "user"
    HOST = "host"
    DEVICE = "device"
    DEPARTMENT = "department"
    SERVICE_ACCOUNT = "service_account"


class UEBABaseline(Base):
    __tablename__ = "ueba_baselines"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    entity_type: Mapped[EntityType] = mapped_column(enum_column(EntityType), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False)
    baseline_mean: Mapped[float] = mapped_column(Float, default=0.0)
    baseline_std: Mapped[float] = mapped_column(Float, default=0.0)
    baseline_data: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    sample_count: Mapped[int] = mapped_column(default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    entity_type: Mapped[EntityType] = mapped_column(enum_column(EntityType), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(20), default="informational")
    threat_categories: Mapped[list] = mapped_column(FlexibleJSON, default=list)
    contributing_factors: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    ml_ensemble_score: Mapped[Optional[float]] = mapped_column(Float)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
