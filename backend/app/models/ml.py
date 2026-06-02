"""ML model metadata and predictions."""
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Float, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.types import GUID, FlexibleJSON


class MLModelMetadata(Base):
    __tablename__ = "ml_model_metadata"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    model_version: Mapped[str] = mapped_column(String(50))
    model_type: Mapped[str] = mapped_column(String(50))
    mlflow_run_id: Mapped[Optional[str]] = mapped_column(String(64))
    metrics: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    drift_score: Mapped[Optional[float]] = mapped_column(Float)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    artifact_path: Mapped[Optional[str]] = mapped_column(String(500))


class MLPrediction(Base):
    __tablename__ = "ml_predictions"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    event_id: Mapped[Optional[UUID]] = mapped_column(GUID)
    model_name: Mapped[str] = mapped_column(String(100))
    risk_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(20))
    threat_type: Mapped[Optional[str]] = mapped_column(String(100))
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(20))
    ensemble_scores: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
