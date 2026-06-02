"""Asset and network topology models."""
import enum
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.types import GUID, FlexibleJSON


class DeviceType(str, enum.Enum):
    WORKSTATION = "workstation"
    SERVER = "server"
    PRINTER = "printer"
    IOT = "iot"
    SWITCH = "switch"
    ROUTER = "router"
    MOBILE = "mobile"
    UNKNOWN = "unknown"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17))
    device_type: Mapped[str] = mapped_column(String(50), default="unknown")
    operating_system: Mapped[Optional[str]] = mapped_column(String(100))
    open_ports: Mapped[list] = mapped_column(FlexibleJSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    department: Mapped[Optional[str]] = mapped_column(String(100))
    owner: Mapped[Optional[str]] = mapped_column(String(255))
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    discovery_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    metadata_: Mapped[dict] = mapped_column("metadata", FlexibleJSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class NetworkDevice(Base):
    __tablename__ = "network_devices"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17))
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    vendor: Mapped[Optional[str]] = mapped_column(String(100))
    device_type: Mapped[str] = mapped_column(String(50), default="unknown")
    is_online: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    scan_session_id: Mapped[Optional[str]] = mapped_column(String(64))
    approved_by: Mapped[Optional[UUID]] = mapped_column(GUID, ForeignKey("users.id"))


class NetworkTopology(Base):
    __tablename__ = "network_topology"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    relationship: Mapped[str] = mapped_column(String(50))
    protocol: Mapped[Optional[str]] = mapped_column(String(20))
    port: Mapped[Optional[int]] = mapped_column(Integer)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
