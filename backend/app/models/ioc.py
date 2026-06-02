"""IOC and threat feed models."""
import enum
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.types import GUID, FlexibleJSON, enum_column


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(50))
    enabled: Mapped[bool] = mapped_column(default=True)
    last_sync: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    sync_interval_hours: Mapped[int] = mapped_column(Integer, default=6)
    config: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    ioc_type: Mapped[IOCType] = mapped_column(enum_column(IOCType), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    feed_source: Mapped[str] = mapped_column(String(50), index=True)
    reputation_score: Mapped[float] = mapped_column(Float, default=0.0)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(255))
    malware_family: Mapped[Optional[str]] = mapped_column(String(255))
    tags: Mapped[list] = mapped_column(FlexibleJSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(FlexibleJSON, default=list)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    enrichment_data: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
