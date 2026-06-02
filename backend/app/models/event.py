"""Security event model for SIEM ingestion."""
import enum
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.types import GUID, FlexibleJSON, enum_column


class EventSource(str, enum.Enum):
    WINDOWS_EVENT = "windows_event"
    LINUX_SYSLOG = "linux_syslog"
    ACTIVE_DIRECTORY = "active_directory"
    AZURE_AD = "azure_ad"
    M365 = "microsoft_365"
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_GUARDDUTY = "aws_guardduty"
    AWS_VPC_FLOW = "aws_vpc_flow"
    AZURE_ACTIVITY = "azure_activity"
    VPN = "vpn"
    EMAIL = "email"
    ENDPOINT = "endpoint"
    FIREWALL = "firewall"
    PROXY = "proxy"
    DNS = "dns"
    DHCP = "dhcp"
    AUTH = "authentication"
    FILE_ACCESS = "file_access"
    DATABASE_AUDIT = "database_audit"
    EDR = "edr"
    ZEEK = "zeek"
    SURICATA = "suricata"
    SNORT = "snort"
    PCAP = "pcap"
    NETWORK = "network"
    SYSMON = "sysmon"
    CROWDSTRIKE = "crowdstrike"
    DEFENDER = "microsoft_defender"
    SENTINELONE = "sentinelone"
    PACKET_CAPTURE = "packet_capture"
    PENTEST = "pentest_monitor"


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_timestamp", "event_timestamp"),
        Index("ix_events_source", "source"),
        Index("ix_events_user_host", "username", "hostname"),
    )

    id: Mapped[UUID] = mapped_column(GUID, primary_key=True, default=uuid4)
    source: Mapped[EventSource] = mapped_column(enum_column(EventSource), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    dest_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), default="informational")
    raw_log: Mapped[Optional[str]] = mapped_column(Text)
    normalized_data: Mapped[dict] = mapped_column(FlexibleJSON, default=dict)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(20))
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(50))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), index=True)
