"""Shared enumerations for Sentinel-AI XDR."""
import enum


class UserRole(str, enum.Enum):
    SUPER_ADMIN = "super_admin"
    SOC_MANAGER = "soc_manager"
    SECURITY_ANALYST = "security_analyst"
    THREAT_HUNTER = "threat_hunter"
    INCIDENT_RESPONDER = "incident_responder"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


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


class EntityType(str, enum.Enum):
    USER = "user"
    HOST = "host"
    DEVICE = "device"
    DEPARTMENT = "department"
    SERVICE_ACCOUNT = "service_account"
