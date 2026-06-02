"""Threat Intelligence API — IOC enrichment and live feed summary."""
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from beanie.operators import Or

from backend.app.api.deps import get_current_user
from backend.app.models.documents import Alert, SecurityEvent, User
from backend.app.services.threat_intel import ThreatIntelService

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])
_intel = ThreatIntelService()

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9.]{1,253}[a-zA-Z0-9]$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


def detect_ioc_type(value: str) -> str:
    v = (value or "").strip()
    if _IP_RE.match(v):
        return "ip"
    if _HASH_RE.match(v):
        return "hash_sha256" if len(v) == 64 else "hash_md5"
    if _DOMAIN_RE.match(v) and "." in v:
        return "domain"
    return "unknown"


class EnrichRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=512)
    ioc_type: Optional[str] = None


async def _internal_correlation(value: str, ioc_type: str) -> Dict[str, Any]:
    """Correlate IOC against live MongoDB alerts and events (no external API required)."""
    related_alerts: List[Dict[str, Any]] = []
    related_events: List[Dict[str, Any]] = []

    if ioc_type == "ip":
        alerts = await Alert.find(
            Or(Alert.source_ip == value, Alert.dest_ip == value)
        ).sort(-Alert.created_at).limit(20).to_list()
        events = await SecurityEvent.find(
            Or(SecurityEvent.source_ip == value, SecurityEvent.dest_ip == value)
        ).sort(-SecurityEvent.event_timestamp).limit(20).to_list()
    else:
        alerts = []
        events = []

    for a in alerts:
        related_alerts.append(
            {
                "id": str(a.id),
                "title": a.title,
                "severity": a.severity.value,
                "status": a.status.value,
                "risk_score": a.risk_score,
                "created_at": a.created_at.isoformat(),
            }
        )
    for e in events:
        related_events.append(
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "severity": e.severity,
                "source": e.source.value,
                "timestamp": e.event_timestamp.isoformat() if e.event_timestamp else None,
            }
        )

    local_score = 0.0
    if related_alerts:
        max_risk = max((a.risk_score for a in alerts), default=0.0)
        local_score = min(1.0, max_risk / 100.0 + 0.2 * len(related_alerts))

    verdict = "clean"
    if local_score >= 0.7:
        verdict = "malicious"
    elif local_score >= 0.35 or related_alerts:
        verdict = "suspicious"

    return {
        "related_alerts": related_alerts,
        "related_events": related_events,
        "local_reputation_score": round(local_score, 3),
        "verdict": verdict,
        "verdict_plain": {
            "clean": "No known threats in your environment for this indicator.",
            "suspicious": "This indicator appears in your security alerts — investigate.",
            "malicious": "High-risk activity linked to this indicator in your environment.",
        }.get(verdict, ""),
    }


@router.post("/enrich")
async def enrich_ioc(req: EnrichRequest, current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    value = req.value.strip()
    ioc_type = req.ioc_type or detect_ioc_type(value)
    if ioc_type == "unknown":
        return {"error": "Could not detect IOC type. Enter an IP, domain, or file hash."}

    external = await _intel.enrich_ioc(ioc_type if ioc_type != "hash_md5" else "hash_sha256", value)
    internal = await _internal_correlation(value, ioc_type if ioc_type != "hash_md5" else "ip")

    combined_score = max(external.get("reputation_score", 0), internal.get("local_reputation_score", 0))
    risk_label = "Low"
    if combined_score >= 0.7:
        risk_label = "High"
    elif combined_score >= 0.35:
        risk_label = "Medium"

    return {
        "ioc_type": ioc_type,
        "value": value,
        "risk_level": risk_label,
        "risk_level_plain": f"{risk_label} risk — based on threat feeds and your live alerts.",
        "reputation_score": round(combined_score, 3),
        "external_sources": external.get("sources", []),
        "tags": external.get("tags", []),
        "enrichment_data": external.get("enrichment_data", {}),
        "internal": internal,
        "feeds_configured": bool(external.get("sources")),
    }


@router.get("/summary")
async def threat_intel_summary(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    alerts = await Alert.find_all().sort(-Alert.created_at).limit(500).to_list()
    high_risk = [a for a in alerts if a.risk_score >= 70 or a.severity.value in ("critical", "high")]
    unique_ips = {a.source_ip for a in alerts if a.source_ip}
    return {
        "total_alerts": len(alerts),
        "high_risk_count": len(high_risk),
        "unique_threat_ips": len(unique_ips),
        "recent_high_risk": [
            {
                "title": a.title,
                "severity": a.severity.value,
                "source_ip": a.source_ip,
                "risk_score": a.risk_score,
                "plain_summary": f"{a.severity.value.title()} alert: {a.title}",
            }
            for a in high_risk[:10]
        ],
    }
