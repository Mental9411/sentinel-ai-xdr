"""Compliance scores derived from live security posture (alerts, audit, assets)."""
from typing import Any, Dict, List

from fastapi import APIRouter, Depends

from backend.app.api.deps import get_current_user
from backend.app.models.documents import Alert, Asset, AuditLog, NetworkDevice, User
from backend.app.models.enums import AlertStatus

router = APIRouter(prefix="/compliance", tags=["Compliance"])


@router.get("/frameworks")
async def compliance_frameworks(current_user: User = Depends(get_current_user)) -> List[Dict[str, Any]]:
    total_alerts = await Alert.count()
    resolved = await Alert.find(Alert.status == AlertStatus.RESOLVED).count()
    audit_count = await AuditLog.count()
    devices = await NetworkDevice.count()
    assets_approved = await Asset.find(Asset.discovery_approved == True).count()

    response_rate = (resolved / total_alerts) if total_alerts else 1.0
    logging_score = min(1.0, audit_count / 10.0) if audit_count else 0.5
    asset_score = min(1.0, (assets_approved / devices) if devices else 0.7)
    monitoring_score = min(1.0, devices / 5.0) if devices else 0.4

    base = 0.55 + 0.15 * response_rate + 0.15 * logging_score + 0.15 * asset_score

    frameworks = [
        ("SOC 2", "Access & monitoring controls", base + 0.05 * monitoring_score),
        ("ISO 27001", "Information security management", base + 0.03 * asset_score),
        ("NIST CSF", "Identify · Protect · Detect · Respond", base + 0.08 * logging_score),
        ("PCI-DSS", "Cardholder data environment", base - 0.02 + 0.1 * response_rate),
        ("HIPAA", "Healthcare data safeguards", base + 0.04 * asset_score),
    ]

    result = []
    for name, description, score in frameworks:
        pct = max(0.35, min(0.98, round(score, 2)))
        status = "On track" if pct >= 0.75 else "Needs attention" if pct >= 0.55 else "At risk"
        result.append(
            {
                "framework": name,
                "description": description,
                "score": pct,
                "score_percent": int(pct * 100),
                "status": status,
                "status_plain": f"{status} — {int(pct * 100)}% based on live alerts, audit logs, and asset coverage.",
                "metrics": {
                    "alerts_total": total_alerts,
                    "alerts_resolved": resolved,
                    "audit_events": audit_count,
                    "devices_discovered": devices,
                    "assets_approved": assets_approved,
                },
            }
        )
    return result
