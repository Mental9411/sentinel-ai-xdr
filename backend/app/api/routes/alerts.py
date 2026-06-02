"""Alerts API."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from beanie.operators import In

from backend.app.api.deps import get_current_user
from backend.app.models.documents import Alert, User
from backend.app.models.enums import AlertStatus

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertResponse(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    threat_category: str
    risk_score: float
    confidence_score: float
    source: str
    detection_engine: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    is_insider_threat: bool = False
    created_at: str


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    status: Optional[AlertStatus] = None,
    detection_engine: Optional[str] = Query(None, description="e.g. ids, ensemble"),
    source: Optional[str] = Query(None, description="e.g. network"),
    limit: int = Query(50, le=500),
    current_user: User = Depends(get_current_user),
):
    conditions = []
    if status:
        conditions.append(Alert.status == status)
    if detection_engine:
        conditions.append(Alert.detection_engine == detection_engine)
    if source:
        conditions.append(Alert.source == source)
    finder = Alert.find(*conditions) if conditions else Alert.find_all()
    alerts = await finder.sort(-Alert.created_at).limit(limit).to_list()
    return [
        AlertResponse(
            id=a.id,
            title=a.title,
            description=a.description,
            severity=a.severity.value,
            status=a.status.value,
            threat_category=a.threat_category.value,
            risk_score=a.risk_score,
            confidence_score=a.confidence_score,
            source=a.source,
            detection_engine=a.detection_engine,
            mitre_technique=a.mitre_technique,
            mitre_tactic=a.mitre_tactic,
            hostname=a.hostname,
            source_ip=a.source_ip,
            dest_ip=a.dest_ip,
            is_insider_threat=a.is_insider_threat,
            created_at=a.created_at.isoformat(),
        )
        for a in alerts
    ]


@router.get("/ids/summary")
async def ids_summary(
    limit: int = Query(100, le=500),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Live IDS alert counts for the IDS dashboard."""
    alerts = (
        await Alert.find(In(Alert.detection_engine, ["ids", "scapy"]))
        .sort(-Alert.created_at)
        .limit(limit)
        .to_list()
    )
    by_severity: Dict[str, int] = {}
    for a in alerts:
        sev = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "total": len(alerts),
        "by_severity": by_severity,
        "latest": alerts[0].created_at.isoformat() if alerts else None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: UUID,
    status: AlertStatus,
    current_user: User = Depends(get_current_user),
):
    alert = await Alert.find_one(Alert.id == alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = status
    await alert.save()
    return {"message": "Updated", "status": status.value}
