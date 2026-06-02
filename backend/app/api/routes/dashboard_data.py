"""Real-time dashboard data API."""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends

from backend.app.api.deps import get_current_user
from backend.app.collectors.endpoint_collector import collect_endpoint_snapshot
from backend.app.collectors.network_discovery import get_local_network
from backend.app.models.documents import Alert, NetworkDevice, PentestDetection, SecurityEvent, User
from backend.app.models.enums import AlertSeverity
from backend.app.config import get_settings
from backend.app.services.event_pipeline import process_realtime_cycle

router = APIRouter(prefix="/dashboard", tags=["Dashboard Data"])


@router.get("/cloud-status")
async def cloud_status(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Whether cloud API credentials are configured for live ingestion."""
    s = get_settings()
    aws_ok = bool(s.aws_access_key_id and s.aws_secret_access_key)
    azure_ok = bool(s.azure_tenant_id and s.azure_client_id and s.azure_client_secret)
    return {
        "aws_configured": aws_ok,
        "azure_configured": azure_ok,
        "m365_configured": False,
        "live_ingestion_ready": aws_ok or azure_ok,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/stats")
async def dashboard_stats(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    alert_count = await Alert.count()
    event_count = await SecurityEvent.count()
    pentest_count = await PentestDetection.count()
    critical = await Alert.find(Alert.severity == AlertSeverity.CRITICAL).count()
    high = await Alert.find(Alert.severity == AlertSeverity.HIGH).count()
    devices = await NetworkDevice.count()
    online = await NetworkDevice.find(NetworkDevice.is_online == True).count()
    return {
        "alerts_total": alert_count,
        "events_total": event_count,
        "pentest_detections": pentest_count,
        "critical_alerts": critical,
        "high_alerts": high,
        "devices_total": devices,
        "devices_online": online,
        "live": True,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/nav-summary")
async def nav_summary(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Compact metrics for app bar and navigation badges."""
    stats = await dashboard_stats(current_user)
    subnet = get_local_network()
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    recent_events = await SecurityEvent.find(SecurityEvent.event_timestamp >= since).count()
    return {
        **stats,
        "events_last_hour": recent_events,
        "subnet": subnet,
    }


@router.get("/endpoint")
async def live_endpoint(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    return collect_endpoint_snapshot()


@router.post("/collect")
async def trigger_collection(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    stats = await process_realtime_cycle()
    return {"status": "ok", "stats": stats}


@router.get("/events")
async def recent_events(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    events = await SecurityEvent.find().sort(-SecurityEvent.event_timestamp).limit(limit).to_list()
    return [
        {
            "id": str(e.id),
            "source": e.source.value,
            "event_type": e.event_type,
            "hostname": e.hostname,
            "severity": e.severity,
            "timestamp": e.event_timestamp.isoformat() if e.event_timestamp else None,
        }
        for e in events
    ]
