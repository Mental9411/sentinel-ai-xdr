"""Audit log API — real actions from discovery, IPS, and admin."""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query

from backend.app.api.deps import get_current_user
from backend.app.models.documents import AuditLog, User

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/")
async def list_audit_logs(
    limit: int = Query(100, le=500),
    action: Optional[str] = None,
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    query = AuditLog.find()
    if action:
        query = AuditLog.find(AuditLog.action == action)
    logs = await query.sort(-AuditLog.created_at).limit(limit).to_list()
    return [
        {
            "id": str(log.id),
            "action": log.action,
            "action_plain": _action_label(log.action),
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": log.details,
            "success": log.success,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]


def _action_label(action: str) -> str:
    labels = {
        "network_discovery": "Network scan completed",
        "asset_approved": "Asset approved for monitoring",
        "login": "User signed in",
        "ips_mode_change": "IPS mode changed",
        "ips_block_request": "IPS block action requested",
    }
    return labels.get(action, action.replace("_", " ").title())
