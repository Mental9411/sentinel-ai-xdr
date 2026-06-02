"""IPS mode and block-request API — synced with audit logs."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.app.api.deps import get_current_user
from backend.app.config import get_settings
from backend.app.models.documents import AuditLog, User
from backend.app.models.enums import UserRole

router = APIRouter(prefix="/ips", tags=["IPS"])

_runtime_mode: Optional[str] = None
_pending_blocks: List[Dict[str, Any]] = []


def _current_mode() -> str:
    if _runtime_mode is not None:
        return _runtime_mode
    return get_settings().ids_mode or "monitor"


class ModeRequest(BaseModel):
    mode: str = Field(..., pattern="^(monitor|prevention)$")


class BlockRequest(BaseModel):
    source_ip: Optional[str] = None
    reason: str = "Manual block request from IPS dashboard"


@router.get("/status")
async def ips_status(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    settings = get_settings()
    pending = [p for p in _pending_blocks if p.get("status") == "pending"]
    return {
        "mode": _current_mode(),
        "require_approval": settings.ips_require_approval,
        "pending_block_requests": len(pending),
        "pending": pending[:20],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/mode")
async def set_ips_mode(
    req: ModeRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if current_user.role == UserRole.READ_ONLY:
        raise HTTPException(403, "IPS mode change requires analyst role or higher")
    global _runtime_mode
    previous = _current_mode()
    _runtime_mode = req.mode
    await AuditLog(
        user_id=current_user.id,
        action="ips_mode_change",
        resource_type="ips",
        resource_id=req.mode,
        details={"previous_mode": previous, "new_mode": req.mode},
        success=True,
    ).insert()
    return {"mode": req.mode, "previous": previous, "message": "IPS mode updated"}


@router.post("/block-request")
async def request_block(
    req: BlockRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if current_user.role == UserRole.READ_ONLY:
        raise HTTPException(403, "Block requests require analyst role or higher")
    settings = get_settings()
    entry = {
        "id": str(uuid4()),
        "source_ip": req.source_ip,
        "reason": req.reason,
        "requested_by": str(current_user.id),
        "status": "pending" if settings.ips_require_approval else "approved",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _pending_blocks.append(entry)
    await AuditLog(
        user_id=current_user.id,
        action="ips_block_request",
        resource_type="ip",
        resource_id=req.source_ip or "any",
        details={"request_id": entry["id"], "reason": req.reason, "status": entry["status"]},
        success=True,
    ).insert()
    return {
        "request": entry,
        "message": "Awaiting SOC Manager approval"
        if entry["status"] == "pending"
        else "Block action approved (simulated — wire firewall integration in production)",
    }
