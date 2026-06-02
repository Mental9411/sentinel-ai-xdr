"""Network discovery and IP monitoring API."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.app.api.deps import get_current_user
from backend.app.collectors.network_discovery import discover_network, get_local_network
from backend.app.services.topology_builder import build_topology_graph
from backend.app.collectors.packet_capture import get_recent_packets, is_capturing, start_capture, stop_capture
from backend.app.models.documents import Asset, AuditLog, NetworkDevice, User
from backend.app.models.enums import UserRole

router = APIRouter(prefix="/network", tags=["Network"])


class DiscoveryRequest(BaseModel):
    subnet: Optional[str] = None
    scan_ports: bool = False


class ApproveAssetRequest(BaseModel):
    ip_address: str
    device_type: str = "unknown"


@router.get("/local-subnet")
async def get_subnet(current_user: User = Depends(get_current_user)):
    subnet = get_local_network()
    return {"subnet": subnet, "message": "Detected from active WiFi/Ethernet interface"}


@router.post("/discover")
async def run_discovery(
    req: DiscoveryRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role == UserRole.READ_ONLY:
        raise HTTPException(403, "Discovery requires analyst role or higher")
    result = discover_network(req.subnet, req.scan_ports)
    if result.get("devices"):
        from backend.app.services.endpoint_threat_analyzer import record_discovery_pentest

        await record_discovery_pentest(
            result.get("subnet", ""),
            result.get("devices", []),
            req.scan_ports,
        )
    await AuditLog(
        user_id=current_user.id,
        action="network_discovery",
        resource_type="subnet",
        resource_id=result.get("subnet"),
        details={"device_count": result.get("device_count"), "session_id": result.get("session_id")},
    ).insert()
    for dev in result.get("devices", []):
        existing = await NetworkDevice.find_one(NetworkDevice.ip_address == dev["ip_address"])
        if not existing:
            await NetworkDevice(
                ip_address=dev["ip_address"],
                mac_address=dev.get("mac_address"),
                hostname=dev.get("hostname"),
                vendor=dev.get("vendor"),
                device_type=dev.get("device_type", "unknown"),
                scan_session_id=result.get("session_id"),
            ).insert()
    return result


@router.get("/topology")
async def get_topology(current_user: User = Depends(get_current_user)):
    """Network topology with name, nodes, and edges from discovered devices."""
    devices = await NetworkDevice.find().sort(-NetworkDevice.last_seen).limit(500).to_list()
    device_dicts = [
        {
            "ip_address": d.ip_address,
            "mac_address": d.mac_address,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "device_type": d.device_type,
            "is_online": d.is_online,
        }
        for d in devices
    ]
    subnet = get_local_network()
    return build_topology_graph(device_dicts, subnet)


@router.get("/devices")
async def list_devices(current_user: User = Depends(get_current_user)):
    devices = await NetworkDevice.find().sort(-NetworkDevice.last_seen).limit(500).to_list()
    return [
        {
            "ip_address": d.ip_address,
            "mac_address": d.mac_address,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "device_type": d.device_type,
            "is_online": d.is_online,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        }
        for d in devices
    ]


@router.post("/assets/approve")
async def approve_asset(req: ApproveAssetRequest, current_user: User = Depends(get_current_user)):
    if current_user.role not in (UserRole.SUPER_ADMIN, UserRole.SOC_MANAGER):
        raise HTTPException(403, "Only managers can approve assets")
    asset = await Asset.find_one(Asset.ip_address == req.ip_address)
    if not asset:
        asset = Asset(ip_address=req.ip_address, device_type=req.device_type)
        await asset.insert()
    else:
        asset.is_authorized = True
        asset.discovery_approved = True
        await asset.save()
    await AuditLog(user_id=current_user.id, action="asset_approved", resource_id=req.ip_address).insert()
    return {"message": "Asset approved", "ip": req.ip_address}


@router.post("/capture/start")
async def start_packet_capture(current_user: User = Depends(get_current_user)):
    if is_capturing():
        return {"status": "capturing", "message": "Packet capture already running"}
    if start_capture():
        return {"status": "capturing", "message": "Live packet capture started"}
    return {
        "status": "unavailable",
        "message": "Could not start capture — install Npcap and run API as Administrator on Windows, or use Run analysis now for endpoint-based detections.",
    }


@router.post("/capture/stop")
async def stop_packet_capture(current_user: User = Depends(get_current_user)):
    stop_capture()
    return {"status": "stopped"}


@router.get("/capture/status")
async def capture_status(current_user: User = Depends(get_current_user)):
    return {"capturing": is_capturing(), "recent_packets": len(get_recent_packets(10))}


@router.get("/capture/packets")
async def recent_packets(limit: int = 100, current_user: User = Depends(get_current_user)):
    return get_recent_packets(limit)
