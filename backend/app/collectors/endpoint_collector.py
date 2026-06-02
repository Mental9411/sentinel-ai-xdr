"""Real-time endpoint monitoring - collects live system data via psutil and OS APIs."""
import hashlib
import json
import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil


def collect_endpoint_snapshot() -> Dict[str, Any]:
    """Collect real endpoint telemetry - no synthetic data."""
    hostname = socket.gethostname()
    boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    cpu_percent = psutil.cpu_percent(interval=None)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/") if platform.system() != "Windows" else psutil.disk_usage("C:\\")
    net_io = psutil.net_io_counters()
    connections = []
    for conn in psutil.net_connections(kind="inet")[:50]:
        if conn.status == "ESTABLISHED":
            connections.append({
                "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid,
            })
    processes = []
    for proc in sorted(psutil.process_iter(["pid", "name", "username", "cpu_percent"]), key=lambda p: p.info.get("cpu_percent") or 0, reverse=True)[:20]:
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    users = []
    for u in psutil.users():
        users.append({
            "name": u.name,
            "terminal": u.terminal,
            "host": u.host,
            "started": datetime.fromtimestamp(u.started, tz=timezone.utc).isoformat() if u.started else None,
        })
    snapshot = {
        "hostname": hostname,
        "platform": platform.platform(),
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_used_gb": round(memory.used / (1024**3), 2),
        "disk_percent": disk.percent,
        "boot_time": boot_time.isoformat(),
        "network_connections": connections,
        "top_processes": processes,
        "logged_in_users": users,
        "net_bytes_sent": net_io.bytes_sent,
        "net_bytes_recv": net_io.bytes_recv,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
    snapshot["fingerprint"] = hashlib.sha256(json.dumps(snapshot, sort_keys=True, default=str).encode()).hexdigest()[:32]
    return snapshot


def collect_authentication_events() -> List[Dict[str, Any]]:
    """Collect real authentication-related events from the local system."""
    events = []
    for u in psutil.users():
        events.append({
            "event_type": "user_session",
            "username": u.name,
            "source_host": u.host,
            "terminal": u.terminal,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    return events
