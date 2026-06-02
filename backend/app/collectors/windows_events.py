"""Windows Event Log collector - real events via pywin32 or wevtutil."""
import json
import platform
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

if platform.system() == "Windows":
    try:
        import win32evtlog  # type: ignore
        import win32evtlogutil  # type: ignore
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
else:
    WIN32_AVAILABLE = False


def collect_windows_security_events(max_events: int = 100) -> List[Dict[str, Any]]:
    """Collect real Windows Security events."""
    if platform.system() != "Windows":
        return []
    events = []
    if WIN32_AVAILABLE:
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            while len(events) < max_events:
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                if not records:
                    break
                for record in records:
                    events.append({
                        "event_type": "windows_security",
                        "event_id": record.EventID,
                        "source": record.SourceName,
                        "timestamp": record.TimeGenerated.isoformat() if hasattr(record.TimeGenerated, "isoformat") else str(record.TimeGenerated),
                        "computer": record.ComputerName,
                        "raw": str(record.StringInserts) if record.StringInserts else "",
                    })
                    if len(events) >= max_events:
                        break
            win32evtlog.CloseEventLog(hand)
        except Exception:
            events = _collect_via_wevtutil(max_events)
    else:
        events = _collect_via_wevtutil(max_events)
    return events


def _collect_via_wevtutil(max_events: int) -> List[Dict[str, Any]]:
    events = []
    try:
        cmd = [
            "wevtutil", "qe", "Security",
            "/c:" + str(max_events), "/rd:true", "/f:json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        events.append({
                            "event_type": "windows_security",
                            "event_id": data.get("EventID"),
                            "source": data.get("Provider", {}).get("@Name", "Security"),
                            "timestamp": data.get("TimeCreated", datetime.now(timezone.utc).isoformat()),
                            "computer": data.get("Computer"),
                            "raw": json.dumps(data)[:2000],
                        })
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return events


def collect_sysmon_events(max_events: int = 50) -> List[Dict[str, Any]]:
    """Collect Sysmon events if log exists."""
    if platform.system() != "Windows":
        return []
    events = []
    try:
        cmd = ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational", "/c:" + str(max_events), "/rd:true", "/f:json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        events.append({
                            "event_type": "sysmon",
                            "event_id": data.get("EventID"),
                            "timestamp": data.get("TimeCreated"),
                            "raw": json.dumps(data)[:2000],
                        })
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return events
