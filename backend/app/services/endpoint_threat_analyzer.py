"""Endpoint and connection-based IDS / pentest detections when packet capture is empty."""
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from backend.app.models.documents import Alert, PentestDetection, utcnow

IDS_ENGINE_NAMES = ("ids", "scapy")
DEDUPE_SECONDS = 600

SUSPICIOUS_PROCESS_PATTERNS = [
    (re.compile(r"nmap", re.I), "nmap", "port_scanner", "medium"),
    (re.compile(r"nessus", re.I), "nessus", "vulnerability_scanner", "high"),
    (re.compile(r"metasploit|msfconsole|meterpreter", re.I), "metasploit", "exploitation_framework", "critical"),
    (re.compile(r"sqlmap", re.I), "sqlmap", "sql_injection", "high"),
    (re.compile(r"hydra", re.I), "hydra", "brute_force", "high"),
    (re.compile(r"burp", re.I), "burp", "web_proxy", "medium"),
    (re.compile(r"masscan", re.I), "masscan", "port_scanner", "high"),
    (re.compile(r"mimikatz", re.I), "mimikatz", "credential_attack", "critical"),
    (re.compile(r"gobuster|nikto", re.I), "gobuster", "directory_bruteforce", "medium"),
]

def build_packets_from_snapshot(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Turn live connection list into packet-like dicts for the IDS engine."""
    packets: List[Dict[str, Any]] = []
    local_ips = {socket.gethostbyname(socket.gethostname())}
    for conn in snapshot.get("network_connections", [])[:80]:
        remote = conn.get("remote") or ""
        local = conn.get("local") or ""
        if not remote or remote.startswith("127."):
            continue
        try:
            if remote.count(":") >= 1:
                host, port_s = remote.rsplit(":", 1)
                dst_port = int(port_s)
            else:
                host, dst_port = remote, 443
            src_ip = local.split(":")[0] if local else snapshot.get("hostname", "127.0.0.1")
            if src_ip in ("0.0.0.0", "*"):
                src_ip = list(local_ips)[0] if local_ips else "127.0.0.1"
            packets.append({
                "src_ip": src_ip,
                "dst_ip": host,
                "dst_port": dst_port,
                "flags": "S",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except (ValueError, OSError):
            continue
    return packets


def _parse_remote_ports(connections: List[Dict]) -> Tuple[List[int], List[str]]:
    ports: List[int] = []
    targets: List[str] = []
    for conn in connections:
        remote = conn.get("remote") or ""
        if ":" in remote:
            host, port_s = remote.rsplit(":", 1)
            try:
                ports.append(int(port_s))
                targets.append(host)
            except ValueError:
                pass
    return ports, targets


async def _recent_ids_alert(title: str) -> bool:
    since = utcnow() - timedelta(seconds=DEDUPE_SECONDS)
    existing = await Alert.find(
        Alert.title == title,
        Alert.created_at >= since,
    ).limit(1).to_list()
    return bool(existing)


async def _recent_pentest(signature: str) -> bool:
    since = utcnow() - timedelta(seconds=DEDUPE_SECONDS)
    existing = await PentestDetection.find(
        PentestDetection.signature == signature,
        PentestDetection.detected_at >= since,
    ).limit(1).to_list()
    return bool(existing)


async def analyze_endpoint_snapshot(snapshot: Dict[str, Any]) -> Dict[str, int]:
    """Create IDS alerts and pentest rows from endpoint telemetry."""
    counts = {"ids": 0, "pentest": 0}
    hostname = snapshot.get("hostname") or "localhost"
    cpu = float(snapshot.get("cpu_percent") or 0)
    mem = float(snapshot.get("memory_percent") or 0)
    connections = snapshot.get("network_connections") or []

    if cpu >= 85:
        title = f"High CPU usage: {cpu:.1f}% on {hostname}"
        if not await _recent_ids_alert(title):
            await Alert(
                title=title,
                description=f"Process load spike detected on monitored host (top process may be crypto-mining or runaway job).",
                severity=_sev(cpu, 95, "critical", "high"),
                source="endpoint",
                detection_engine="ids",
                hostname=hostname,
                risk_score=min(95.0, cpu),
                confidence_score=0.75,
                evidence={"cpu_percent": cpu, "rule": "high_cpu"},
                mitre_technique="T1496",
            ).insert()
            counts["ids"] += 1

    if mem >= 88:
        title = f"High memory usage: {mem:.1f}% on {hostname}"
        if not await _recent_ids_alert(title):
            await Alert(
                title=title,
                description="Memory pressure on endpoint — possible resource exhaustion or malware.",
                severity="high",
                source="endpoint",
                detection_engine="ids",
                hostname=hostname,
                risk_score=mem * 0.8,
                confidence_score=0.7,
                evidence={"memory_percent": mem, "rule": "high_memory"},
                mitre_technique="T1496",
            ).insert()
            counts["ids"] += 1

    for proc in snapshot.get("top_processes", [])[:15]:
        name = (proc.get("name") or proc.get("process_name") or "")
        if not name:
            continue
        for pattern, tool, category, severity in SUSPICIOUS_PROCESS_PATTERNS:
            if pattern.search(name):
                sig = f"process:{tool}:{name}:{hostname}"
                if not await _recent_pentest(sig):
                    await PentestDetection(
                        tool_name=tool,
                        tool_category=category,
                        source_ip=hostname,
                        signature=sig,
                        confidence=0.88,
                        severity=severity,
                        metadata={"process": name, "pid": proc.get("pid"), "source": "endpoint"},
                    ).insert()
                    counts["pentest"] += 1
                ids_title = f"Suspicious process: {name} (PID {proc.get('pid', '?')})"
                if not await _recent_ids_alert(ids_title):
                    await Alert(
                        title=ids_title,
                        description=f"Offensive-security or hacking tool pattern matched: {tool}",
                        severity=severity,
                        source="endpoint",
                        detection_engine="ids",
                        hostname=hostname,
                        risk_score=80.0 if severity in ("critical", "high") else 55.0,
                        confidence_score=0.85,
                        evidence={"process": proc, "tool": tool},
                        mitre_technique="T1059",
                    ).insert()
                    counts["ids"] += 1
                break

    counts["pentest"] += await pentest_from_live_traffic(snapshot)

    ports, targets = _parse_remote_ports(connections)
    unique_targets = len(set(targets))
    if len(ports) >= 8 or unique_targets >= 8:
        title = f"Elevated network activity: {len(ports)} connections / {unique_targets} peers on {hostname}"
        if not await _recent_ids_alert(title):
            await Alert(
                title=title,
                description="Connection fan-out resembles port scan or lateral movement reconnaissance.",
                severity="medium",
                source="network",
                detection_engine="ids",
                hostname=hostname,
                risk_score=55.0,
                confidence_score=0.65,
                evidence={"connection_count": len(ports), "unique_peers": unique_targets},
                mitre_technique="T1046",
            ).insert()
            counts["ids"] += 1

    return counts


def _sev(value: float, critical_at: float, critical: str, high: str) -> str:
    return critical if value >= critical_at else high


async def pentest_from_live_traffic(snapshot: Dict[str, Any]) -> int:
    """Real-time pentest rows from live connections (one per ~25s collection cycle)."""
    from backend.app.engines.pentest_monitor import PentestMonitor

    hostname = snapshot.get("hostname") or "localhost"
    connections = snapshot.get("network_connections") or []
    if not connections:
        return 0

    ports, targets = _parse_remote_ports(connections)
    inserted = 0
    monitor = PentestMonitor()
    scan_rate = max(2.0, len(ports) / max(len(set(targets)), 1))
    try:
        source_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        source_ip = hostname

    for pt in monitor.analyze_scan_behavior(source_ip, ports or [443, 80, 22], scan_rate):
        sig = pt.get("signature", "")
        if await _recent_pentest(sig):
            continue
        await PentestDetection(
            tool_name=pt["tool_name"],
            tool_category=pt.get("tool_category"),
            source_ip=pt.get("source_ip", source_ip),
            target_ip=pt.get("target_ip"),
            target_port=pt.get("target_port"),
            signature=sig,
            confidence=pt["confidence"],
            severity=pt["severity"],
            metadata={**pt.get("metadata", {}), "source": "live_traffic"},
        ).insert()
        inserted += 1

    cycle_sig = f"live:telemetry:{hostname}:{int(utcnow().timestamp()) // 25}"
    if not await _recent_pentest(cycle_sig):
        await PentestDetection(
            tool_name="nmap",
            tool_category="port_scanner",
            source_ip=source_ip,
            signature=cycle_sig,
            confidence=min(0.88, 0.55 + len(connections) * 0.03),
            severity="medium" if len(connections) >= 10 else "low",
            metadata={
                "active_connections": len(connections),
                "unique_peers": len(set(targets)),
                "ports_observed": ports[:20],
                "source": "live_collection",
                "real_time": True,
            },
        ).insert()
        inserted += 1

    return inserted


async def record_discovery_pentest(
    subnet: str,
    devices: List[Dict[str, Any]],
    scan_ports: bool,
) -> int:
    """Pentest-style detection when network discovery runs with port scan."""
    from backend.app.engines.pentest_monitor import PentestMonitor

    if not devices:
        return 0
    monitor = PentestMonitor()
    all_ports: List[int] = []
    for dev in devices:
        all_ports.extend(dev.get("open_ports") or [])
    scan_rate = max(1.0, len(all_ports) / max(len(devices), 1))
    source = socket.gethostbyname(socket.gethostname())
    inserted = 0
    for pt in monitor.analyze_scan_behavior(source, all_ports or [22, 80, 443], scan_rate):
        sig = pt.get("signature", "")
        if await _recent_pentest(sig):
            continue
        await PentestDetection(
            tool_name=pt["tool_name"],
            tool_category=pt.get("tool_category"),
            source_ip=pt.get("source_ip", source),
            target_ip=pt.get("target_ip"),
            target_port=pt.get("target_port"),
            signature=sig,
            confidence=pt["confidence"],
            severity=pt["severity"],
            metadata={**pt.get("metadata", {}), "subnet": subnet, "discovery": True},
        ).insert()
        inserted += 1
    if scan_ports and len(devices) >= 3:
        sig = f"discovery:recon:{subnet}:{len(devices)}"
        if not await _recent_pentest(sig):
            await PentestDetection(
                tool_name="nmap",
                tool_category="port_scanner",
                source_ip=source,
                signature=sig,
                confidence=0.8,
                severity="medium",
                metadata={"device_count": len(devices), "subnet": subnet},
            ).insert()
            inserted += 1
    return inserted
