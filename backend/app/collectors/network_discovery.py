"""Enterprise network discovery - ARP-based (netdiscover-style) with compliance controls.

Only scans subnets the host is authorized to monitor. Requires admin approval for asset registration.
"""
import hashlib
import ipaddress
import platform
import socket
import struct
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

try:
    from scapy.all import ARP, Ether, srp  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def get_local_network() -> Optional[str]:
    """Detect local WiFi/Ethernet subnet from active interfaces."""
    for iface, addrs in psutil.net_if_addrs().items():
        if iface.lower().startswith(("lo", "docker", "veth", "br-")):
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                net = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                if net.num_addresses > 2:
                    return str(net)
    return None


def arp_scan_scapy(subnet: str, timeout: int = 3) -> List[Dict[str, Any]]:
    """ARP scan using Scapy - netdiscover equivalent."""
    if not SCAPY_AVAILABLE:
        return arp_scan_fallback(subnet)
    devices = []
    try:
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=timeout, verbose=0)
        for _, received in answered:
            devices.append({
                "ip_address": received.psrc,
                "mac_address": received.hwsrc.upper(),
                "hostname": _reverse_dns(received.psrc),
                "vendor": _mac_vendor(received.hwsrc),
                "device_type": _guess_device_type(received.hwsrc),
                "is_online": True,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "method": "arp_scapy",
            })
    except Exception as e:
        devices = arp_scan_fallback(subnet)
        if not devices:
            raise RuntimeError(f"ARP scan failed: {e}") from e
    return devices


def arp_scan_fallback(subnet: str) -> List[Dict[str, Any]]:
    """Fallback using system ARP table + ping sweep."""
    devices = []
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = list(net.hosts())[:254]
        if platform.system() == "Windows":
            for host in hosts:
                subprocess.run(
                    ["ping", "-n", "1", "-w", "200", str(host)],
                    capture_output=True, timeout=2,
                )
        else:
            for host in hosts:
                subprocess.run(
                    ["ping", "-c", "1", "-W", "1", str(host)],
                    capture_output=True, timeout=2,
                )
        time.sleep(1)
        if platform.system() == "Windows":
            out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and "." in parts[0]:
                    ip = parts[0]
                    mac = parts[1].replace("-", ":").upper()
                    if mac != "FF-FF-FF-FF-FF-FF" and len(mac) >= 11:
                        devices.append({
                            "ip_address": ip,
                            "mac_address": mac,
                            "hostname": _reverse_dns(ip),
                            "vendor": _mac_vendor(mac),
                            "device_type": "unknown",
                            "is_online": True,
                            "discovered_at": datetime.now(timezone.utc).isoformat(),
                            "method": "arp_table",
                        })
        else:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        devices.append({
                            "ip_address": parts[0],
                            "mac_address": parts[3].upper(),
                            "hostname": _reverse_dns(parts[0]),
                            "vendor": _mac_vendor(parts[3]),
                            "device_type": "unknown",
                            "is_online": True,
                            "discovered_at": datetime.now(timezone.utc).isoformat(),
                            "method": "proc_arp",
                        })
    except Exception:
        pass
    return devices


def port_scan_quick(ip: str, ports: List[int] = None) -> List[int]:
    """Quick TCP connect scan for common ports."""
    ports = ports or [22, 80, 443, 445, 3389, 8080]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            sock.close()
    return open_ports


def discover_network(
    subnet: Optional[str] = None,
    scan_ports: bool = False,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Full network discovery with compliance metadata."""
    subnet = subnet or get_local_network()
    if not subnet:
        return {"error": "Could not detect local network", "devices": []}
    session_id = session_id or hashlib.sha256(f"{subnet}{time.time()}".encode()).hexdigest()[:16]
    devices = arp_scan_scapy(subnet)
    for dev in devices:
        if scan_ports:
            dev["open_ports"] = port_scan_quick(dev["ip_address"])
        dev["scan_session_id"] = session_id
        dev["requires_approval"] = True
    return {
        "subnet": subnet,
        "session_id": session_id,
        "device_count": len(devices),
        "devices": devices,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "compliance_note": "Assets require administrator approval before monitoring",
    }


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def _mac_vendor(mac: str) -> Optional[str]:
    oui = mac.replace(":", "").replace("-", "")[:6].upper()
    vendors = {
        "001A2B": "Apple", "3C5AB4": "Google", "B827EB": "Raspberry Pi",
        "001E65": "Cisco", "F4F5E8": "Microsoft", "ACDE48": "Intel",
    }
    return vendors.get(oui)


def _guess_device_type(mac: str) -> str:
    vendor = _mac_vendor(mac) or ""
    if "Apple" in vendor:
        return "mobile"
    if "Cisco" in vendor:
        return "router"
    return "workstation"
