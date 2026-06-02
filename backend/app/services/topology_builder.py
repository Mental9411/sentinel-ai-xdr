"""Build network topology graph and human-readable topology name from discovered devices."""
import ipaddress
from typing import Any, Dict, List, Optional, Tuple


TOPOLOGY_TYPES = {
    "empty": "Empty — run Network Discovery",
    "single_host": "Single Host",
    "star": "Star (Hub-and-Spoke)",
    "flat_lan": "Flat LAN (Layer-2)",
    "extended_lan": "Extended LAN",
}


def _ip_key(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def _find_gateway(devices: List[Dict[str, Any]], subnet: Optional[str]) -> Optional[str]:
    for d in devices:
        if d.get("device_type") in ("router", "gateway"):
            return d.get("ip_address")
    if subnet:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            gateway_guess = str(net.network_address + 1)
            for d in devices:
                if d.get("ip_address") == gateway_guess:
                    return gateway_guess
        except ValueError:
            pass
    if devices:
        return min(devices, key=lambda x: _ip_key(x.get("ip_address", "255.255.255.255"))).get("ip_address")
    return None


def classify_topology(
    devices: List[Dict[str, Any]], gateway_ip: Optional[str], subnet: Optional[str]
) -> Tuple[str, str, str]:
    """
    Returns (topology_type, topology_name, description).
    Types match common enterprise/home layouts detected from discovery.
    """
    n = len(devices)
    subnet_label = subnet or "local subnet"

    if n == 0:
        return (
            "empty",
            TOPOLOGY_TYPES["empty"],
            "No hosts found. Run Live Network Discovery from the dashboard sidebar.",
        )
    if n == 1:
        ip = devices[0].get("ip_address", "unknown")
        return (
            "single_host",
            f"Single Host Network — {ip}",
            "Only one device is visible (often the monitoring host or an isolated segment).",
        )

    routers = sum(1 for d in devices if d.get("device_type") in ("router", "gateway"))
    if gateway_ip and n >= 2:
        spokes = n - 1
        if routers >= 1:
            name = f"Star Topology — {subnet_label} · gateway {gateway_ip} · {spokes} spoke(s)"
        else:
            name = f"Star Topology (inferred hub) — {subnet_label} · hub {gateway_ip} · {spokes} device(s)"
        desc = (
            "Classic hub-and-spoke: endpoints connect through a central router/switch gateway. "
            "Typical for home WiFi, branch offices, and SOHO networks."
        )
        return ("star", name, desc)

    if n >= 8:
        return (
            "extended_lan",
            f"Extended LAN — {subnet_label} · {n} devices",
            "Many hosts on one segment without a clear gateway in scan data — common on large switched LANs.",
        )

    return (
        "flat_lan",
        f"Flat LAN (Layer-2) — {subnet_label} · {n} devices",
        "Devices share a broadcast domain (switch/VLAN). No dedicated router was identified in discovery.",
    )


def infer_topology_name(devices: List[Dict[str, Any]], gateway_ip: Optional[str], subnet: Optional[str]) -> str:
    _, name, _ = classify_topology(devices, gateway_ip, subnet)
    return name


def build_topology_graph(
    devices: List[Dict[str, Any]],
    subnet: Optional[str] = None,
) -> Dict[str, Any]:
    gateway_ip = _find_gateway(devices, subnet)
    topology_type, topology_name, topology_description = classify_topology(devices, gateway_ip, subnet)

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for d in devices:
        ip = d.get("ip_address", "")
        label = d.get("hostname") or ip
        role = "gateway" if ip == gateway_ip else d.get("device_type", "endpoint")
        nodes.append(
            {
                "id": ip,
                "label": label,
                "ip": ip,
                "mac": d.get("mac_address"),
                "vendor": d.get("vendor"),
                "device_type": d.get("device_type"),
                "role": role,
                "is_online": d.get("is_online", True),
            }
        )

    if len(devices) > 1 and gateway_ip:
        for d in devices:
            ip = d.get("ip_address")
            if ip and ip != gateway_ip:
                edges.append(
                    {
                        "source": gateway_ip,
                        "target": ip,
                        "type": "lan",
                    }
                )
    elif len(devices) > 1:
        hub = gateway_ip or devices[0].get("ip_address")
        for d in devices[1:]:
            ip = d.get("ip_address")
            if ip and ip != hub:
                edges.append({"source": hub, "target": ip, "type": "adjacent"})

    online = sum(1 for d in devices if d.get("is_online", True))
    return {
        "topology_type": topology_type,
        "topology_type_label": TOPOLOGY_TYPES.get(topology_type, topology_type),
        "topology_name": topology_name,
        "topology_description": topology_description,
        "subnet": subnet,
        "gateway_ip": gateway_ip,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "devices_online": online,
        "nodes": nodes,
        "edges": edges,
    }
