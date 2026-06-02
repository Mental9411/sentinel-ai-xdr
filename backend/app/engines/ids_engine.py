"""IDS/IPS Engine - Scapy-based detection with Suricata/Snort log parsing."""
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from backend.app.config import get_settings

settings = get_settings()


class IDSEngine:
    """Real-time intrusion detection with monitor and prevention modes."""

    DETECTION_RULES = {
        "port_scan": {"threshold": 15, "window_seconds": 60, "severity": "medium", "mitre": "T1046"},
        "syn_flood": {"threshold": 100, "window_seconds": 10, "severity": "high", "mitre": "T1498"},
        "dns_tunneling": {"query_length": 100, "severity": "high", "mitre": "T1071.004"},
        "brute_force": {"failed_attempts": 10, "window_seconds": 300, "severity": "high", "mitre": "T1110"},
        "arp_spoofing": {"duplicate_mac": True, "severity": "critical", "mitre": "T1557.002"},
        "beaconing": {"interval_variance": 5, "severity": "high", "mitre": "T1071"},
        "data_exfiltration": {"bytes_threshold": 50_000_000, "severity": "critical", "mitre": "T1048"},
        "c2_traffic": {"patterns": [r"\.onion\.", r"beacon", r"c2\."], "severity": "critical", "mitre": "T1071"},
    }

    def __init__(self, mode: str = "monitor"):
        self.mode = mode or settings.ids_mode
        self._port_scan_tracker: Dict[str, List[datetime]] = defaultdict(list)
        self._src_scan_tracker: Dict[str, List[datetime]] = defaultdict(list)
        self._syn_tracker: Dict[str, int] = defaultdict(int)
        self._arp_table: Dict[str, str] = {}
        self._beacon_intervals: Dict[str, List[float]] = defaultdict(list)
        self._connection_bytes: Dict[str, int] = defaultdict(int)

    def process_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        src = packet.get("src_ip", "")
        dst = packet.get("dst_ip", "")
        dst_port = packet.get("dst_port")
        flags = str(packet.get("flags", ""))

        if dst_port and src:
            now = datetime.now(timezone.utc)
            window = self.DETECTION_RULES["port_scan"]["window_seconds"]
            threshold = self.DETECTION_RULES["port_scan"]["threshold"]
            cutoff = now - timedelta(seconds=window)
            for tracker_key, tracker in [(f"{src}->{dst}", self._port_scan_tracker), (src, self._src_scan_tracker)]:
                tracker[tracker_key].append(now)
                tracker[tracker_key] = [t for t in tracker[tracker_key] if t > cutoff]
            if len(self._src_scan_tracker[src]) >= threshold:
                alerts.append(self._make_alert("port_scan", src, dst, dst_port, "Port scan detected (multiple targets)"))
            elif len(self._port_scan_tracker[f"{src}->{dst}"]) >= threshold:
                alerts.append(self._make_alert("port_scan", src, dst, dst_port, "Port scan detected (multiple ports)"))

        if "S" in flags and "A" not in flags:
            self._syn_tracker[src] += 1
            if self._syn_tracker[src] >= self.DETECTION_RULES["syn_flood"]["threshold"]:
                alerts.append(self._make_alert("syn_flood", src, dst, None, "SYN flood detected"))

        dns_query = packet.get("dns_query", "")
        if dns_query and len(dns_query) > self.DETECTION_RULES["dns_tunneling"]["query_length"]:
            alerts.append(self._make_alert("dns_tunneling", src, dst, 53, f"Long DNS query: {dns_query[:50]}"))

        for pattern in self.DETECTION_RULES["c2_traffic"]["patterns"]:
            if re.search(pattern, str(packet), re.IGNORECASE):
                alerts.append(self._make_alert("c2_traffic", src, dst, dst_port, "C2 traffic pattern"))

        return alerts

    def parse_suricata_alert(self, log_line: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(log_line)
            alert = data.get("alert", data)
            return self._make_alert(
                alert.get("category", "suricata"),
                data.get("src_ip", ""),
                data.get("dest_ip", ""),
                data.get("dest_port"),
                alert.get("signature", "Suricata alert"),
                engine="suricata",
                severity=alert.get("severity", 2),
            )
        except json.JSONDecodeError:
            return None

    def parse_snort_alert(self, log_line: str) -> Optional[Dict[str, Any]]:
        match = re.search(r"\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.+?)\s+\[\*\*\]", log_line)
        if match:
            parts = log_line.split()
            src = parts[-2] if len(parts) > 2 else ""
            return self._make_alert("snort", src, "", None, match.group(1), engine="snort")
        return None

    def check_arp_spoofing(self, ip: str, mac: str) -> Optional[Dict[str, Any]]:
        if ip in self._arp_table and self._arp_table[ip] != mac:
            return self._make_alert("arp_spoofing", ip, "", None, f"ARP spoof: {ip} was {self._arp_table[ip]} now {mac}")
        self._arp_table[ip] = mac
        return None

    def _make_alert(
        self, rule: str, src: str, dst: str, port: Optional[int],
        message: str, engine: str = "ids", severity: Optional[Any] = None,
    ) -> Dict[str, Any]:
        rule_cfg = self.DETECTION_RULES.get(rule, {})
        sev = severity if isinstance(severity, str) else rule_cfg.get("severity", "medium")
        return {
            "rule": rule,
            "engine": engine,
            "source_ip": src,
            "dest_ip": dst,
            "port": port,
            "message": message,
            "severity": sev,
            "mitre_technique": rule_cfg.get("mitre"),
            "mode": self.mode,
            "requires_approval": self.mode == "prevention" and settings.ips_require_approval,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def request_prevention(self, target_ip: str, action_type: str = "block") -> Dict[str, Any]:
        return {
            "action_type": action_type,
            "target_ip": target_ip,
            "status": "pending",
            "requires_approval": settings.ips_require_approval,
            "mode": self.mode,
        }
