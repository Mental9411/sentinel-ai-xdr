"""Live packet capture using Scapy - real network traffic."""
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional

try:
    from scapy.all import IP, TCP, UDP, DNS, sniff  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

_packet_buffer: Deque[Dict[str, Any]] = deque(maxlen=1000)
_capture_running = False
_capture_thread: Optional[threading.Thread] = None


def _process_packet(packet) -> None:
    record: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "length": len(packet),
    }
    if packet.haslayer(IP):
        record["src_ip"] = packet[IP].src
        record["dst_ip"] = packet[IP].dst
        record["protocol"] = packet[IP].proto
    if packet.haslayer(TCP):
        record["src_port"] = packet[TCP].sport
        record["dst_port"] = packet[TCP].dport
        record["flags"] = str(packet[TCP].flags)
    if packet.haslayer(UDP):
        record["src_port"] = packet[UDP].sport
        record["dst_port"] = packet[UDP].dport
    if packet.haslayer(DNS) and packet.haslayer(DNS) and packet[DNS].qd:
        record["dns_query"] = packet[DNS].qd.qname.decode(errors="ignore")
    _packet_buffer.append(record)


def start_capture(interface: Optional[str] = None, filter_str: str = "ip") -> bool:
    global _capture_running, _capture_thread
    if not SCAPY_AVAILABLE or _capture_running:
        return False

    def _run():
        global _capture_running
        _capture_running = True
        try:
            sniff(iface=interface, prn=_process_packet, filter=filter_str, store=False)
        except Exception:
            pass
        finally:
            _capture_running = False

    _capture_thread = threading.Thread(target=_run, daemon=True)
    _capture_thread.start()
    return True


def stop_capture() -> None:
    global _capture_running
    _capture_running = False


def get_recent_packets(limit: int = 100) -> List[Dict[str, Any]]:
    return list(_packet_buffer)[-limit:]


def is_capturing() -> bool:
    return _capture_running
