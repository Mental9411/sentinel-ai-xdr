"""Unit tests for IDS engine."""
from backend.app.engines.ids_engine import IDSEngine


def test_port_scan_detection():
    engine = IDSEngine(mode="monitor")
    alerts = []
    for i in range(20):
        alerts.extend(engine.process_packet({
            "src_ip": "10.0.0.50",
            "dst_ip": f"10.0.0.{i + 1}",
            "dst_port": 80 + i,
        }))
    assert any(a["rule"] == "port_scan" for a in alerts)


def test_syn_flood_detection():
    engine = IDSEngine(mode="monitor")
    alerts = []
    for _ in range(110):
        alerts.extend(engine.process_packet({
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "flags": "S",
        }))
    assert any(a["rule"] == "syn_flood" for a in alerts)
