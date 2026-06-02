"""Real-time event ingestion and processing pipeline (MongoDB)."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from backend.app.collectors.endpoint_collector import collect_endpoint_snapshot
from backend.app.collectors.packet_capture import get_recent_packets
from backend.app.services.endpoint_threat_analyzer import (
    analyze_endpoint_snapshot,
    build_packets_from_snapshot,
)
from backend.app.core.redis_cache import publish_event
from backend.app.engines.ids_engine import IDSEngine
from backend.app.engines.pentest_monitor import PentestMonitor
from backend.app.engines.ueba_engine import UEBAEngine
from backend.app.ml.detection_engine import MLDetectionEngine
from backend.app.models.documents import Alert, PentestDetection, RiskScore, SecurityEvent
from backend.app.models.enums import AlertSeverity, AlertStatus, EntityType, EventSource, ThreatCategory

ueba_engine = UEBAEngine()
ids_engine = IDSEngine()
pentest_monitor = PentestMonitor()
ml_engine = MLDetectionEngine(model_dir="data/models")


def _parse_severity(value: str) -> AlertSeverity:
    try:
        return AlertSeverity(value.lower())
    except ValueError:
        return AlertSeverity.MEDIUM


async def ingest_event(event_data: Dict[str, Any], source: EventSource) -> SecurityEvent:
    fp = hashlib.sha256(json.dumps(event_data, sort_keys=True, default=str).encode()).hexdigest()[:32]
    ts = event_data.get("timestamp")
    if isinstance(ts, str):
        event_timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    else:
        event_timestamp = datetime.now(timezone.utc)

    event = SecurityEvent(
        source=source,
        event_type=event_data.get("event_type", "unknown"),
        event_timestamp=event_timestamp,
        hostname=event_data.get("hostname"),
        source_ip=event_data.get("source_ip") or event_data.get("src_ip"),
        dest_ip=event_data.get("dest_ip") or event_data.get("dst_ip"),
        username=event_data.get("username"),
        process_name=event_data.get("process_name"),
        severity=event_data.get("severity", "informational"),
        raw_log=event_data.get("raw", json.dumps(event_data)[:5000]),
        normalized_data=event_data,
        mitre_technique=event_data.get("mitre_technique"),
        fingerprint=fp,
    )
    await event.insert()
    await publish_event(
        "sentinel:events:stream",
        {"id": str(event.id), "source": source.value, "type": event.event_type},
    )
    return event


async def process_realtime_cycle() -> Dict[str, Any]:
    stats = {"events": 0, "alerts": 0, "pentest": 0, "devices": 0}

    snapshot = collect_endpoint_snapshot()
    await ingest_event(
        {**snapshot, "event_type": "endpoint_snapshot", "timestamp": snapshot["collected_at"]},
        EventSource.ENDPOINT,
    )
    stats["events"] += 1

    for auth_evt in snapshot.get("logged_in_users", []):
        await ingest_event(
            {
                **auth_evt,
                "event_type": "authentication",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": snapshot["hostname"],
            },
            EventSource.AUTH,
        )
        stats["events"] += 1

    ep_counts = await analyze_endpoint_snapshot(snapshot)
    stats["alerts"] += ep_counts.get("ids", 0)
    stats["pentest"] += ep_counts.get("pentest", 0)

    packets = get_recent_packets(50)
    if not packets:
        packets = build_packets_from_snapshot(snapshot)

    for pkt in packets:
        for alert_data in ids_engine.process_packet(pkt):
            await _create_alert_from_detection(alert_data, EventSource.NETWORK)
            stats["alerts"] += 1
        for pt in pentest_monitor.analyze_packet(pkt):
            await PentestDetection(
                tool_name=pt["tool_name"],
                tool_category=pt.get("tool_category"),
                source_ip=pt.get("source_ip", "unknown"),
                target_ip=pt.get("target_ip"),
                target_port=pt.get("target_port"),
                signature=pt["signature"],
                confidence=pt["confidence"],
                severity=pt["severity"],
                metadata=pt.get("metadata", {}),
            ).insert()
            stats["pentest"] += 1

    ml_result = ml_engine.predict(_snapshot_to_ml_features(snapshot, packets))
    if ml_result["risk_score"] > 40:
        alert = Alert(
            title=f"ML Anomaly Detected - {ml_result['threat_type']}",
            description=f"Ensemble risk score: {ml_result['risk_score']}",
            severity=_parse_severity(ml_result.get("severity", "medium")),
            status=AlertStatus.NEW,
            threat_category=ThreatCategory.ANOMALY,
            risk_score=ml_result["risk_score"],
            confidence_score=ml_result["confidence"],
            source="ml_engine",
            detection_engine="ensemble",
            mitre_technique=ml_result["mitre_technique"],
            mitre_tactic=ml_result["mitre_tactic"],
            hostname=snapshot.get("hostname"),
            evidence=ml_result,
        )
        await alert.insert()
        stats["alerts"] += 1

    ueba_result = ueba_engine.calculate_anomaly_score(
        EntityType.HOST,
        snapshot["hostname"],
        {
            "cpu_percent": snapshot["cpu_percent"],
            "memory_percent": snapshot["memory_percent"],
            "connection_count": len(snapshot.get("network_connections", [])),
        },
    )
    await RiskScore(
        entity_type=EntityType.HOST,
        entity_id=snapshot["hostname"],
        risk_score=ueba_result["risk_score"],
        confidence=ueba_result["confidence"],
        severity=ueba_result["severity"],
        threat_categories=ueba_result.get("threat_categories", []),
        ml_ensemble_score=ml_result["risk_score"],
    ).insert()

    return stats


async def _create_alert_from_detection(data: Dict, source: EventSource) -> Alert:
    title = data.get("message", "IDS Alert")
    engine = data.get("engine", "ids")
    since = datetime.now(timezone.utc) - timedelta(minutes=10)
    existing = await Alert.find(
        Alert.title == title,
        Alert.detection_engine == engine,
        Alert.created_at >= since,
    ).limit(1).to_list()
    if existing:
        return existing[0]

    sev_map = {
        "critical": AlertSeverity.CRITICAL,
        "high": AlertSeverity.HIGH,
        "medium": AlertSeverity.MEDIUM,
        "low": AlertSeverity.LOW,
    }
    alert = Alert(
        title=data.get("message", "IDS Alert"),
        severity=sev_map.get(data.get("severity", "medium"), AlertSeverity.MEDIUM),
        status=AlertStatus.NEW,
        threat_category=ThreatCategory.NETWORK_INTRUSION,
        source=source.value,
        detection_engine=data.get("engine", "ids"),
        source_ip=data.get("source_ip"),
        dest_ip=data.get("dest_ip"),
        mitre_technique=data.get("mitre_technique"),
        evidence=data,
        risk_score=70 if data.get("severity") == "critical" else 50,
        confidence_score=0.85,
    )
    await alert.insert()
    await publish_event(
        "sentinel:alerts:stream",
        {"title": alert.title, "severity": alert.severity.value},
    )
    return alert


def _snapshot_to_ml_features(snapshot: Dict, packets: List[Dict]) -> Dict[str, Any]:
    return {
        "bytes_in": snapshot.get("net_bytes_recv", 0),
        "bytes_out": snapshot.get("net_bytes_sent", 0),
        "connection_count": len(snapshot.get("network_connections", [])),
        "cpu_percent": snapshot.get("cpu_percent", 0),
        "memory_percent": snapshot.get("memory_percent", 0),
        "process_count": len(snapshot.get("top_processes", [])),
        "connections": [
            {"src": p.get("local"), "dst": p.get("remote")}
            for p in snapshot.get("network_connections", [])
        ],
        "event_history": packets[-10:],
    }
