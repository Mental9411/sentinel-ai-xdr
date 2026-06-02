"""UEBA Engine - behavioral baselines and insider threat detection."""
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.models.enums import AlertSeverity, EntityType, ThreatCategory


class UEBAEngine:
    """User and Entity Behavior Analytics with dynamic risk scoring."""

    INSIDER_THREAT_RULES = {
        "data_exfiltration": {"metric": "bytes_out", "multiplier": 3.0, "category": ThreatCategory.DATA_EXFILTRATION},
        "excessive_downloads": {"metric": "download_count", "multiplier": 2.5, "category": ThreatCategory.INSIDER_THREAT},
        "unusual_hours": {"metric": "hour_of_day", "std_threshold": 2.0, "category": ThreatCategory.INSIDER_THREAT},
        "privilege_escalation": {"metric": "privilege_events", "multiplier": 1.0, "category": ThreatCategory.PRIVILEGE_ESCALATION},
        "lateral_movement": {"metric": "unique_hosts", "multiplier": 2.0, "category": ThreatCategory.LATERAL_MOVEMENT},
        "credential_misuse": {"metric": "failed_auth", "multiplier": 2.0, "category": ThreatCategory.BRUTE_FORCE},
        "usb_abuse": {"metric": "usb_events", "multiplier": 1.0, "category": ThreatCategory.INSIDER_THREAT},
        "shadow_it": {"metric": "unauthorized_apps", "multiplier": 1.5, "category": ThreatCategory.POLICY_VIOLATION},
    }

    def __init__(self):
        self._baselines: Dict[str, Dict[str, Dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
        self._samples: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))

    def update_baseline(self, entity_type: EntityType, entity_id: str, metric: str, value: float) -> None:
        key = f"{entity_type.value}:{entity_id}"
        samples = self._samples[key][metric]
        samples.append(value)
        if len(samples) > 1000:
            samples.pop(0)
        if len(samples) >= 10:
            mean = sum(samples) / len(samples)
            variance = sum((x - mean) ** 2 for x in samples) / len(samples)
            std = math.sqrt(variance) if variance > 0 else 0.01
            self._baselines[key][metric] = {"mean": mean, "std": std, "count": len(samples)}

    def calculate_anomaly_score(self, entity_type: EntityType, entity_id: str, metrics: Dict[str, float]) -> Dict[str, Any]:
        key = f"{entity_type.value}:{entity_id}"
        anomalies = []
        total_score = 0.0
        for metric, value in metrics.items():
            baseline = self._baselines[key].get(metric)
            if baseline and baseline["std"] > 0:
                z_score = abs(value - baseline["mean"]) / baseline["std"]
                if z_score > 2.0:
                    anomalies.append({"metric": metric, "z_score": z_score, "value": value, "baseline_mean": baseline["mean"]})
                    total_score += min(z_score * 10, 30)
        risk_score = min(100, total_score)
        severity = self._score_to_severity(risk_score)
        return {
            "entity_type": entity_type.value,
            "entity_id": entity_id,
            "risk_score": risk_score,
            "confidence": min(0.99, 0.5 + len(anomalies) * 0.1),
            "severity": severity,
            "anomalies": anomalies,
            "threat_categories": list({self._metric_to_category(a["metric"]) for a in anomalies}),
        }

    def detect_insider_threats(self, user_id: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        threats = []
        metrics = self._aggregate_user_metrics(events)
        for rule_name, rule in self.INSIDER_THREAT_RULES.items():
            metric_val = metrics.get(rule["metric"], 0)
            baseline = self._baselines.get(f"user:{user_id}", {}).get(rule["metric"])
            if baseline:
                threshold = baseline["mean"] + rule.get("multiplier", 2) * baseline["std"]
                if metric_val > threshold:
                    threats.append({
                        "rule": rule_name,
                        "threat_category": rule["category"].value,
                        "risk_score": min(100, (metric_val / max(threshold, 1)) * 50),
                        "confidence": 0.8,
                        "severity": AlertSeverity.HIGH.value,
                        "evidence": {"metric": rule["metric"], "value": metric_val, "threshold": threshold},
                    })
        hour = datetime.now(timezone.utc).hour
        if metrics.get("typical_hours") and hour not in metrics["typical_hours"]:
            threats.append({
                "rule": "unusual_working_hours",
                "threat_category": ThreatCategory.INSIDER_THREAT.value,
                "risk_score": 65,
                "confidence": 0.75,
                "severity": AlertSeverity.MEDIUM.value,
                "evidence": {"current_hour": hour},
            })
        return threats

    def _aggregate_user_metrics(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        metrics: Dict[str, Any] = defaultdict(float)
        hosts = set()
        for e in events:
            metrics["bytes_out"] += e.get("bytes_out", 0)
            metrics["download_count"] += 1 if "download" in e.get("event_type", "").lower() else 0
            metrics["failed_auth"] += 1 if "failed" in e.get("event_type", "").lower() else 0
            metrics["privilege_events"] += 1 if "privilege" in e.get("event_type", "").lower() else 0
            metrics["usb_events"] += 1 if "usb" in e.get("event_type", "").lower() else 0
            if e.get("hostname"):
                hosts.add(e["hostname"])
        metrics["unique_hosts"] = len(hosts)
        return dict(metrics)

    def _score_to_severity(self, score: float) -> str:
        if score >= 80:
            return AlertSeverity.CRITICAL.value
        if score >= 60:
            return AlertSeverity.HIGH.value
        if score >= 40:
            return AlertSeverity.MEDIUM.value
        if score >= 20:
            return AlertSeverity.LOW.value
        return AlertSeverity.INFORMATIONAL.value

    def _metric_to_category(self, metric: str) -> str:
        mapping = {
            "bytes_out": "data_exfiltration",
            "failed_auth": "credential_misuse",
            "unique_hosts": "lateral_movement",
            "privilege_events": "privilege_escalation",
        }
        return mapping.get(metric, "anomaly")
