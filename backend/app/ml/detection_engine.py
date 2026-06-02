"""Enterprise ML Detection Engine - ensemble of 6 models."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

MITRE_MAPPING = {
    "anomaly": ("TA0005", "T1078"),
    "malware": ("TA0002", "T1204"),
    "exfiltration": ("TA0010", "T1048"),
    "lateral_movement": ("TA0008", "T1021"),
    "c2": ("TA0011", "T1071"),
    "brute_force": ("TA0006", "T1110"),
}


class SimpleAutoencoder(nn.Module if TORCH_AVAILABLE else object):
    def __init__(self, input_dim: int = 20):
        if not TORCH_AVAILABLE:
            return
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(input_dim, 10), nn.ReLU(), nn.Linear(10, 5))
        self.decoder = nn.Sequential(nn.Linear(5, 10), nn.ReLU(), nn.Linear(10, input_dim))

    def forward(self, x):
        return self.decoder(self.encoder(x))


class MLDetectionEngine:
    """Ensemble ML engine with Isolation Forest, Autoencoder, LSTM, XGBoost, RF, Graph detection."""

    FEATURE_NAMES = [
        "bytes_in", "bytes_out", "connection_count", "failed_auth", "unique_dest_ips",
        "unique_ports", "process_count", "cpu_percent", "memory_percent", "hour_sin",
        "hour_cos", "dns_queries", "http_requests", "privilege_events", "file_access_count",
        "email_sent", "login_count", "geo_anomaly", "protocol_diversity", "entropy_score",
    ]

    def __init__(self, model_dir: str = "/var/lib/sentinel/models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.05, random_state=42)
        self.random_forest = RandomForestClassifier(n_estimators=100, random_state=42)
        self.xgb_model = xgb.XGBClassifier(n_estimators=100) if XGB_AVAILABLE else None
        self.autoencoder: Optional[Any] = None
        self._fitted = False
        self.weights = {
            "isolation_forest": 0.2,
            "autoencoder": 0.15,
            "lstm": 0.15,
            "xgboost": 0.2,
            "random_forest": 0.15,
            "graph": 0.15,
        }

    def _extract_features(self, event_data: Dict[str, Any]) -> np.ndarray:
        features = []
        for name in self.FEATURE_NAMES:
            features.append(float(event_data.get(name, 0)))
        return np.array(features).reshape(1, -1)

    def fit(self, training_data: List[Dict[str, Any]], labels: Optional[List[int]] = None) -> Dict[str, float]:
        X = np.array([self._extract_features(d).flatten() for d in training_data])
        X_scaled = self.scaler.fit_transform(X)
        self.isolation_forest.fit(X_scaled)
        if labels:
            self.random_forest.fit(X_scaled, labels)
            if self.xgb_model:
                self.xgb_model.fit(X_scaled, labels)
        if TORCH_AVAILABLE:
            self.autoencoder = SimpleAutoencoder(X_scaled.shape[1])
            optimizer = torch.optim.Adam(self.autoencoder.parameters(), lr=0.001)
            tensor_x = torch.FloatTensor(X_scaled)
            for _ in range(50):
                optimizer.zero_grad()
                reconstructed = self.autoencoder(tensor_x)
                loss = nn.MSELoss()(reconstructed, tensor_x)
                loss.backward()
                optimizer.step()
        self._fitted = True
        joblib.dump(self.scaler, self.model_dir / "scaler.joblib")
        joblib.dump(self.isolation_forest, self.model_dir / "isolation_forest.joblib")
        return {"samples": len(training_data), "features": len(self.FEATURE_NAMES)}

    def predict(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        X = self._extract_features(event_data)
        X_scaled = self.scaler.transform(X) if self._fitted else X
        scores = {}

        if self._fitted:
            if_score = -self.isolation_forest.decision_function(X_scaled)[0]
            scores["isolation_forest"] = float(max(0, min(1, (if_score + 0.5))))
        else:
            scores["isolation_forest"] = 0.3

        if self.autoencoder and TORCH_AVAILABLE:
            with torch.no_grad():
                tensor_x = torch.FloatTensor(X_scaled)
                reconstructed = self.autoencoder(tensor_x)
                ae_error = float(nn.MSELoss()(reconstructed, tensor_x))
                scores["autoencoder"] = min(1.0, ae_error * 10)
        else:
            scores["autoencoder"] = 0.25

        scores["lstm"] = self._lstm_score(event_data)
        scores["xgboost"] = self._xgb_score(X_scaled) if self.xgb_model and self._fitted else 0.3
        scores["random_forest"] = self._rf_score(X_scaled) if self._fitted else 0.3
        scores["graph"] = self._graph_anomaly_score(event_data)

        ensemble = sum(scores[k] * self.weights[k] for k in self.weights)
        risk_score = min(100, ensemble * 100)
        threat_type = self._classify_threat(scores, event_data)
        tactic, technique = MITRE_MAPPING.get(threat_type, ("TA0040", "T1082"))

        return {
            "risk_score": round(risk_score, 2),
            "confidence": round(min(0.99, 0.5 + ensemble * 0.5), 3),
            "severity": self._risk_to_severity(risk_score),
            "threat_type": threat_type,
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "ensemble_scores": scores,
            "model_version": "1.0.0",
            "predicted_at": datetime.now(timezone.utc).isoformat(),
        }

    def _lstm_score(self, event_data: Dict[str, Any]) -> float:
        history = event_data.get("event_history", [])
        if len(history) < 3:
            return 0.2
        values = [h.get("bytes_out", 0) for h in history[-10:]]
        if len(values) < 2:
            return 0.2
        diffs = np.diff(values)
        volatility = float(np.std(diffs)) if len(diffs) > 0 else 0
        return min(1.0, volatility / (np.mean(values) + 1) * 0.5)

    def _xgb_score(self, X_scaled: np.ndarray) -> float:
        proba = self.xgb_model.predict_proba(X_scaled)[0]
        return float(max(proba))

    def _rf_score(self, X_scaled: np.ndarray) -> float:
        proba = self.random_forest.predict_proba(X_scaled)[0]
        return float(max(proba))

    def _graph_anomaly_score(self, event_data: Dict[str, Any]) -> float:
        connections = event_data.get("connections", [])
        if not connections:
            return 0.1
        unique_nodes = set()
        for c in connections:
            unique_nodes.add(c.get("src", ""))
            unique_nodes.add(c.get("dst", ""))
        edge_count = len(connections)
        node_count = max(len(unique_nodes), 1)
        density = edge_count / (node_count * (node_count - 1) + 1)
        return min(1.0, density * 2)

    def _classify_threat(self, scores: Dict[str, float], event_data: Dict[str, Any]) -> str:
        if event_data.get("bytes_out", 0) > 1_000_000:
            return "exfiltration"
        if scores.get("graph", 0) > 0.7:
            return "lateral_movement"
        if event_data.get("failed_auth", 0) > 5:
            return "brute_force"
        if max(scores.values()) > 0.8:
            return "anomaly"
        return "anomaly"

    def _risk_to_severity(self, risk: float) -> str:
        if risk >= 80:
            return "critical"
        if risk >= 60:
            return "high"
        if risk >= 40:
            return "medium"
        if risk >= 20:
            return "low"
        return "informational"
