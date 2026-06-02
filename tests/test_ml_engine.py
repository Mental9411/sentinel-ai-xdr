"""Unit tests for ML detection engine."""
from backend.app.ml.detection_engine import MLDetectionEngine


def test_ml_predict():
    engine = MLDetectionEngine(model_dir="data/models")
    result = engine.predict({
        "bytes_out": 5000,
        "connection_count": 10,
        "failed_auth": 0,
    })
    assert "risk_score" in result
    assert "severity" in result
    assert "ensemble_scores" in result
    assert 0 <= result["risk_score"] <= 100


def test_ml_fit():
    engine = MLDetectionEngine(model_dir="data/models")
    data = [{"bytes_out": i * 100, "connection_count": i} for i in range(20)]
    metrics = engine.fit(data)
    assert metrics["samples"] == 20
