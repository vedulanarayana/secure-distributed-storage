from anomaly import score as score_module
from anomaly.features import AccessFeatures, extract_features
from anomaly.score import score_event
from anomaly.train import train


def test_normal_event_not_flagged():
    score_module._model = train(n_samples=1000, seed=1)

    features = AccessFeatures(
        request_rate=4.0, off_hours=0.0, bytes_transferred=2_000_000.0, failed_auth_count=0.0
    )
    _, is_outlier = score_event(features)
    assert not is_outlier


def test_extreme_outlier_is_flagged():
    score_module._model = train(n_samples=1000, seed=1)

    features = AccessFeatures(
        request_rate=500.0, off_hours=1.0, bytes_transferred=5_000_000_000.0, failed_auth_count=25.0
    )
    _, is_outlier = score_event(features)
    assert is_outlier


def test_extract_features_counts_recent_failures():
    recent = [{"success": True}, {"success": False}, {"success": False}]
    current = {"timestamp": 1_700_000_000.0, "bytes_transferred": 1000}
    features = extract_features(recent, current)
    assert features.failed_auth_count == 2
    assert features.request_rate == 3
