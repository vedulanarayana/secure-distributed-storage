import joblib

from anomaly.features import AccessFeatures, to_vector
from anomaly.train import MODEL_PATH, train

_model = None


def get_model():
    global _model
    if _model is None:
        if MODEL_PATH.exists():
            _model = joblib.load(MODEL_PATH)
        else:
            # No trained model on disk yet (e.g. fresh checkout without
            # running `python -m anomaly.train`) - train one on the fly so
            # the service still comes up rather than hard-failing.
            _model = train()
    return _model


def score_event(features: AccessFeatures) -> tuple[float, bool]:
    """Score one access event. Higher (more positive) = more normal.

    Callers should treat `is_outlier` as a signal to require step-up
    authentication, not as an automatic block - see THREAT_MODEL.md.
    """
    model = get_model()
    vector = [to_vector(features)]
    raw_score = model.decision_function(vector)[0]
    is_outlier = model.predict(vector)[0] == -1
    return float(raw_score), bool(is_outlier)
