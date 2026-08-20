"""Trains the access-pattern anomaly detector on a simulated normal-access dataset.

There is no real production traffic to learn from in this project, so
"normal" is defined explicitly here: a handful of requests per session,
almost always during business hours, moving a few hundred KB to a few MB,
with authentication that almost always succeeds. The model then flags
anything that looks statistically unlike that baseline. This is an honest
simplification, not a stand-in for training on live access logs.
"""

import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = Path(__file__).parent / "model" / "isolation_forest.joblib"


def generate_normal_dataset(n_samples: int = 2000, seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    request_rate = rng.normal(loc=4, scale=1.5, size=n_samples).clip(min=0)
    off_hours = rng.binomial(n=1, p=0.08, size=n_samples).astype(float)
    bytes_transferred = rng.lognormal(mean=14, sigma=0.6, size=n_samples)
    failed_auth = rng.binomial(n=1, p=0.03, size=n_samples).astype(float)
    return np.column_stack([request_rate, off_hours, bytes_transferred, failed_auth])


def train(n_samples: int = 2000, seed: int = 42, contamination: float = 0.05) -> IsolationForest:
    data = generate_normal_dataset(n_samples, seed)
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(data)
    return model


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the access-pattern anomaly detector on a simulated normal-access dataset."
    )
    parser.add_argument("--samples", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    model = train(args.samples, args.seed, args.contamination)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"model written to {MODEL_PATH}")


if __name__ == "__main__":
    main()
