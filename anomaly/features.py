import datetime as dt
from dataclasses import dataclass
from typing import Any


@dataclass
class AccessFeatures:
    request_rate: float
    off_hours: float
    bytes_transferred: float
    failed_auth_count: float


def extract_features(recent_events: list[dict[str, Any]], current_event: dict[str, Any]) -> AccessFeatures:
    timestamp = current_event["timestamp"]
    hour = dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).hour
    off_hours = 1.0 if (hour < 8 or hour >= 20) else 0.0
    failed = sum(1 for e in recent_events if not e.get("success", True))
    return AccessFeatures(
        request_rate=float(len(recent_events)),
        off_hours=off_hours,
        bytes_transferred=float(current_event.get("bytes_transferred", 0)),
        failed_auth_count=float(failed),
    )


def to_vector(features: AccessFeatures) -> list[float]:
    return [
        features.request_rate,
        features.off_hours,
        features.bytes_transferred,
        features.failed_auth_count,
    ]
