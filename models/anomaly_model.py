from __future__ import annotations

import csv
import math
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from sklearn.ensemble import IsolationForest

from .text_utils import confidence_to_severity

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "anomaly_baseline.csv"

_MODEL: IsolationForest | None = None
_MODEL_LOCK = Lock()

_STATE_LOCK = Lock()
_USER_STATE: dict[str, dict[str, object]] = defaultdict(lambda: {"times": deque(), "last": None, "lengths": deque()})


def _read_baseline(path: Path) -> list[list[float]]:
    if not path.exists():
        return []
    out: list[list[float]] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                out.append(
                    [
                        float(row.get("messages_per_minute", 0.0)),
                        float(row.get("message_length", 0.0)),
                        float(row.get("interval_seconds", 0.0)),
                    ]
                )
            except ValueError:
                continue
    return out


def _synthetic_normal() -> list[list[float]]:
    return [
        [2.0, 18.0, 12.0],
        [3.0, 22.0, 9.0],
        [4.0, 30.0, 8.0],
        [1.0, 12.0, 25.0],
        [5.0, 24.0, 7.0],
        [2.0, 40.0, 10.0],
        [3.0, 16.0, 14.0],
        [4.0, 28.0, 6.0],
    ]


def train_model(force_retrain: bool = False) -> IsolationForest:
    global _MODEL
    with _MODEL_LOCK:
        if _MODEL is not None and not force_retrain:
            return _MODEL

        rows = _synthetic_normal()
        rows.extend(_read_baseline(DATA_FILE))

        model = IsolationForest(contamination=0.08, random_state=42)
        model.fit(rows)
        _MODEL = model
        return model


def _build_user_features(user: str, message: str) -> tuple[list[float], int]:
    now = time.time()
    with _STATE_LOCK:
        state = _USER_STATE[user]
        times: deque[float] = state["times"]  # type: ignore[assignment]
        lengths: deque[int] = state["lengths"]  # type: ignore[assignment]

        times.append(now)
        lengths.append(len(message))

        while times and now - times[0] > 60:
            times.popleft()
        while len(lengths) > 200:
            lengths.popleft()

        if len(times) >= 2:
            avg_interval = max(0.01, (times[-1] - times[0]) / (len(times) - 1))
        else:
            avg_interval = 30.0

        msg_per_min = float(len(times))
        mean_len = float(sum(lengths) / len(lengths)) if lengths else float(len(message))
        observed = len(times)

    return [msg_per_min, mean_len, avg_interval], observed


def predict(user: str, message: str) -> dict:
    model = train_model()
    features, observed = _build_user_features(user, message)

    if observed < 8:
        return {
            "is_threat": False,
            "type": "anomaly",
            "severity": "low",
            "confidence": 0.0,
        }

    raw = float(model.decision_function([features])[0])
    anomaly_prob = 1.0 / (1.0 + math.exp(6.0 * raw))

    # Guardrail to avoid flagging normal short greetings.
    if features[0] < 8.0 and features[2] > 2.0:
        anomaly_prob *= 0.4

    is_threat = anomaly_prob >= 0.78
    severity = confidence_to_severity(anomaly_prob, low=0.78, medium=0.88, high=0.95)

    return {
        "is_threat": is_threat,
        "type": "anomaly",
        "severity": severity if is_threat else "low",
        "confidence": round(anomaly_prob, 3),
        "signals": {
            "messages_per_minute": round(features[0], 3),
            "mean_message_length": round(features[1], 3),
            "avg_interval_seconds": round(features[2], 3),
        },
    }
