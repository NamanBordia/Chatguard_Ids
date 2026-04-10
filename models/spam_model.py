from __future__ import annotations

import csv
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from .text_utils import confidence_to_severity, normalize_text

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "spam.csv"

_MODEL: Pipeline | None = None
_MODEL_LOCK = Lock()

_POSITIVE = {"spam"}
_NEGATIVE = {"safe", "ham", "normal"}

_USER_TIMESTAMPS: dict[str, deque[float]] = defaultdict(deque)
_STATE_LOCK = Lock()


def _read_rows(path: Path) -> list[tuple[str, int]]:
    if not path.exists():
        return []
    rows: list[tuple[str, int]] = []
    encodings = ["utf-8", "utf-8-sig", "cp1252", "latin-1"]

    for enc in encodings:
        try:
            rows.clear()
            with path.open("r", encoding=enc, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    text = str(row.get("v2", row.get("text", ""))).strip()
                    label = str(row.get("v1", row.get("label", ""))).strip().lower()
                    if not text:
                        continue
                    if label in _POSITIVE:
                        rows.append((text, 1))
                    elif label in _NEGATIVE:
                        rows.append((text, 0))
            return rows
        except UnicodeDecodeError:
            continue

    # Final fallback: replace undecodable bytes instead of failing training.
    rows.clear()
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = str(row.get("v2", row.get("text", ""))).strip()
            label = str(row.get("v1", row.get("label", ""))).strip().lower()
            if not text:
                continue
            if label in _POSITIVE:
                rows.append((text, 1))
            elif label in _NEGATIVE:
                rows.append((text, 0))
    return rows


def _seed_rows() -> list[tuple[str, int]]:
    return [
        ("hello bob", 0),
        ("meeting at 5", 0),
        ("please review this", 0),
        ("buy now buy now buy now", 1),
        ("free reward click now", 1),
        ("limited offer act fast", 1),
    ]


def _build_dataset() -> tuple[list[str], list[int]]:
    rows = _seed_rows()
    rows.extend(_read_rows(DATA_FILE))
    X = [normalize_text(text) for text, _ in rows]
    y = [label for _, label in rows]
    return X, y


def train_model(force_retrain: bool = False) -> Pipeline:
    global _MODEL
    with _MODEL_LOCK:
        if _MODEL is not None and not force_retrain:
            return _MODEL
        X, y = _build_dataset()
        model = Pipeline(
            [
                ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=15000)),
                ("clf", MultinomialNB(alpha=0.4)),
            ]
        )
        model.fit(X, y)
        _MODEL = model
        return model


def _rate_rule(user: str) -> tuple[bool, float]:
    now = time.time()
    with _STATE_LOCK:
        q = _USER_TIMESTAMPS[user]
        q.append(now)
        while q and now - q[0] > 10:
            q.popleft()
        count = len(q)

    if count > 8:
        return True, 0.95
    if count > 5:
        return True, 0.8
    return False, 0.0


def predict(user: str, message: str) -> dict:
    model = train_model()
    cleaned = normalize_text(message)
    ml_prob = float(model.predict_proba([cleaned])[0][1])

    rate_flag, rate_score = _rate_rule(user)
    combined = max(ml_prob, rate_score)

    is_threat = combined >= 0.5
    severity = confidence_to_severity(combined, low=0.5, medium=0.7, high=0.88)

    return {
        "is_threat": is_threat,
        "type": "spam",
        "severity": severity if is_threat else "low",
        "confidence": round(combined, 3),
        "signals": {"ml_prob": round(ml_prob, 3), "rate_rule": rate_flag},
    }
