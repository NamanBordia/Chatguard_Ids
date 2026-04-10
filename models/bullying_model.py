from __future__ import annotations

import csv
from pathlib import Path
from threading import Lock

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .text_utils import confidence_to_severity, normalize_text

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

_MODEL: Pipeline | None = None
_LOCK = Lock()

_DATA_FILES = [
    "aggression_parsed_dataset.csv",
    "attack_parsed_dataset.csv",
    "kaggle_parsed_dataset.csv",
    "toxicity_parsed_dataset.csv",
    "twitter_parsed_dataset.csv",
    "twitter_racism_parsed_dataset.csv",
    "twitter_sexism_parsed_dataset.csv",
    "youtube_parsed_dataset.csv",
]
_MAX_ROWS_PER_FILE = 60000

_POSITIVE = {"abusive", "bullying", "toxic", "hate", "cyberbullying", "1", "true"}
_NEGATIVE = {"safe", "ham", "normal", "non-toxic", "0", "false", "none"}


def _parse_row_label(row: dict[str, str]) -> int | None:
    if "oh_label" in row and str(row.get("oh_label", "")).strip() != "":
        try:
            return 1 if float(str(row["oh_label"]).strip()) >= 0.5 else 0
        except ValueError:
            pass

    annotation = str(row.get("Annotation", "")).strip().lower()
    if annotation:
        if annotation in {"none", "normal", "neutral"}:
            return 0
        return 1

    for key in ("label", "class", "target", "toxic"):
        value = str(row.get(key, "")).strip().lower()
        if not value:
            continue
        if value in _POSITIVE:
            return 1
        if value in _NEGATIVE:
            return 0
        try:
            return 1 if float(value) >= 0.5 else 0
        except ValueError:
            continue
    return None


def _read_rows(path: Path) -> list[tuple[str, int]]:
    if not path.exists():
        return []
    rows: list[tuple[str, int]] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = str(row.get("Text", row.get("text", row.get("comment_text", "")))).strip()
            if not text:
                continue
            lbl = _parse_row_label({k: str(v) for k, v in row.items()})
            if lbl is None:
                continue
            rows.append((text, lbl))
            if len(rows) >= _MAX_ROWS_PER_FILE:
                break
    return rows


def _seed_rows() -> list[tuple[str, int]]:
    return [
        ("you are amazing", 0),
        ("thanks for helping", 0),
        ("let us solve this peacefully", 0),
        ("you are stupid", 1),
        ("shut up loser", 1),
        ("kill yourself", 1),
        ("you are worthless", 1),
        ("i hate you", 1),
    ]


def _build_dataset() -> tuple[list[str], list[int]]:
    rows = _seed_rows()
    for filename in _DATA_FILES:
        rows.extend(_read_rows(DATA_DIR / filename))

    X = [normalize_text(text) for text, _ in rows]
    y = [label for _, label in rows]
    return X, y


def train_model(force_retrain: bool = False) -> Pipeline:
    global _MODEL
    with _LOCK:
        if _MODEL is not None and not force_retrain:
            return _MODEL

        X, y = _build_dataset()
        model = Pipeline(
            [
                ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=20000)),
                ("clf", LogisticRegression(max_iter=4000, class_weight="balanced", solver="liblinear")),
            ]
        )
        model.fit(X, y)
        _MODEL = model
        return model


def predict(message: str) -> dict:
    model = train_model()
    cleaned = normalize_text(message)
    prob = float(model.predict_proba([cleaned])[0][1])
    is_threat = prob >= 0.5
    severity = confidence_to_severity(prob, low=0.5, medium=0.68, high=0.84)
    return {
        "is_threat": is_threat,
        "type": "cyberbullying",
        "severity": severity if is_threat else "low",
        "confidence": round(prob, 3),
    }
