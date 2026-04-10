from __future__ import annotations

import re
from typing import Iterable

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

_WORD_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = set(ENGLISH_STOP_WORDS)


def normalize_text(text: str) -> str:
    tokens = [t for t in _WORD_RE.findall(text.lower()) if t not in _STOPWORDS]
    return " ".join(tokens)


def confidence_to_severity(score: float, low: float = 0.5, medium: float = 0.7, high: float = 0.85) -> str:
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    if score >= low:
        return "low"
    return "low"


def clamp(score: float) -> float:
    return max(0.0, min(1.0, score))


def safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def is_label_positive(label: str, positives: Iterable[str]) -> bool:
    return label.strip().lower() in {p.strip().lower() for p in positives}
