from __future__ import annotations

import csv
import re
from pathlib import Path
from threading import Lock

from sklearn.ensemble import RandomForestClassifier

from .text_utils import confidence_to_severity

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"

_URL_RE = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd"}
_SUSPICIOUS_TLDS = {".zip", ".xyz", ".click", ".top", ".work", ".gq", ".tk"}
_IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)

_MODEL: RandomForestClassifier | None = None
_LOCK = Lock()
_MAX_ROWS = 100000


def _extract_urls(text: str) -> list[str]:
    return _URL_RE.findall(text)


def _url_features(text: str) -> list[float]:
    lowered = text.lower()
    urls = _extract_urls(text)
    merged = " ".join(u.lower() for u in urls)

    has_shortener = float(any(any(s in u.lower() for s in _SHORTENERS) for u in urls))
    has_ip = float(bool(_IP_URL_RE.search(text)))
    has_at = float("@" in merged)
    has_long = float(any(len(u) > 80 for u in urls))
    suspicious_tld = float(any(tld in merged for tld in _SUSPICIOUS_TLDS))
    credential_bait = float(
        any(k in lowered for k in ["verify", "bank", "password", "login now", "otp", "reset now", "urgent"])
    )
    url_count = float(len(urls))

    return [has_shortener, has_ip, has_at, has_long, suspicious_tld, credential_bait, url_count]


def _seed_rows() -> list[tuple[str, int]]:
    return [
        ("Please review docs by tomorrow", 0),
        ("Check this dashboard link", 0),
        ("Verify account now at http://bit.ly/free-login", 1),
        ("Urgent bank alert reset password", 1),
        ("login now: https://tinyurl.com/security-check", 1),
    ]


def _read_rows(path: Path) -> list[tuple[str, int]]:
    if not path.exists():
        return []
    rows: list[tuple[str, int]] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = str(row.get("text", row.get("url", ""))).strip()
            if not text:
                text = str(row.get("URL", "")).strip()
            label = str(row.get("label", "")).strip().lower()
            if not text:
                continue
            if label in {"phishing", "scam", "malicious", "1", "true"}:
                rows.append((text, 1))
            elif label in {"safe", "benign", "normal", "0", "false"}:
                rows.append((text, 0))
            if len(rows) >= _MAX_ROWS:
                break
    return rows


def train_model(force_retrain: bool = False) -> RandomForestClassifier:
    global _MODEL
    with _LOCK:
        if _MODEL is not None and not force_retrain:
            return _MODEL

        rows = _seed_rows()
        rows.extend(_read_rows(DATA_FILE))
        X = [_url_features(text) for text, _ in rows]
        y = [label for _, label in rows]

        model = RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced_subsample")
        model.fit(X, y)
        _MODEL = model
        return model


def predict(message: str) -> dict:
    model = train_model()
    urls = _extract_urls(message)
    feats = _url_features(message)
    ml_prob = float(model.predict_proba([feats])[0][1])

    heuristic_prob = 0.0
    heuristic_prob += 0.35 * feats[0]
    heuristic_prob += 0.3 * feats[1]
    heuristic_prob += 0.2 * feats[4]
    heuristic_prob += 0.35 * feats[5]
    if urls and heuristic_prob == 0:
        heuristic_prob = 0.25

    combined = max(ml_prob, min(1.0, heuristic_prob))
    is_threat = combined >= 0.45
    severity = confidence_to_severity(combined, low=0.45, medium=0.68, high=0.85)

    return {
        "is_threat": is_threat,
        "type": "phishing",
        "severity": severity if is_threat else "low",
        "confidence": round(combined, 3),
        "urls": urls,
    }
