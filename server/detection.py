"""Modular detection engine for chat IDS/IPS.

All models are implemented as Python modules in models/ (no .pkl artifacts).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from models.anomaly_model import predict as anomaly_predict
from models.anomaly_model import train_model as anomaly_train
from models.bullying_model import predict as bullying_predict
from models.bullying_model import train_model as bullying_train
from models.phishing_model import predict as phishing_predict
from models.phishing_model import train_model as phishing_train
from models.spam_model import predict as spam_predict
from models.spam_model import train_model as spam_train


def initialize_detection_engine() -> None:
    """Load/train all detector models at server startup."""
    bullying_train(force_retrain=False)
    spam_train(force_retrain=False)
    phishing_train(force_retrain=False)
    anomaly_train(force_retrain=False)


def detect_cyberbullying(message: str) -> dict:
    return bullying_predict(message)


def detect_spam(user: str, message: str) -> dict:
    return spam_predict(user, message)


def detect_phishing(message: str) -> dict:
    return phishing_predict(message)


def detect_anomaly(user: str, message: str) -> dict:
    return anomaly_predict(user, message)


def detect_all(user: str, message: str) -> Tuple[dict, dict, dict, dict]:
    bullying = detect_cyberbullying(message)
    spam = detect_spam(user, message)
    phishing = detect_phishing(message)
    anomaly = detect_anomaly(user, message)
    return bullying, spam, phishing, anomaly
