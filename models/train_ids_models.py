"""Train all IDS detection models (Python module-based, no pickle files)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from models.anomaly_model import train_model as train_anomaly
from models.bullying_model import train_model as train_bullying
from models.phishing_model import train_model as train_phishing
from models.spam_model import train_model as train_spam


if __name__ == "__main__":
    train_bullying(force_retrain=True)
    train_spam(force_retrain=True)
    train_phishing(force_retrain=True)
    train_anomaly(force_retrain=True)
    print("[TRAIN] All IDS models initialized in Python modules.")
    print("[TRAIN] Models: cyberbullying, spam, phishing, anomaly")
