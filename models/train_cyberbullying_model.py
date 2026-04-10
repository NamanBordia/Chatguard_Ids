from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from models.bullying_model import train_model


if __name__ == "__main__":
    train_model(force_retrain=True)
    print("[TRAIN] cyberbullying model ready (python module).")
