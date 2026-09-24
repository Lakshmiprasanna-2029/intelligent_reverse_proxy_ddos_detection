from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parent.parent
THRESHOLD_FILE = BASE_DIR / "artifacts" / "adaptive_threshold.json"

DEFAULT_THRESHOLD = 0.50


def load_threshold():
    try:
        with open(THRESHOLD_FILE, "r") as f:
            data = json.load(f)

        if isinstance(data, dict):
            for key in ["threshold", "adaptive_threshold", "value"]:
                if key in data:
                    return float(data[key])

    except Exception:
        pass

    return DEFAULT_THRESHOLD


ADAPTIVE_THRESHOLD = load_threshold()


def calculate_risk(prediction: dict):
    """
    AegisProxy multi-evidence risk engine.

    Evidence:
    1. Attack probability
    2. Classification confidence
    3. Predicted attack/benign class

    Decision:
    - ALLOW
    - RATE_LIMIT
    - BLOCK
    """

    attack_probability = float(
        prediction.get("attack_probability", 0.0)
    )

    confidence = float(
        prediction.get("classification_confidence", 0.0)
    )

    predicted_class = int(
        prediction.get("predicted_class", 0)
    )

    # ---------------------------------------------------------
    # Evidence 1: attack probability
    # ---------------------------------------------------------
    evidence_attack = attack_probability

    # ---------------------------------------------------------
    # Evidence 2: classification confidence
    # ---------------------------------------------------------
    evidence_confidence = confidence

    # ---------------------------------------------------------
    # Evidence 3: predicted class
    # ---------------------------------------------------------
    evidence_class = 1.0 if predicted_class != 0 else 0.0

    # ---------------------------------------------------------
    # Multi-evidence fusion
    # ---------------------------------------------------------
    risk_score = (
        0.50 * evidence_attack
        + 0.30 * evidence_confidence * evidence_class
        + 0.20 * evidence_class
    )

    # ---------------------------------------------------------
    # Adaptive decision policy
    # ---------------------------------------------------------
    if risk_score >= ADAPTIVE_THRESHOLD:
        decision = "BLOCK"

    elif risk_score >= ADAPTIVE_THRESHOLD * 0.60:
        decision = "RATE_LIMIT"

    else:
        decision = "ALLOW"

    return {
        "risk_score": round(float(risk_score), 6),
        "adaptive_threshold": ADAPTIVE_THRESHOLD,
        "evidence_attack": round(evidence_attack, 6),
        "evidence_confidence": round(evidence_confidence, 6),
        "evidence_class": round(evidence_class, 6),
        "decision": decision,
    }