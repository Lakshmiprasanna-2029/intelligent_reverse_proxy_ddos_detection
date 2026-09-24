from pathlib import Path
import joblib
import numpy as np

# ============================================================
# AEGISPROXY — MODEL LOADER
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = PROJECT_ROOT / "model" / "xgboost_final.pkl"
PREPROCESSOR_PATH = PROJECT_ROOT / "artifacts" / "quantile_transformer.pkl"

print("=" * 60)
print("AEGISPROXY MODEL INITIALIZATION")
print("=" * 60)

print("Project root:", PROJECT_ROOT)
print("Model path:", MODEL_PATH)
print("Preprocessor path:", PREPROCESSOR_PATH)

# ------------------------------------------------------------
# Validate files
# ------------------------------------------------------------

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"XGBoost model not found:\n{MODEL_PATH}"
    )

if not PREPROCESSOR_PATH.exists():
    raise FileNotFoundError(
        f"QuantileTransformer not found:\n{PREPROCESSOR_PATH}"
    )

# ------------------------------------------------------------
# Load trained artifacts
# ------------------------------------------------------------

model = joblib.load(MODEL_PATH)
preprocessor = joblib.load(PREPROCESSOR_PATH)

print("✅ XGBoost model loaded")
print("✅ QuantileTransformer loaded")

# ------------------------------------------------------------
# Proposal-aligned 28 features
# ------------------------------------------------------------

PARITY_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
]

assert len(PARITY_FEATURES) == 28

CLASS_NAMES = {
    0: "BENIGN",
    1: "DDoS_LOIC_HTTP",
    2: "DoS_GoldenEye",
    3: "DoS_Hulk",
    4: "DoS_Slowhttptest",
    5: "DoS_Slowloris",
}


def predict(features):
    """
    Predict a single HTTP flow using the trained
    28-feature AegisProxy pipeline.
    """

    # --------------------------------------------------------
    # Convert input to 2D numpy array
    # --------------------------------------------------------

    X = np.asarray(features, dtype=np.float32)

    if X.ndim == 1:
        X = X.reshape(1, -1)

    if X.shape[1] != 28:
        raise ValueError(
            f"Expected 28 features, received {X.shape[1]}"
        )

    # --------------------------------------------------------
    # Apply TRAIN-FITTED QuantileTransformer
    # --------------------------------------------------------

    X_transformed = preprocessor.transform(X)

    X_transformed = np.asarray(
        X_transformed,
        dtype=np.float32
    )

    # --------------------------------------------------------
    # XGBoost prediction
    # --------------------------------------------------------

    probabilities = model.predict_proba(X_transformed)[0]

    predicted_class = int(np.argmax(probabilities))

    confidence = float(
        probabilities[predicted_class]
    )

    attack_probability = float(
        1.0 - probabilities[0]
    )

    return {
        "predicted_class": predicted_class,
        "predicted_class_name": CLASS_NAMES[predicted_class],
        "classification_confidence": confidence,
        "attack_probability": attack_probability,
        "probabilities": {
            CLASS_NAMES[i]: float(probabilities[i])
            for i in range(len(probabilities))
        },
    }