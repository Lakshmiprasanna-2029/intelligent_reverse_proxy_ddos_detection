"""
AegisProxy E4 Evaluation

Evaluates the complete ML cascade on replayed
benign and attack traffic.

Metrics:
    ASR = Attack Success Rate
    CBR = Cascade Bypass Rate

ASR:
    Fraction of attack requests incorrectly classified
    as BENIGN.

CBR:
    Fraction of requests handled by the Student model
    without escalation to the FT-Transformer teacher.
"""

from pathlib import Path
import sys
import time
import numpy as np
import pandas as pd

# ------------------------------------------------------------
# Project root
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(PROJECT_ROOT))

from backend.cascade import predict


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

TEST_PATH = (
    PROJECT_ROOT
    / "results"
    / "test_predictions.csv"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "results"
    / "e4_evaluation.csv"
)

REPETITIONS = 3

ATTACK_CLASSES = {
    "DDoS_LOIC_HTTP",
    "DoS_GoldenEye",
    "DoS_Hulk",
    "DoS_Slowhttptest",
    "DoS_Slowloris",
}


# ------------------------------------------------------------
# Locate feature columns
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


# ------------------------------------------------------------
# Load test data
# ------------------------------------------------------------

print("=" * 70)
print("AEGISPROXY — E4 CASCADE EVALUATION")
print("=" * 70)

if not TEST_PATH.exists():
    raise FileNotFoundError(
        f"Test prediction file not found:\n{TEST_PATH}"
    )

df = pd.read_csv(TEST_PATH)

print("\nLoaded:")
print(TEST_PATH)

print("\nShape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())


# ------------------------------------------------------------
# Find feature columns
# ------------------------------------------------------------

missing = [
    feature
    for feature in PARITY_FEATURES
    if feature not in df.columns
]

if missing:

    # Some prediction files may not contain raw features.
    # In that case E4 cannot replay the original flows.

    raise ValueError(
        "E4 requires the 28 raw parity features.\n"
        f"Missing features: {missing}\n\n"
        "Use the original test.parquet from the dataset "
        "instead of a prediction-only CSV."
    )


# ------------------------------------------------------------
# Label column
# ------------------------------------------------------------

LABEL_COLUMN = None

for candidate in ["Label", "label", "class", "Class"]:

    if candidate in df.columns:
        LABEL_COLUMN = candidate
        break

if LABEL_COLUMN is None:

    raise ValueError(
        "Could not find the ground-truth label column."
    )


# ------------------------------------------------------------
# Select balanced replay sample
# ------------------------------------------------------------

benign = df[
    df[LABEL_COLUMN].astype(str).str.upper()
    == "BENIGN"
]

attacks = df[
    df[LABEL_COLUMN].astype(str).str.upper()
    != "BENIGN"
]

print("\nBenign samples:", len(benign))
print("Attack samples:", len(attacks))


if len(benign) == 0 or len(attacks) == 0:

    raise ValueError(
        "Both benign and attack traffic are required."
    )


# Keep evaluation reasonably fast.
# Equal number of benign and attack flows.

sample_size = min(
    len(benign),
    len(attacks),
    1000
)

benign = benign.sample(
    n=sample_size,
    random_state=42
)

attacks = attacks.sample(
    n=sample_size,
    random_state=42
)

evaluation_df = pd.concat(
    [benign, attacks],
    ignore_index=True
)

print(
    "\nReplay set:",
    len(evaluation_df)
)


# ------------------------------------------------------------
# E4 evaluation
# ------------------------------------------------------------

records = []

total_requests = 0
student_requests = 0
teacher_requests = 0

attack_requests = 0
attack_successes = 0


for repetition in range(1, REPETITIONS + 1):

    print(
        f"\nRunning replay {repetition}/{REPETITIONS}..."
    )

    for _, row in evaluation_df.iterrows():

        features = [
            row[feature]
            for feature in PARITY_FEATURES
        ]

        true_label = str(
            row[LABEL_COLUMN]
        )

        try:

            result = predict(features)

        except Exception as e:

            print(
                "Prediction failed:",
                e
            )

            continue

        total_requests += 1

        model_used = result.get(
            "model_used",
            "unknown"
        )

        if model_used == "student":

            student_requests += 1

        elif model_used == "teacher":

            teacher_requests += 1

        is_attack = (
            true_label.upper() != "BENIGN"
        )

        if is_attack:

            attack_requests += 1

            predicted_name = result.get(
                "predicted_class_name"
            )

            if predicted_name == "BENIGN":

                attack_successes += 1

        records.append({

            "repetition": repetition,

            "true_label": true_label,

            "predicted_label":
                result.get(
                    "predicted_class_name"
                ),

            "model_used":
                model_used,

            "student_confidence":
                result.get(
                    "student_confidence"
                ),

            "teacher_escalated":
                result.get(
                    "teacher_escalated"
                ),

            "classification_confidence":
                result.get(
                    "classification_confidence"
                ),

            "attack_probability":
                result.get(
                    "attack_probability"
                ),

        })


# ------------------------------------------------------------
# Metrics
# ------------------------------------------------------------

if attack_requests > 0:

    ASR = (
        attack_successes
        / attack_requests
    )

else:

    ASR = 0.0


if total_requests > 0:

    CBR = (
        student_requests
        / total_requests
    )

else:

    CBR = 0.0


teacher_rate = (
    teacher_requests / total_requests
    if total_requests
    else 0.0
)


# ------------------------------------------------------------
# Save detailed results
# ------------------------------------------------------------

results_df = pd.DataFrame(records)

results_df.to_csv(
    OUTPUT_PATH,
    index=False
)


# ------------------------------------------------------------
# Print results
# ------------------------------------------------------------

print("\n")
print("=" * 70)
print("E4 RESULTS")
print("=" * 70)

print(
    f"Total requests       : {total_requests}"
)

print(
    f"Attack requests      : {attack_requests}"
)

print(
    f"Student decisions    : {student_requests}"
)

print(
    f"Teacher decisions    : {teacher_requests}"
)

print(
    f"Teacher escalation   : {teacher_rate:.4f}"
)

print(
    f"Cascade Bypass Rate  : {CBR:.4f}"
)

print(
    f"Attack Success Rate  : {ASR:.4f}"
)

print(
    f"Attack Success %     : {ASR * 100:.2f}%"
)

print(
    f"Student handling %   : {CBR * 100:.2f}%"
)

print(
    f"Teacher handling %   : {teacher_rate * 100:.2f}%"
)

print("\nSaved:")
print(OUTPUT_PATH)

print("=" * 70)