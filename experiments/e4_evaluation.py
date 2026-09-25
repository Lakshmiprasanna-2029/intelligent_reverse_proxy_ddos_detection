"""
AegisProxy E4 Evaluation

Replays the actual test.parquet through the complete
Student DNN + FT-Transformer cascade.

Metrics:
    ASR = Attack Success Rate
    CBR = Cascade Bypass Rate

ASR:
    Fraction of attack requests incorrectly classified
    as BENIGN.

CBR:
    Fraction of requests handled by Student
    without Teacher escalation.
"""

from pathlib import Path
import sys
import numpy as np
import pandas as pd

# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(PROJECT_ROOT))

from backend.cascade import predict


# ============================================================
# PATHS
# ============================================================

TEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "test.parquet"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "results"
    / "e4_evaluation.csv"
)

REPETITIONS = 1


# ============================================================
# 28 PARITY FEATURES
# ============================================================

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


# ============================================================
# START
# ============================================================

print("=" * 70)
print("AEGISPROXY — E4 CASCADE EVALUATION")
print("=" * 70)

print("\nTest dataset:")
print(TEST_PATH)


# ============================================================
# CHECK FILE
# ============================================================

if not TEST_PATH.exists():
    raise FileNotFoundError(
        f"\nTest dataset not found:\n{TEST_PATH}"
    )


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_parquet(TEST_PATH)

print("\nDataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())


# ============================================================
# VERIFY PARITY FEATURES
# ============================================================

missing = [
    feature
    for feature in PARITY_FEATURES
    if feature not in df.columns
]

if missing:

    raise ValueError(
        "\nMissing parity features:\n"
        + "\n".join(missing)
    )

print(
    "\nNumber of parity features found:",
    len(PARITY_FEATURES)
)

print("Missing:")
print(missing)


# ============================================================
# LABEL
# ============================================================

if "Label" not in df.columns:

    raise ValueError(
        "Ground-truth 'Label' column not found."
    )

print("\nClass distribution:")

print(
    df["Label"].value_counts()
)


# ============================================================
# CLEAN FEATURES
# ============================================================

evaluation_df = df[
    PARITY_FEATURES + ["Label"]
].copy()


# Replace invalid numerical values

evaluation_df[PARITY_FEATURES] = (
    evaluation_df[PARITY_FEATURES]
    .replace([np.inf, -np.inf], np.nan)
)


before = len(evaluation_df)

evaluation_df = evaluation_df.dropna(
    subset=PARITY_FEATURES
)

after = len(evaluation_df)

print(
    f"\nRemoved invalid rows: {before - after}"
)


# ============================================================
# BALANCED REPLAY SET
# ============================================================

benign = evaluation_df[
    evaluation_df["Label"]
    .astype(str)
    .str.upper()
    == "BENIGN"
]

attacks = evaluation_df[
    evaluation_df["Label"]
    .astype(str)
    .str.upper()
    != "BENIGN"
]


print("\nBenign samples:", len(benign))
print("Attack samples:", len(attacks))


if len(benign) == 0:
    raise ValueError("No BENIGN samples found.")

if len(attacks) == 0:
    raise ValueError("No attack samples found.")


# ============================================================
# BALANCED SAMPLE
# ============================================================

sample_size = min(
    len(benign),
    len(attacks),
    1000
)

benign_sample = benign.sample(
    n=sample_size,
    random_state=42
)

attack_sample = attacks.sample(
    n=sample_size,
    random_state=42
)


evaluation_df = pd.concat(
    [
        benign_sample,
        attack_sample
    ],
    ignore_index=True
)


# Shuffle

evaluation_df = evaluation_df.sample(
    frac=1.0,
    random_state=42
).reset_index(drop=True)


print(
    "\nBalanced replay set:",
    len(evaluation_df)
)


# ============================================================
# METRIC COUNTERS
# ============================================================

records = []

total_requests = 0

student_requests = 0

teacher_requests = 0

attack_requests = 0

attack_successes = 0

correct_predictions = 0


# ============================================================
# REPLAY
# ============================================================

for repetition in range(
    1,
    REPETITIONS + 1
):

    print(
        f"\nRunning replay "
        f"{repetition}/{REPETITIONS}..."
    )

    for index, row in evaluation_df.iterrows():

        features = [
            float(row[feature])
            for feature in PARITY_FEATURES
        ]

        true_label = str(
            row["Label"]
        )

        try:

            result = predict(
                features
            )

        except Exception as e:

            print(
                f"\nPrediction failed "
                f"at sample {index}:"
            )

            print(e)

            continue


        # ----------------------------------------------------
        # COUNTERS
        # ----------------------------------------------------

        total_requests += 1


        model_used = result.get(
            "model_used",
            "unknown"
        )


        if model_used == "student":

            student_requests += 1

        elif model_used == "teacher":

            teacher_requests += 1


        # ----------------------------------------------------
        # PREDICTION
        # ----------------------------------------------------

        predicted_label = result.get(
            "predicted_class_name"
        )


        if predicted_label == true_label:

            correct_predictions += 1


        # ----------------------------------------------------
        # ATTACK
        # ----------------------------------------------------

        is_attack = (
            true_label.upper()
            != "BENIGN"
        )


        if is_attack:

            attack_requests += 1

            if predicted_label == "BENIGN":

                attack_successes += 1


        # ----------------------------------------------------
        # SAVE RESULT
        # ----------------------------------------------------

        records.append({

            "repetition":
                repetition,

            "sample_index":
                index,

            "true_label":
                true_label,

            "predicted_label":
                predicted_label,

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

            "cascade_threshold":
                result.get(
                    "cascade_threshold"
                ),

        })


# ============================================================
# METRICS
# ============================================================

if total_requests > 0:

    accuracy = (
        correct_predictions
        / total_requests
    )

else:

    accuracy = 0.0


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
    teacher_requests
    / total_requests
    if total_requests
    else 0.0
)


# ============================================================
# SAVE
# ============================================================

results_df = pd.DataFrame(
    records
)

OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True
)

results_df.to_csv(
    OUTPUT_PATH,
    index=False
)


# ============================================================
# RESULTS
# ============================================================

print("\n")
print("=" * 70)
print("E4 RESULTS")
print("=" * 70)

print(
    f"Total requests       : "
    f"{total_requests}"
)

print(
    f"Attack requests      : "
    f"{attack_requests}"
)

print(
    f"Student decisions    : "
    f"{student_requests}"
)

print(
    f"Teacher decisions    : "
    f"{teacher_requests}"
)

print(
    f"Overall Accuracy     : "
    f"{accuracy:.4f}"
)

print(
    f"Teacher escalation   : "
    f"{teacher_rate:.4f}"
)

print(
    f"Cascade Bypass Rate  : "
    f"{CBR:.4f}"
)

print(
    f"Attack Success Rate  : "
    f"{ASR:.4f}"
)

print(
    f"Attack Success %     : "
    f"{ASR * 100:.2f}%"
)

print(
    f"Student handling %   : "
    f"{CBR * 100:.2f}%"
)

print(
    f"Teacher handling %   : "
    f"{teacher_rate * 100:.2f}%"
)

print("\nSaved:")
print(OUTPUT_PATH)

print("=" * 70)