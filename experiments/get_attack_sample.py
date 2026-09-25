from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TEST_PATH = PROJECT_ROOT / "data" / "processed" / "test.parquet"

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

df = pd.read_parquet(TEST_PATH)

benign = df[
    df["Label"].astype(str).str.upper() == "BENIGN"
]

attacks = df[
    df["Label"].astype(str).str.upper() != "BENIGN"
]

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

# E4 sample_index 111
row = evaluation_df.iloc[111]

print("=" * 70)
print("AEGISPROXY — EXACT E4 SAMPLE 111")
print("=" * 70)

print("True label:", row["Label"])
print("Original dataframe index:", row.name)

print("\n28 FEATURES:")
print("-" * 70)

for i, feature in enumerate(PARITY_FEATURES, 1):
    print(
        f"{i:2}. {feature}: {row[feature]}"
    )

print("\nPython feature list:")
print("[")
for feature in PARITY_FEATURES:
    print(f"    {float(row[feature])!r},")
print("]")

print("=" * 70)