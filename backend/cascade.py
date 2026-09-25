from pathlib import Path
import json
import numpy as np
import tensorflow as tf
import joblib

# ============================================================
# AEGISPROXY — STUDENT / TEACHER CASCADE
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

STUDENT_PATH = PROJECT_ROOT / "model" / "student_dl.keras"
TEACHER_PATH = PROJECT_ROOT / "model" / "teacher_ft.keras"
CLASS_PATH = PROJECT_ROOT / "model" / "class_names.json"
PREPROCESSOR_PATH = PROJECT_ROOT / "artifacts" / "quantile_transformer.pkl"
THRESHOLD_PATH = PROJECT_ROOT / "artifacts" / "cascade_threshold.json"


# ------------------------------------------------------------
# Feature tokenizer required to load FT-Transformer
# ------------------------------------------------------------

@tf.keras.utils.register_keras_serializable(
    package="AegisProxy"
)
class FeatureTokenizer(tf.keras.layers.Layer):

    def __init__(
        self,
        num_features,
        embed_dim,
        **kwargs
    ):
        super().__init__(**kwargs)

        self.num_features = num_features
        self.embed_dim = embed_dim

        self.weight = self.add_weight(
            name="feature_weight",
            shape=(num_features, embed_dim),
            initializer="glorot_uniform",
            trainable=True
        )

        self.bias = self.add_weight(
            name="feature_bias",
            shape=(num_features, embed_dim),
            initializer="zeros",
            trainable=True
        )

    def call(self, x):
        x = tf.expand_dims(x, axis=-1)

        return (
            x * self.weight
            + self.bias
        )

    def get_config(self):

        config = super().get_config()

        config.update({
            "num_features": self.num_features,
            "embed_dim": self.embed_dim
        })

        return config


# ------------------------------------------------------------
# Validate artifacts
# ------------------------------------------------------------

required_files = [
    STUDENT_PATH,
    TEACHER_PATH,
    CLASS_PATH,
    PREPROCESSOR_PATH,
    THRESHOLD_PATH,
]

for path in required_files:

    if not path.exists():
        raise FileNotFoundError(
            f"Required AegisProxy artifact not found:\n{path}"
        )


# ------------------------------------------------------------
# Load artifacts
# ------------------------------------------------------------

print("=" * 60)
print("AEGISPROXY CASCADE INITIALIZATION")
print("=" * 60)

with open(CLASS_PATH, "r") as f:
    CLASS_NAMES_RAW = json.load(f)

CLASS_NAMES = {
    int(k): v
    for k, v in CLASS_NAMES_RAW.items()
}

with open(THRESHOLD_PATH, "r") as f:
    threshold_config = json.load(f)

CASCADE_THRESHOLD = float(
    threshold_config["threshold"]
)

preprocessor = joblib.load(
    PREPROCESSOR_PATH
)

student = tf.keras.models.load_model(
    STUDENT_PATH
)

teacher = tf.keras.models.load_model(
    TEACHER_PATH,
    custom_objects={
        "FeatureTokenizer": FeatureTokenizer
    }
)

print("Student loaded")
print("Teacher loaded")
print("Preprocessor loaded")
print("Cascade threshold:", CASCADE_THRESHOLD)


# ------------------------------------------------------------
# Prediction
# ------------------------------------------------------------

def predict(features):

    X = np.asarray(
        features,
        dtype=np.float32
    )

    if X.ndim == 1:
        X = X.reshape(1, -1)

    if X.shape[1] != 28:

        raise ValueError(
            f"Expected 28 features, received {X.shape[1]}"
        )

    # Same preprocessing used by XGBoost
    X_transformed = preprocessor.transform(X)

    X_transformed = np.asarray(
        X_transformed,
        dtype=np.float32
    )

    # ========================================================
    # STEP 1 — STUDENT
    # ========================================================

    student_probs = student.predict(
        X_transformed,
        verbose=0
    )[0]

    student_class = int(
        np.argmax(student_probs)
    )

    student_confidence = float(
        student_probs[student_class]
    )

    # ========================================================
    # STEP 2 — CONFIDENCE CHECK
    # ========================================================

    if student_confidence >= CASCADE_THRESHOLD:

        final_probs = student_probs

        final_class = student_class

        final_confidence = student_confidence

        model_used = "student"

        escalated = False

    else:

        # ====================================================
        # STEP 3 — TEACHER ESCALATION
        # ====================================================

        teacher_probs = teacher.predict(
            X_transformed,
            verbose=0
        )[0]

        final_class = int(
            np.argmax(teacher_probs)
        )

        final_confidence = float(
            teacher_probs[final_class]
        )

        final_probs = teacher_probs

        model_used = "teacher"

        escalated = True

    # --------------------------------------------------------
    # Attack probability
    # --------------------------------------------------------

    attack_probability = float(
        1.0 - final_probs[0]
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {

        "predicted_class": final_class,

        "predicted_class_name":
            CLASS_NAMES[final_class],

        "classification_confidence":
            final_confidence,

        "attack_probability":
            attack_probability,

        "probabilities": {
            CLASS_NAMES[i]:
                float(final_probs[i])
            for i in range(len(final_probs))
        },

        # Cascade information
        "model_used": model_used,

        "student_confidence":
            student_confidence,

        "teacher_escalated":
            escalated,

        "cascade_threshold":
            CASCADE_THRESHOLD,
    }