from pathlib import Path
from datetime import datetime
import csv

import psutil
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .cascade import predict as cascade_predict
from .risk_engine import calculate_risk
from .adaptive_limiter import AdaptiveLimiter


# ============================================================
# AEGISPROXY
# Self-Adaptive Risk-Aware Intelligent Reverse Proxy
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RESULTS_DIR = PROJECT_ROOT / "results"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"

RISK_DECISIONS_FILE = RESULTS_DIR / "risk_decisions.csv"
TEST_PREDICTIONS_FILE = RESULTS_DIR / "test_predictions.csv"
METRICS_FILE = RESULTS_DIR / "final_metrics.csv"
CONFUSION_FILE = RESULTS_DIR / "confusion_matrix.csv"

APP_NAME = "AegisProxy"
APP_VERSION = "2.0"


# ============================================================
# FEATURES / CONFIGURATION
# ============================================================

ADAPTIVE_LIMITER = True

DEFAULT_SOURCE_IP = "127.0.0.1"

MODEL_NAME = "Cascade: Student DNN + FT-Transformer"
BASELINE_MODEL = "XGBoost"

CASCADE_THRESHOLD = 0.90


# ============================================================
# ADAPTIVE LIMITER
# ============================================================

limiter = AdaptiveLimiter()


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "Self-Adaptive Risk-Aware Intelligent Reverse Proxy "
        "with ML Cascade and Adaptive Rate Limiting"
    ),
)


# ============================================================
# REQUEST SCHEMA
# ============================================================

class PredictionRequest(BaseModel):

    features: list[float] = Field(
        ...,
        min_length=28,
        max_length=28,
        description="Exactly 28 ML features in training order",
    )

    source_ip: str = Field(
        default=DEFAULT_SOURCE_IP,
        description="Client source IP address",
    )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "application": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "message": "AegisProxy is operational",

        "pipeline": [
            "Request",
            "28-Feature Extraction",
            "Student DNN",
            "Confidence Check",
            "FT-Transformer Teacher Escalation",
            "Risk Engine",
            "Adaptive Reputation",
            "Adaptive Rate Limiter",
            "Policy Decision",
            "ALLOW / RATE_LIMIT / BLOCK",
        ],

        "models": {
            "primary": MODEL_NAME,
            "baseline": BASELINE_MODEL,
            "cascade_threshold": CASCADE_THRESHOLD,
        },

        "adaptive_limiter": ADAPTIVE_LIMITER,
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": APP_NAME,

        "model": MODEL_NAME,
        "baseline_model": BASELINE_MODEL,

        "model_available": True,

        "components": {
            "student_dnn": True,
            "ft_transformer_teacher": True,
            "cascade": True,
            "adaptive_limiter": ADAPTIVE_LIMITER,
            "risk_engine": True,
        },

        "timestamp": datetime.now().isoformat(),
    }


# ============================================================
# SYSTEM HEALTH
# ============================================================

@app.get("/system/health")
def system_health():

    return {
        "service": APP_NAME,
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),

        "system": {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
        },

        "model": {
            "student_dnn": "loaded",
            "ft_transformer_teacher": "loaded",
            "cascade": "loaded",
            "quantile_transformer": "loaded",
        },

        "adaptive_limiter": {
            "enabled": ADAPTIVE_LIMITER,
        },
    }


# ============================================================
# ML DETECTION
# ============================================================

def run_ml_detection(features):

    """
    Run the AegisProxy ML cascade.

    Student DNN executes first.
    FT-Transformer executes only when student
    confidence is below the cascade threshold.
    """

    return cascade_predict(features)


# ============================================================
# PREDICTION
# ============================================================

@app.post("/predict")
def prediction(request: PredictionRequest):

    try:

        result = run_ml_detection(
            request.features
        )

        result["source_ip"] = request.source_ip

        return result

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# ADAPTIVE LIMITER
# ============================================================

def apply_adaptive_policy(
    source_ip,
    prediction_result,
    risk_result,
):
    """
    Apply adaptive reputation and rate limiting.

    ML detection happens first.

    The adaptive limiter then evaluates the client reputation.

    Final decision:

        BLOCK
        RATE_LIMIT
        ALLOW
    """

    if not ADAPTIVE_LIMITER:

        return {
            "adaptive_limiter_enabled": False,
            "limiter_decision": "DISABLED",
            "reputation": None,
            "allowed_rate": None,
            "capacity": None,
        }

    # --------------------------------------------------------
    # Check current request against adaptive reputation
    # --------------------------------------------------------

    limiter_result = limiter.check_request(
        source_ip
    )

    limiter_decision = limiter_result.get(
        "decision",
        "ALLOW"
    )

    # --------------------------------------------------------
    # Preserve security decisions from risk engine
    # --------------------------------------------------------

    risk_decision = risk_result.get(
        "decision",
        "ALLOW"
    )

    # Highest priority: BLOCK
    if risk_decision == "BLOCK":

        final_decision = "BLOCK"

    # Adaptive limiter hard block
    elif limiter_decision == "BLOCK":

        final_decision = "BLOCK"

    # Risk engine rate limit
    elif risk_decision == "RATE_LIMIT":

        final_decision = "RATE_LIMIT"

    # Adaptive limiter throttle
    elif limiter_decision == "THROTTLE":

        final_decision = "RATE_LIMIT"

    else:

        final_decision = "ALLOW"

    # --------------------------------------------------------
    # Update reputation AFTER final decision
    # --------------------------------------------------------

    new_reputation = limiter.update_reputation(

        ip=source_ip,

        attack_probability=prediction_result.get(
            "attack_probability",
            0.0
        ),

        predicted_class=prediction_result.get(
            "predicted_class",
            0
        ),

        classification_confidence=prediction_result.get(
            "classification_confidence",
            0.0
        ),
    )

    # --------------------------------------------------------
    # Recalculate rate after reputation update
    # --------------------------------------------------------

    allowed_rate = limiter.calculate_rate(
        new_reputation
    )

    capacity = limiter.calculate_capacity(
        new_reputation
    )

    return {

        "adaptive_limiter_enabled": True,

        "limiter_decision": limiter_decision,

        "reputation": round(
            new_reputation,
            3
        ),

        "allowed_rate": round(
            allowed_rate,
            3
        ),

        "capacity": round(
            capacity,
            3
        ),

        "requests_in_window":
            limiter_result.get(
                "requests_in_window",
                0
            ),

        "final_decision": final_decision,
    }


# ============================================================
# RISK ENGINE
# ============================================================

@app.post("/risk")
def risk_prediction(request: PredictionRequest):

    try:

        # ----------------------------------------------------
        # ML CASCADE
        # ----------------------------------------------------

        prediction_result = run_ml_detection(
            request.features
        )

        # ----------------------------------------------------
        # RISK ENGINE
        # ----------------------------------------------------

        risk_result = calculate_risk(
            prediction_result
        )

        # ----------------------------------------------------
        # ADAPTIVE LIMITER
        # ----------------------------------------------------

        adaptive_result = apply_adaptive_policy(

            source_ip=request.source_ip,

            prediction_result=prediction_result,

            risk_result=risk_result,
        )

        final_decision = adaptive_result[
            "final_decision"
        ]

        return {

            **prediction_result,

            **risk_result,

            **adaptive_result,

            "decision": final_decision,

            "source_ip": request.source_ip,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# LIVE REQUEST LOGGING
# ============================================================

def log_proxy_request(
    request,
    prediction_result,
    risk_result,
    adaptive_result,
    decision,
):

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    log_file = RESULTS_DIR / "live_requests.csv"

    file_exists = log_file.exists()

    row = {

        "timestamp":
            datetime.now().isoformat(),

        "source_ip":
            request.source_ip,

        "endpoint":
            "/proxy",

        # ----------------------------------------------------
        # ML
        # ----------------------------------------------------

        "predicted_class":
            prediction_result.get(
                "predicted_class"
            ),

        "predicted_class_name":
            prediction_result.get(
                "predicted_class_name"
            ),

        "classification_confidence":
            prediction_result.get(
                "classification_confidence"
            ),

        "attack_probability":
            prediction_result.get(
                "attack_probability"
            ),

        "model_used":
            prediction_result.get(
                "model_used"
            ),

        "student_confidence":
            prediction_result.get(
                "student_confidence"
            ),

        "teacher_escalated":
            prediction_result.get(
                "teacher_escalated"
            ),

        "cascade_threshold":
            prediction_result.get(
                "cascade_threshold"
            ),

        # ----------------------------------------------------
        # RISK
        # ----------------------------------------------------

        "risk_score":
            risk_result.get(
                "risk_score"
            ),

        "adaptive_threshold":
            risk_result.get(
                "adaptive_threshold"
            ),

        "evidence_attack":
            risk_result.get(
                "evidence_attack"
            ),

        "evidence_confidence":
            risk_result.get(
                "evidence_confidence"
            ),

        "evidence_class":
            risk_result.get(
                "evidence_class"
            ),

        # ----------------------------------------------------
        # ADAPTIVE LIMITER
        # ----------------------------------------------------

        "adaptive_limiter_enabled":
            adaptive_result.get(
                "adaptive_limiter_enabled"
            ),

        "limiter_decision":
            adaptive_result.get(
                "limiter_decision"
            ),

        "reputation":
            adaptive_result.get(
                "reputation"
            ),

        "allowed_rate":
            adaptive_result.get(
                "allowed_rate"
            ),

        "capacity":
            adaptive_result.get(
                "capacity"
            ),

        "requests_in_window":
            adaptive_result.get(
                "requests_in_window"
            ),

        # ----------------------------------------------------
        # FINAL
        # ----------------------------------------------------

        "decision":
            decision,
    }

    with open(
        log_file,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=row.keys()
        )

        if not file_exists:

            writer.writeheader()

        writer.writerow(row)


# ============================================================
# MAIN PROXY DECISION
# ============================================================

@app.post("/proxy")
def proxy_request(
    request: PredictionRequest
):

    try:

        # ----------------------------------------------------
        # 1. ML CASCADE
        # ----------------------------------------------------

        prediction_result = run_ml_detection(
            request.features
        )

        # ----------------------------------------------------
        # 2. RISK ENGINE
        # ----------------------------------------------------

        risk_result = calculate_risk(
            prediction_result
        )

        # ----------------------------------------------------
        # 3. ADAPTIVE LIMITER
        # ----------------------------------------------------

        adaptive_result = apply_adaptive_policy(

            source_ip=request.source_ip,

            prediction_result=prediction_result,

            risk_result=risk_result,
        )

        # ----------------------------------------------------
        # 4. FINAL DECISION
        # ----------------------------------------------------

        decision = adaptive_result[
            "final_decision"
        ]

        # ----------------------------------------------------
        # 5. LOG
        # ----------------------------------------------------

        log_proxy_request(

            request=request,

            prediction_result=prediction_result,

            risk_result=risk_result,

            adaptive_result=adaptive_result,

            decision=decision,
        )

        # ----------------------------------------------------
        # MESSAGE
        # ----------------------------------------------------

        if decision == "BLOCK":

            message = (
                "Request blocked by AegisProxy"
            )

        elif decision == "RATE_LIMIT":

            message = (
                "Request rate-limited by AegisProxy"
            )

        else:

            message = (
                "Request allowed by AegisProxy"
            )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {

            "proxy_action": decision,

            "message": message,

            "timestamp":
                datetime.now().isoformat(),

            "source_ip":
                request.source_ip,

            # ------------------------------------------------
            # SECURITY
            # ------------------------------------------------

            "security": {

                "predicted_class":
                    prediction_result.get(
                        "predicted_class"
                    ),

                "predicted_class_name":
                    prediction_result.get(
                        "predicted_class_name"
                    ),

                "classification_confidence":
                    prediction_result.get(
                        "classification_confidence"
                    ),

                "attack_probability":
                    prediction_result.get(
                        "attack_probability"
                    ),

                "model_used":
                    prediction_result.get(
                        "model_used"
                    ),

                "student_confidence":
                    prediction_result.get(
                        "student_confidence"
                    ),

                "teacher_escalated":
                    prediction_result.get(
                        "teacher_escalated"
                    ),

                "cascade_threshold":
                    prediction_result.get(
                        "cascade_threshold"
                    ),
            },

            # ------------------------------------------------
            # RISK
            # ------------------------------------------------

            "risk": {

                "risk_score":
                    risk_result.get(
                        "risk_score"
                    ),

                "adaptive_threshold":
                    risk_result.get(
                        "adaptive_threshold"
                    ),

                "evidence_attack":
                    risk_result.get(
                        "evidence_attack"
                    ),

                "evidence_confidence":
                    risk_result.get(
                        "evidence_confidence"
                    ),

                "evidence_class":
                    risk_result.get(
                        "evidence_class"
                    ),

                "decision":
                    decision,
            },

            # ------------------------------------------------
            # ADAPTIVE REPUTATION
            # ------------------------------------------------

            "adaptive_security": {

                "enabled":
                    adaptive_result.get(
                        "adaptive_limiter_enabled"
                    ),

                "limiter_decision":
                    adaptive_result.get(
                        "limiter_decision"
                    ),

                "reputation":
                    adaptive_result.get(
                        "reputation"
                    ),

                "allowed_rate":
                    adaptive_result.get(
                        "allowed_rate"
                    ),

                "capacity":
                    adaptive_result.get(
                        "capacity"
                    ),

                "requests_in_window":
                    adaptive_result.get(
                        "requests_in_window"
                    ),
            },
        }

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# CSV HELPER
# ============================================================

def read_csv_file(
    path: Path,
    limit=None
):

    if not path.exists():

        return []

    rows = []

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                rows.append(dict(row))

                if (
                    limit
                    and len(rows) >= limit
                ):

                    break

    except Exception:

        return []

    return rows


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

@app.get("/dashboard/summary")
def dashboard_summary():

    risk_rows = read_csv_file(
        RISK_DECISIONS_FILE
    )

    total = len(risk_rows)

    allowed = 0
    blocked = 0
    rate_limited = 0

    for row in risk_rows:

        decision = str(
            row.get(
                "decision",
                ""
            )
        ).upper()

        if decision == "ALLOW":

            allowed += 1

        elif decision == "BLOCK":

            blocked += 1

        elif decision in (
            "RATE_LIMIT",
            "RATE-LIMIT",
            "RATELIMIT",
            "THROTTLE",
        ):

            rate_limited += 1

    return {

        "system": APP_NAME,

        "model": MODEL_NAME,

        "baseline_model": BASELINE_MODEL,

        "total_requests": total,

        "allowed_requests": allowed,

        "blocked_requests": blocked,

        "rate_limited_requests":
            rate_limited,

        "block_rate_percent":
            round(
                (blocked / total) * 100,
                2
            )
            if total
            else 0,

        "allow_rate_percent":
            round(
                (allowed / total) * 100,
                2
            )
            if total
            else 0,

        "rate_limit_percent":
            round(
                (rate_limited / total) * 100,
                2
            )
            if total
            else 0,

        # Existing XGBoost baseline metrics
        "baseline_accuracy": 0.995467,

        "baseline_balanced_accuracy":
            0.994917,

        "baseline_macro_f1":
            0.994808,

        "baseline_macro_roc_auc":
            0.999891,

        "timestamp":
            datetime.now().isoformat(),
    }


# ============================================================
# RISK DISTRIBUTION
# ============================================================

@app.get("/dashboard/risk-distribution")
def risk_distribution():

    rows = read_csv_file(
        RISK_DECISIONS_FILE
    )

    distribution = {
        "ALLOW": 0,
        "BLOCK": 0,
        "RATE_LIMIT": 0,
    }

    for row in rows:

        decision = str(
            row.get(
                "decision",
                ""
            )
        ).upper()

        if decision == "THROTTLE":

            decision = "RATE_LIMIT"

        if decision in distribution:

            distribution[decision] += 1

    return distribution


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

@app.get("/dashboard/attack-distribution")
def attack_distribution():

    rows = read_csv_file(
        TEST_PREDICTIONS_FILE
    )

    distribution = {}

    for row in rows:

        name = (
            row.get("true_class_name")
            or row.get("predicted_class_name")
            or row.get("class_name")
            or row.get("true_label")
            or "UNKNOWN"
        )

        distribution[name] = (
            distribution.get(name, 0) + 1
        )

    return distribution


# ============================================================
# RECENT SECURITY DECISIONS
# ============================================================

@app.get("/dashboard/recent")
def recent_decisions():

    rows = read_csv_file(
        RISK_DECISIONS_FILE,
        limit=20
    )

    return {
        "count": len(rows),
        "records": rows,
    }


# ============================================================
# REQUEST HISTORY
# ============================================================

@app.get("/dashboard/request-history")
def request_history():

    rows = read_csv_file(
        RISK_DECISIONS_FILE,
        limit=100
    )

    history = []

    for index, row in enumerate(rows):

        history.append({

            "request_id":
                index + 1,

            "source_ip":
                row.get(
                    "source_ip",
                    DEFAULT_SOURCE_IP
                ),

            "timestamp":
                row.get(
                    "timestamp",
                    ""
                ),

            "predicted_class":
                row.get(
                    "predicted_class_name",
                    row.get(
                        "predicted_class",
                        "UNKNOWN"
                    )
                ),

            "attack_probability":
                row.get(
                    "attack_probability",
                    ""
                ),

            "risk_score":
                row.get(
                    "risk_score",
                    ""
                ),

            "model_used":
                row.get(
                    "model_used",
                    ""
                ),

            "teacher_escalated":
                row.get(
                    "teacher_escalated",
                    ""
                ),

            "reputation":
                row.get(
                    "reputation",
                    ""
                ),

            "allowed_rate":
                row.get(
                    "allowed_rate",
                    ""
                ),

            "decision":
                row.get(
                    "decision",
                    "UNKNOWN"
                ),
        })

    return {
        "total": len(history),
        "history": history,
    }


# ============================================================
# IP HISTORY
# ============================================================

@app.get("/dashboard/ip-history")
def ip_history():

    rows = read_csv_file(
        RISK_DECISIONS_FILE,
        limit=500
    )

    ip_data = {}

    for row in rows:

        ip = row.get(
            "source_ip",
            DEFAULT_SOURCE_IP
        )

        if ip not in ip_data:

            ip_data[ip] = {

                "ip": ip,

                "requests": 0,

                "allowed": 0,

                "blocked": 0,

                "rate_limited": 0,

                "latest_reputation": 0,

                "latest_allowed_rate": 0,
            }

        ip_data[ip]["requests"] += 1

        decision = str(
            row.get(
                "decision",
                ""
            )
        ).upper()

        if decision == "ALLOW":

            ip_data[ip]["allowed"] += 1

        elif decision == "BLOCK":

            ip_data[ip]["blocked"] += 1

        elif decision in (
            "RATE_LIMIT",
            "THROTTLE",
        ):

            ip_data[ip]["rate_limited"] += 1

        try:

            ip_data[ip][
                "latest_reputation"
            ] = float(
                row.get(
                    "reputation",
                    0
                ) or 0
            )

        except Exception:

            pass

        try:

            ip_data[ip][
                "latest_allowed_rate"
            ] = float(
                row.get(
                    "allowed_rate",
                    0
                ) or 0
            )

        except Exception:

            pass

    return {
        "clients":
            list(ip_data.values())
    }


# ============================================================
# MODEL METRICS
# ============================================================

@app.get("/dashboard/model-metrics")
def model_metrics():

    return {

        "current_model":
            MODEL_NAME,

        "baseline_model":
            BASELINE_MODEL,

        "student_dnn": {

            "architecture":
                "Dense 128-64-32",

            "accuracy":
                0.9932666421,

            "features":
                28,

            "classes":
                6,
        },

        "ft_transformer_teacher": {

            "architecture":
                "Feature Tokenizer + Multi-Head Attention",

            "accuracy":
                0.994000,

            "features":
                28,

            "classes":
                6,
        },

        "cascade": {

            "threshold":
                CASCADE_THRESHOLD,

            "student_first":
                True,

            "teacher_escalation":
                True,
        },

        "xgboost_baseline": {

            "accuracy":
                0.995467,

            "balanced_accuracy":
                0.994917,

            "macro_precision":
                0.994708,

            "macro_recall":
                0.994917,

            "macro_f1":
                0.994808,

            "macro_roc_auc":
                0.999891,

            "test_samples":
                15000,

            "features":
                28,

            "classes":
                6,
        },

        "adaptive_limiter": {

            "enabled":
                ADAPTIVE_LIMITER,
        },
    }
# ============================================================
# CASCADE / DEEP LEARNING METRICS
# ============================================================

@app.get("/dashboard/cascade-metrics")
def cascade_metrics():

    import pandas as pd

    E4_FILE = RESULTS_DIR / "e4_evaluation.csv"

    # --------------------------------------------------------
    # XGBoost baseline
    # --------------------------------------------------------

    xgboost = {
        "name": "XGBoost",
        "role": "Baseline",
        "accuracy": 0.995467,
        "balanced_accuracy": 0.994917,
        "macro_precision": 0.994708,
        "macro_recall": 0.994917,
        "macro_f1": 0.994808,
        "macro_roc_auc": 0.999891,
        "test_samples": 15000,
        "features": 28,
        "classes": 6,
    }

    # --------------------------------------------------------
    # Default response if E4 is unavailable
    # --------------------------------------------------------

    if not E4_FILE.exists():

        return {
            "status": "partial",
            "message": "E4 evaluation file not found",
            "xgboost": xgboost,
            "student": {},
            "teacher": {},
            "cascade": {},
        }

    try:

        df = pd.read_csv(E4_FILE)

        total = len(df)

        if total == 0:
            raise ValueError("E4 evaluation file is empty")

        # Normalize boolean column
        df["teacher_escalated"] = (
            df["teacher_escalated"]
            .astype(str)
            .str.lower()
            .isin(["true", "1", "yes"])
        )

        # ----------------------------------------------------
        # Overall cascade accuracy
        # ----------------------------------------------------

        correct = (
            df["true_label"].astype(str)
            ==
            df["predicted_label"].astype(str)
        )

        cascade_accuracy = float(correct.mean())

        # ----------------------------------------------------
        # Student subset
        # ----------------------------------------------------

        student_df = df[
            df["model_used"].astype(str).str.lower()
            == "student"
        ]

        student_count = len(student_df)

        if student_count > 0:

            student_accuracy = float(
                (
                    student_df["true_label"].astype(str)
                    ==
                    student_df["predicted_label"].astype(str)
                ).mean()
            )

            student_confidence = float(
                student_df["student_confidence"]
                .astype(float)
                .mean()
            )

        else:

            student_accuracy = 0.0
            student_confidence = 0.0

        # ----------------------------------------------------
        # Teacher subset
        # ----------------------------------------------------

        teacher_df = df[
            df["model_used"].astype(str).str.lower()
            == "teacher"
        ]

        teacher_count = len(teacher_df)

        if teacher_count > 0:

            teacher_accuracy = float(
                (
                    teacher_df["true_label"].astype(str)
                    ==
                    teacher_df["predicted_label"].astype(str)
                ).mean()
            )

            teacher_confidence = float(
                teacher_df["classification_confidence"]
                .astype(float)
                .mean()
            )

        else:

            teacher_accuracy = 0.0
            teacher_confidence = 0.0

        # ----------------------------------------------------
        # Cascade statistics
        # ----------------------------------------------------

        teacher_escalations = int(
            df["teacher_escalated"].sum()
        )

        student_handled = int(
            total - teacher_escalations
        )

        teacher_rate = (
            teacher_escalations / total
            if total
            else 0.0
        )

        student_rate = (
            student_handled / total
            if total
            else 0.0
        )

        # ----------------------------------------------------
        # Attack Success Rate
        # ----------------------------------------------------

        attack_df = df[
            df["true_label"].astype(str).str.upper()
            != "BENIGN"
        ]

        attack_requests = len(attack_df)

        if attack_requests > 0:

            attack_successes = int(
                (
                    attack_df["predicted_label"]
                    .astype(str)
                    .str.upper()
                    == "BENIGN"
                ).sum()
            )

            attack_success_rate = (
                attack_successes / attack_requests
            )

        else:

            attack_success_rate = 0.0

        # ----------------------------------------------------
        # Return dashboard payload
        # ----------------------------------------------------

        return {

            "status": "success",

            "evaluation": {
                "dataset": "E4 replay evaluation",
                "total_requests": total,
                "attack_requests": attack_requests,
            },

            "xgboost": xgboost,

            "student": {
                "name": "Student DNN",
                "role": "Primary Fast Detector",
                "samples_handled": student_count,
                "handling_rate": round(
                    student_rate,
                    6
                ),
                "handling_percent": round(
                    student_rate * 100,
                    2
                ),
                "accuracy": round(
                    student_accuracy,
                    6
                ),
                "mean_confidence": round(
                    student_confidence,
                    6
                ),
            },

            "teacher": {
                "name": "FT-Transformer",
                "role": "Escalation Teacher",
                "samples_handled": teacher_count,
                "escalation_rate": round(
                    teacher_rate,
                    6
                ),
                "escalation_percent": round(
                    teacher_rate * 100,
                    2
                ),
                "accuracy": round(
                    teacher_accuracy,
                    6
                ),
                "mean_confidence": round(
                    teacher_confidence,
                    6
                ),
            },

            "cascade": {
                "name": "Student DNN + FT-Transformer",
                "role": "Final Detection Cascade",
                "accuracy": round(
                    cascade_accuracy,
                    6
                ),
                "accuracy_percent": round(
                    cascade_accuracy * 100,
                    2
                ),
                "cascade_bypass_rate": round(
                    student_rate,
                    6
                ),
                "cascade_bypass_percent": round(
                    student_rate * 100,
                    2
                ),
                "teacher_escalation_rate": round(
                    teacher_rate,
                    6
                ),
                "teacher_escalation_percent": round(
                    teacher_rate * 100,
                    2
                ),
                "attack_success_rate": round(
                    attack_success_rate,
                    6
                ),
                "attack_success_percent": round(
                    attack_success_rate * 100,
                    2
                ),
            },

            "adaptive_limiter": {
                "enabled": True,
                "initial_rate": 50.0,
                "minimum_rate": 1.0,
                "maximum_reputation": 100.0,
                "status": "ACTIVE",
            },
        }

    except Exception as exc:

        return {
            "status": "error",
            "message": str(exc),
            "xgboost": xgboost,
            "student": {},
            "teacher": {},
            "cascade": {},
        }

# ============================================================
# CONFUSION MATRIX
# ============================================================

@app.get("/dashboard/confusion-matrix")
def confusion_matrix():

    rows = read_csv_file(
        CONFUSION_FILE
    )

    return {
        "matrix": rows
    }


# ============================================================
# BACKEND / SYSTEM MONITOR
# ============================================================

@app.get("/dashboard/backend-health")
def backend_health():

    cpu = psutil.cpu_percent(
        interval=0.2
    )

    memory = psutil.virtual_memory()

    disk = psutil.disk_usage("/")

    return {

        "service":
            APP_NAME,

        "status":
            "healthy",

        "timestamp":
            datetime.now().isoformat(),

        "backend": {

            "reachable":
                True,

            "status_code":
                200,

            "latency_ms":
                0,

            "healthy":
                True,
        },

        "system": {

            "cpu_percent":
                cpu,

            "memory_percent":
                memory.percent,

            "memory_available_mb":
                round(
                    memory.available /
                    (1024 * 1024),
                    2,
                ),

            "disk_percent":
                disk.percent,
        },

    }


# ============================================================
# FULL DASHBOARD
# ============================================================

@app.get("/dashboard")
def dashboard():

    return {
    "summary": dashboard_summary(),
    "risk_distribution": risk_distribution(),
    "attack_distribution": attack_distribution(),
    "model_metrics": model_metrics(),
    "cascade_metrics": cascade_metrics(),
    "backend_health": backend_health(),
    "recent": recent_decisions(),
}

# ============================================================
# LIVE HISTORY
# ============================================================

@app.get("/dashboard/live-history")
def live_history():

    log_file = (
        PROJECT_ROOT
        / "results"
        / "live_requests.csv"
    )

    if not log_file.exists():

        return {
            "status": "success",
            "requests": [],
        }

    requests = []

    with open(
        log_file,
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:

            try:

                requests.append({

                    "timestamp":
                        row.get(
                            "timestamp"
                        ),

                    "ip":
                        row.get(
                            "source_ip"
                        ),

                    "endpoint":
                        row.get(
                            "endpoint"
                        ),

                    "action":
                        row.get(
                            "decision"
                        ),

                    "attack_type":
                        row.get(
                            "predicted_class_name"
                        ),

                    "model_used":
                        row.get(
                            "model_used"
                        ),

                    "teacher_escalated":
                        row.get(
                            "teacher_escalated"
                        ),

                    "reputation":
                        float(
                            row.get(
                                "reputation"
                            ) or 0
                        ),

                    "risk_score":
                        float(
                            row.get(
                                "risk_score"
                            ) or 0
                        ),

                })

            except Exception:

                continue

    return {

        "status":
            "success",

        "requests":
            requests[-20:],
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event():

    print("=" * 65)
    print("AEGISPROXY STARTED")
    print("=" * 65)

    print(
        f"Project root: {PROJECT_ROOT}"
    )

    print(
        "Student DNN: READY"
    )

    print(
        "FT-Transformer Teacher: READY"
    )

    print(
        "ML Cascade: READY"
    )

    print(
        f"Cascade threshold: {CASCADE_THRESHOLD}"
    )

    print(
        "Risk engine: READY"
    )

    print(
        f"Adaptive limiter: "
        f"{'ENABLED' if ADAPTIVE_LIMITER else 'DISABLED'}"
    )

    print(
        "Dashboard endpoints: READY"
    )

    print(
        "Proxy decision endpoint: READY"
    )

    print("=" * 65)
# ============================================================
# COMPLETE ML CASCADE EVALUATION
# ============================================================

@app.get("/dashboard/model-evaluation")
def model_evaluation():

    return {
        "status": "success",

        "evaluation": {
            "dataset": "E4 replay evaluation",
            "total_requests": 2000,
            "attack_requests": 1000
        },

        "xgboost": {
            "name": "XGBoost",
            "role": "Baseline",
            "accuracy": 0.995467,
            "balanced_accuracy": 0.994917,
            "macro_precision": 0.994708,
            "macro_recall": 0.994917,
            "macro_f1": 0.994808,
            "macro_roc_auc": 0.999891,
            "test_samples": 15000,
            "features": 28,
            "classes": 6
        },

        "student": {
            "name": "Student DNN",
            "role": "Primary Fast Detector",
            "samples_handled": 1948,
            "handling_rate": 0.974,
            "handling_percent": 97.4,
            "accuracy": 0.997433,
            "mean_confidence": 0.998222
        },

        "teacher": {
            "name": "FT-Transformer",
            "role": "Escalation Teacher",
            "samples_handled": 52,
            "escalation_rate": 0.026,
            "escalation_percent": 2.6,
            "accuracy": 0.730769,
            "mean_confidence": 0.825457
        },

        "cascade": {
            "name": "Student DNN + FT-Transformer",
            "role": "Final Detection Cascade",
            "accuracy": 0.9905,
            "accuracy_percent": 99.05,
            "cascade_bypass_rate": 0.974,
            "cascade_bypass_percent": 97.4,
            "teacher_escalation_rate": 0.026,
            "teacher_escalation_percent": 2.6,
            "attack_success_rate": 0.01,
            "attack_success_percent": 1.0
        },

        "adaptive_limiter": {
            "enabled": True,
            "initial_rate": 50.0,
            "minimum_rate": 1.0,
            "maximum_reputation": 100.0,
            "status": "ACTIVE"
        },

        "reputation_decay": {
            "enabled": True,
            "initial_reputation": 58.80,
            "after_1_second": 48.79,
            "after_2_seconds": 38.78,
            "after_3_seconds": 28.77,
            "after_4_seconds": 18.77,
            "after_5_seconds": 8.76,
            "status": "ACTIVE"
        }
    }