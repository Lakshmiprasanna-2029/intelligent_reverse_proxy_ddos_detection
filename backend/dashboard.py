from pathlib import Path
import time
import pandas as pd
import psutil
from fastapi import APIRouter

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"

RISK_FILE = RESULTS_DIR / "risk_decisions.csv"
METRICS_FILE = RESULTS_DIR / "final_metrics.csv"
CM_FILE = RESULTS_DIR / "confusion_matrix.csv"


def load_csv(path):
    if not path.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


def get_dashboard_summary():
    risk = load_csv(RISK_FILE)
    metrics = load_csv(METRICS_FILE)

    result = {
        "model": "XGBoost",
        "total_test_samples": 15000,
        "total_risk_decisions": len(risk),
        "allowed": 0,
        "blocked": 0,
        "rate_limited": 0,
        "accuracy": None,
        "balanced_accuracy": None,
        "precision": None,
        "recall": None,
        "f1": None,
        "roc_auc": None
    }

    if not risk.empty and "decision" in risk.columns:
        result["allowed"] = int((risk["decision"] == "ALLOW").sum())
        result["blocked"] = int((risk["decision"] == "BLOCK").sum())
        result["rate_limited"] = int(
            (risk["decision"] == "RATE_LIMIT").sum()
        )

    if not metrics.empty:
        row = metrics.iloc[0]

        aliases = {
            "accuracy": ["accuracy"],
            "balanced_accuracy": ["balanced_accuracy"],
            "precision": ["precision", "macro_precision"],
            "recall": ["recall", "macro_recall"],
            "f1": ["f1", "macro_f1"],
            "roc_auc": ["roc_auc", "macro_roc_auc"]
        }

        for target, names in aliases.items():
            for name in names:
                if name in metrics.columns:
                    try:
                        result[target] = float(row[name])
                        break
                    except:
                        pass

    return result


def get_risk_distribution():
    risk = load_csv(RISK_FILE)

    result = {
        "BLOCK": 0,
        "ALLOW": 0,
        "RATE_LIMIT": 0
    }

    if not risk.empty and "decision" in risk.columns:
        counts = risk["decision"].value_counts()

        for key in result:
            result[key] = int(counts.get(key, 0))

    return result


def get_attack_distribution():
    risk = load_csv(RISK_FILE)

    if risk.empty:
        return {}

    column = (
        "true_class_name"
        if "true_class_name" in risk.columns
        else "predicted_class_name"
    )

    if column not in risk.columns:
        return {}

    return {
        str(k): int(v)
        for k, v in risk[column].value_counts().items()
    }


def get_recent_decisions(limit=20):
    risk = load_csv(RISK_FILE)

    if risk.empty:
        return []

    columns = [
        "true_class_name",
        "predicted_class_name",
        "classification_confidence",
        "attack_probability",
        "evidence_attack",
        "evidence_confidence",
        "risk_score",
        "decision"
    ]

    columns = [c for c in columns if c in risk.columns]

    return risk[columns].tail(limit).to_dict(orient="records")


def get_confusion_matrix():
    cm = load_csv(CM_FILE)

    if cm.empty:
        return []

    return cm.to_dict(orient="records")


def get_model_metrics():
    metrics = load_csv(METRICS_FILE)

    if metrics.empty:
        return {}

    return metrics.iloc[0].to_dict()


def get_system_health():
    return {
        "status": "ONLINE",
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "memory_percent": psutil.virtual_memory().percent,
        "timestamp": time.time()
    }


# ============================================================
# DASHBOARD API ROUTES
# ============================================================

@router.get("/summary")
def dashboard_summary():
    return get_dashboard_summary()


@router.get("/risk-distribution")
def risk_distribution():
    return get_risk_distribution()


@router.get("/attack-distribution")
def attack_distribution():
    return get_attack_distribution()


@router.get("/recent")
def recent_decisions():
    return get_recent_decisions()


@router.get("/confusion-matrix")
def confusion_matrix():
    return get_confusion_matrix()


@router.get("/metrics")
def model_metrics():
    return get_model_metrics()


@router.get("/health")
def system_health():
    return get_system_health()

@app.get("/dashboard/live-history")
def live_history():
    import csv
    from pathlib import Path

    log_file = Path("results/live_requests.csv")

    if not log_file.exists():
        return {
            "status": "success",
            "requests": []
        }

    rows = []

    with open(log_file, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            rows.append({
                "timestamp": row.get("timestamp"),
                "ip": row.get("source_ip"),
                "endpoint": row.get("endpoint"),
                "action": row.get("decision"),
                "attack_type": row.get("predicted_class_name"),
                "risk_score": float(row.get("risk_score", 0))
            })

    return {
        "status": "success",
        "requests": rows[-20:]
    }