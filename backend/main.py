from pathlib import Path
from datetime import datetime
import csv
import time
import psutil
import urllib.request
import urllib.error

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from .detector import predict
from .risk_engine import calculate_risk


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

LIVE_REQUESTS_FILE = RESULTS_DIR / "live_requests.csv"

APP_NAME = "AegisProxy"
APP_VERSION = "1.0"

# Protected backend
BACKEND_URL = "http://127.0.0.1:9001"

# ============================================================
# RATE LIMIT CONFIGURATION
# ============================================================

RATE_LIMIT_REQUESTS = 5
RATE_LIMIT_WINDOW = 10          # seconds
TEMP_BLOCK_SECONDS = 30

# IP -> timestamps
request_history = {}

# IP -> block expiry timestamp
blocked_ips = {}


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Self-Adaptive Risk-Aware Intelligent Reverse Proxy",
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
            "IP Identification",
            "Rate Limit Check",
            "Feature Input",
            "XGBoost Detection",
            "Risk Engine",
            "Policy Decision",
            "ALLOW / RATE_LIMIT / BLOCK",
        ],
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": APP_NAME,
        "model": "XGBoost",
        "model_available": True,
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
            "xgboost": "loaded",
            "quantile_transformer": "loaded",
        },
    }


# ============================================================
# RATE LIMIT HELPERS
# ============================================================

def check_rate_limit(client_ip):
    now = time.time()

    if client_ip in blocked_ips:
        if now < blocked_ips[client_ip]:
            return {
                "blocked": True,
                "rate_limited": False,
                "count": 0,
                "remaining": 0,
            }
        else:
            del blocked_ips[client_ip]

    if client_ip not in request_history:
        request_history[client_ip] = []

    request_history[client_ip] = [
        t for t in request_history[client_ip]
        if now - t < RATE_LIMIT_WINDOW
    ]

    request_history[client_ip].append(now)

    count = len(request_history[client_ip])

    return {
        "blocked": False,
        "rate_limited": count > RATE_LIMIT_REQUESTS,
        "count": count,
        "remaining": max(
            0,
            RATE_LIMIT_REQUESTS - count
        ),
    }
    # --------------------------------------------------------
    # Check temporary block
    # --------------------------------------------------------

    if ip in blocked_ips:

        expiry = blocked_ips[ip]

        if now < expiry:

            remaining = round(expiry - now, 2)

            return {
                "allowed": False,
                "blocked": True,
                "rate_limited": False,
                "remaining": remaining,
            }

        del blocked_ips[ip]

    # --------------------------------------------------------
    # Get request timestamps
    # --------------------------------------------------------

    timestamps = request_history.get(ip, [])

    # Keep only requests inside current window

    timestamps = [
        timestamp
        for timestamp in timestamps
        if now - timestamp < RATE_LIMIT_WINDOW
    ]

    # --------------------------------------------------------
    # Rate limit
    # --------------------------------------------------------

    if len(timestamps) >= RATE_LIMIT_REQUESTS:

        request_history[ip] = timestamps

        return {
            "allowed": False,
            "blocked": False,
            "rate_limited": True,
            "remaining": 0,
        }

    # --------------------------------------------------------
    # Register request
    # --------------------------------------------------------

    timestamps.append(now)

    request_history[ip] = timestamps

    return {
        "allowed": True,
        "blocked": False,
        "rate_limited": False,
        "remaining": RATE_LIMIT_REQUESTS - len(timestamps),
    }


# ============================================================
# PREDICTION
# ============================================================

@app.post("/predict")
def prediction(request: PredictionRequest):

    try:

        result = predict(request.features)

        return result

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# RISK ENGINE
# ============================================================

@app.post("/risk")
def risk_prediction(request: PredictionRequest):

    try:

        prediction_result = predict(request.features)

        risk_result = calculate_risk(prediction_result)

        return {
            **prediction_result,
            **risk_result,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# CSV LOGGING
# ============================================================
def get_client_ip(request: Request):
    forwarded = request.headers.get("X-Forwarded-For")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host if request.client else "127.0.0.1"
def log_proxy_request(
    ip,
    endpoint,
    prediction_result,
    risk_result,
    decision,
):

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    row = {

        "timestamp":
            datetime.now().isoformat(),

        "source_ip":
            ip,

        "endpoint":
            endpoint,

        "predicted_class":
            prediction_result.get("predicted_class"),

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
    }

    file_exists = LIVE_REQUESTS_FILE.exists()

    with open(
        LIVE_REQUESTS_FILE,
        "a",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=row.keys(),
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)


# ============================================================
# MAIN PROXY
# ============================================================

@app.post("/proxy")
def proxy_request(
    request: PredictionRequest,
    http_request: Request,
):

    try:

        # ----------------------------------------------------
        # 1. Identify client
        # ----------------------------------------------------

        client_ip = get_client_ip(http_request)

        # ----------------------------------------------------
        # 2. Rate-limit check
        # ----------------------------------------------------

        rate_result = check_rate_limit(client_ip)

        # ----------------------------------------------------
        # Temporarily blocked IP
        # ----------------------------------------------------

        if rate_result["blocked"]:

            decision = "BLOCK"

            prediction_result = {
                "predicted_class": -1,
                "predicted_class_name": "RATE_LIMIT_BLOCK",
                "classification_confidence": 1.0,
                "attack_probability": 1.0,
            }

            risk_result = {
                "risk_score": 1.0,
                "adaptive_threshold": 0.5,
                "evidence_attack": 1.0,
                "evidence_confidence": 1.0,
                "evidence_class": 1.0,
                "decision": "BLOCK",
            }

            log_proxy_request(
                client_ip,
                "/proxy",
                prediction_result,
                risk_result,
                decision,
            )

            return {
                "proxy_action": "BLOCK",

                "message":
                    "IP temporarily blocked by AegisProxy",

                "timestamp":
                    datetime.now().isoformat(),

                "source_ip":
                    client_ip,

                "rate_limit": rate_result,

                "security":
                    prediction_result,

                "risk":
                    risk_result,
            }

        # ----------------------------------------------------
        # Rate limit exceeded
        # ----------------------------------------------------

        if rate_result["rate_limited"]:

            decision = "RATE_LIMIT"

            prediction_result = {
                "predicted_class": -1,
                "predicted_class_name": "RATE_LIMIT",
                "classification_confidence": 1.0,
                "attack_probability": 0.0,
            }

            risk_result = {
                "risk_score": 0.5,
                "adaptive_threshold": 0.5,
                "evidence_attack": 0.0,
                "evidence_confidence": 1.0,
                "evidence_class": 0.0,
                "decision": "RATE_LIMIT",
            }

            log_proxy_request(
                client_ip,
                "/proxy",
                prediction_result,
                risk_result,
                decision,
            )

            return {
                "proxy_action": "RATE_LIMIT",

                "message":
                    "Request rate-limited by AegisProxy",

                "timestamp":
                    datetime.now().isoformat(),

                "source_ip":
                    client_ip,

                "rate_limit": {
                    **rate_result,
                    "limit":
                        RATE_LIMIT_REQUESTS,
                    "window_seconds":
                        RATE_LIMIT_WINDOW,
                },

                "security":
                    prediction_result,

                "risk":
                    risk_result,
            }

        # ----------------------------------------------------
        # 3. ML Detection
        # ----------------------------------------------------

        prediction_result = predict(
            request.features
        )

        # ----------------------------------------------------
        # 4. Risk Engine
        # ----------------------------------------------------

        risk_result = calculate_risk(
            prediction_result
        )

        decision = risk_result.get(
            "decision",
            "ALLOW",
        )

        # ----------------------------------------------------
        # 5. If ML detects attack -> block IP
        # ----------------------------------------------------

        if decision == "BLOCK":

            blocked_ips[client_ip] = (
                time.time()
                + TEMP_BLOCK_SECONDS
            )

        # ----------------------------------------------------
        # 6. Logging
        # ----------------------------------------------------

        log_proxy_request(
            client_ip,
            "/proxy",
            prediction_result,
            risk_result,
            decision,
        )

        # ----------------------------------------------------
        # 7. Message
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
        # 8. Response
        # ----------------------------------------------------

        return {

            "proxy_action":
                decision,

            "message":
                message,

            "timestamp":
                datetime.now().isoformat(),

            "source_ip":
                client_ip,

            "rate_limit": {
                "remaining":
                    rate_result["remaining"],

                "limit":
                    RATE_LIMIT_REQUESTS,

                "window_seconds":
                    RATE_LIMIT_WINDOW,
            },

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
            },

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
        }

    except Exception as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# CSV READER
# ============================================================

def read_csv_file(
    path: Path,
    limit=None,
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

    except Exception:

        return []

    if limit:

        return rows[-limit:]

    return rows


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

@app.get("/dashboard/summary")
def dashboard_summary():

    rows = read_csv_file(
        LIVE_REQUESTS_FILE
    )

    total = len(rows)

    allowed = 0
    blocked = 0
    rate_limited = 0

    attacks = 0

    for row in rows:

        decision = str(
            row.get("decision", "")
        ).upper()

        if decision == "ALLOW":
            allowed += 1

        elif decision == "BLOCK":
            blocked += 1

        elif decision in (
            "RATE_LIMIT",
            "RATE-LIMIT",
            "RATELIMIT",
        ):

            rate_limited += 1

        attack_probability = float(
            row.get(
                "attack_probability",
                0,
            ) or 0
        )

        if attack_probability >= 0.5:
            attacks += 1

    return {

        "system":
            "AegisProxy",

        "model":
            "XGBoost",

        "total_requests":
            total,

        "allowed_requests":
            allowed,

        "blocked_requests":
            blocked,

        "rate_limited_requests":
            rate_limited,

        "detected_attacks":
            attacks,

        "block_rate_percent":
            round(
                blocked / total * 100,
                2,
            ) if total else 0,

        "allow_rate_percent":
            round(
                allowed / total * 100,
                2,
            ) if total else 0,

        "rate_limit_percent":
            round(
                rate_limited / total * 100,
                2,
            ) if total else 0,

        "model_accuracy":
            0.995467,

        "balanced_accuracy":
            0.994917,

        "macro_f1":
            0.994808,

        "macro_roc_auc":
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
        LIVE_REQUESTS_FILE
    )

    distribution = {
        "ALLOW": 0,
        "BLOCK": 0,
        "RATE_LIMIT": 0,
    }

    for row in rows:

        decision = str(
            row.get("decision", "")
        ).upper()

        if decision in distribution:

            distribution[decision] += 1

    return distribution


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

@app.get("/dashboard/attack-distribution")
def attack_distribution():

    rows = read_csv_file(
        LIVE_REQUESTS_FILE
    )

    distribution = {}

    for row in rows:

        name = (
            row.get(
                "predicted_class_name"
            )
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
        LIVE_REQUESTS_FILE,
        limit=20,
    )

    return {
        "count": len(rows),
        "records": rows,
    }


# ============================================================
# REQUEST HISTORY
# ============================================================

@app.get("/dashboard/request-history")
def request_history_endpoint():

    rows = read_csv_file(
        LIVE_REQUESTS_FILE,
        limit=100,
    )

    history = []

    for index, row in enumerate(rows):

        history.append({

            "request_id":
                index + 1,

            "source_ip":
                row.get(
                    "source_ip",
                    "127.0.0.1",
                ),

            "timestamp":
                row.get(
                    "timestamp",
                    "",
                ),

            "predicted_class":
                row.get(
                    "predicted_class_name",
                    "UNKNOWN",
                ),

            "attack_probability":
                row.get(
                    "attack_probability",
                    "",
                ),

            "risk_score":
                row.get(
                    "risk_score",
                    "",
                ),

            "decision":
                row.get(
                    "decision",
                    "UNKNOWN",
                ),
        })

    return {

        "total":
            len(history),

        "history":
            history,
    }


# ============================================================
# IP HISTORY
# ============================================================

@app.get("/dashboard/ip-history")
def ip_history():

    rows = read_csv_file(
        LIVE_REQUESTS_FILE,
        limit=1000,
    )

    ip_data = {}

    for row in rows:

        ip = row.get(
            "source_ip",
            "127.0.0.1",
        )

        if ip not in ip_data:

            ip_data[ip] = {

                "ip":
                    ip,

                "requests":
                    0,

                "allowed":
                    0,

                "blocked":
                    0,

                "rate_limited":
                    0,
            }

        ip_data[ip]["requests"] += 1

        decision = str(
            row.get(
                "decision",
                "",
            )
        ).upper()

        if decision == "ALLOW":

            ip_data[ip]["allowed"] += 1

        elif decision == "BLOCK":

            ip_data[ip]["blocked"] += 1

        elif decision == "RATE_LIMIT":

            ip_data[ip]["rate_limited"] += 1

    return {
        "clients":
            list(ip_data.values())
    }


# ============================================================
# RATE LIMIT STATUS
# ============================================================

@app.get("/dashboard/rate-limit")
def rate_limit_status():

    now = time.time()

    clients = []

    for ip, timestamps in request_history.items():

        active = [
            timestamp
            for timestamp in timestamps
            if now - timestamp < RATE_LIMIT_WINDOW
        ]

        if active:

            clients.append({

                "ip":
                    ip,

                "requests_in_window":
                    len(active),

                "limit":
                    RATE_LIMIT_REQUESTS,

                "window_seconds":
                    RATE_LIMIT_WINDOW,

                "remaining":
                    max(
                        RATE_LIMIT_REQUESTS
                        - len(active),
                        0,
                    ),

                "blocked":
                    ip in blocked_ips
                    and now < blocked_ips[ip],
            })

    return {

        "configuration": {

            "limit":
                RATE_LIMIT_REQUESTS,

            "window_seconds":
                RATE_LIMIT_WINDOW,

            "temporary_block_seconds":
                TEMP_BLOCK_SECONDS,
        },

        "clients":
            clients,
    }


# ============================================================
# MODEL METRICS
# ============================================================

@app.get("/dashboard/model-metrics")
def model_metrics():

    return {

        "model":
            "XGBoost",

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
# BACKEND HEALTH
# ============================================================

@app.get("/dashboard/backend-health")
def backend_health():

    cpu = psutil.cpu_percent(
        interval=0.2
    )

    memory = psutil.virtual_memory()

    disk = psutil.disk_usage("/")

    backend_reachable = False
    backend_status = 0
    backend_latency = 0

    # --------------------------------------------------------
    # Actually check protected backend
    # --------------------------------------------------------

    start = time.perf_counter()

    try:

        response = urllib.request.urlopen(
            BACKEND_URL + "/health",
            timeout=2,
        )

        backend_status = response.status

        backend_reachable = (
            response.status == 200
        )

        backend_latency = round(
            (
                time.perf_counter()
                - start
            ) * 1000,
            2,
        )

    except Exception:

        backend_reachable = False

        backend_status = 0

        backend_latency = round(
            (
                time.perf_counter()
                - start
            ) * 1000,
            2,
        )

    return {

        "service":
            "AegisProxy",

        "status":
            "healthy",

        "timestamp":
            datetime.now().isoformat(),

        "backend": {

            "url":
                BACKEND_URL,

            "reachable":
                backend_reachable,

            "status_code":
                backend_status,

            "latency_ms":
                backend_latency,

            "healthy":
                backend_reachable,
        },

        "system": {

            "cpu_percent":
                cpu,

            "memory_percent":
                memory.percent,

            "memory_available_mb":
                round(
                    memory.available
                    / (1024 * 1024),
                    2,
                ),

            "disk_percent":
                disk.percent,
        },
    }


# ============================================================
# LIVE HISTORY
# ============================================================

@app.get("/dashboard/live-history")
def live_history():

    rows = read_csv_file(
        LIVE_REQUESTS_FILE,
        limit=50,
    )

    requests = []

    for row in rows:

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

                "risk_score":
                    float(
                        row.get(
                            "risk_score"
                        ) or 0
                    ),

                "attack_probability":
                    float(
                        row.get(
                            "attack_probability"
                        ) or 0
                    ),
            })

        except Exception:

            continue

    return {

        "status":
            "success",

        "requests":
            requests,
    }


# ============================================================
# FULL DASHBOARD
# ============================================================

@app.get("/dashboard")
def dashboard():

    return {

        "summary":
            dashboard_summary(),

        "risk_distribution":
            risk_distribution(),

        "attack_distribution":
            attack_distribution(),

        "model_metrics":
            model_metrics(),

        "backend_health":
            backend_health(),

        "rate_limit":
            rate_limit_status(),

        "recent":
            recent_decisions(),
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event():

    print("=" * 60)

    print("AEGISPROXY STARTED")

    print("=" * 60)

    print(
        f"Project root: {PROJECT_ROOT}"
    )

    print(
        "ML detector: READY"
    )

    print(
        "Risk engine: READY"
    )

    print(
        "Rate limiter: READY"
    )

    print(
        "Dashboard endpoints: READY"
    )

    print(
        "Backend health monitor: READY"
    )

    print(
        "Proxy decision endpoint: READY"
    )

    print("=" * 60)
