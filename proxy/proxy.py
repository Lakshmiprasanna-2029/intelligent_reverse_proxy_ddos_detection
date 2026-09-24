import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="AegisProxy Reverse Proxy")

BACKEND_URL = "http://127.0.0.1:8000"


@app.get("/proxy-health")
def proxy_health():
    return {
        "proxy": "AegisProxy",
        "status": "running",
        "mode": "risk-aware"
    }


@app.post("/proxy")
async def proxy_request(request: Request):

    body = await request.json()

    features = body.get("features")

    if not features or len(features) != 28:
        return JSONResponse(
            status_code=400,
            content={
                "error": "Exactly 28 features are required",
                "received": len(features) if features else 0
            }
        )

    try:
        response = requests.post(
            f"{BACKEND_URL}/risk",
            json={"features": features},
            timeout=10
        )

        risk = response.json()

    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "error": "Risk engine unavailable",
                "details": str(e)
            }
        )

    decision = risk.get("decision")

    if decision == "BLOCK":
        return JSONResponse(
            status_code=403,
            content={
                "proxy_action": "BLOCK",
                "reason": "High risk traffic detected",
                **risk
            }
        )

    if decision == "RATE_LIMIT":
        return JSONResponse(
            status_code=429,
            content={
                "proxy_action": "RATE_LIMIT",
                "reason": "Suspicious traffic detected",
                **risk
            }
        )

    # ALLOW
    return {
        "proxy_action": "ALLOW",
        "message": "Request allowed by AegisProxy",
        **risk
    }