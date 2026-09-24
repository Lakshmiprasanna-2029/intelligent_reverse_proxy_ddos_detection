from fastapi import FastAPI
from datetime import datetime

app = FastAPI(title="AegisProxy Protected Backend")


@app.get("/")
def root():
    return {
        "service": "Protected Backend",
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "protected-backend",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/data")
def data():
    return {
        "message": "Response from protected backend",
        "status": "success",
        "timestamp": datetime.now().isoformat()
    }