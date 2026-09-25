"""
AegisProxy E7 — End-to-End Adaptive Attack Scenario

Demonstrates:

Request
  -> Cascade
  -> Risk
  -> Reputation
  -> Adaptive Limiter
  -> ALLOW / THROTTLE / BLOCK
"""

from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.cascade import predict
from backend.adaptive_limiter import AdaptiveLimiter


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

IP = "10.20.30.40"

# 28-feature attack sample that is known to trigger
# the teacher as demonstrated earlier.
ATTACK_FEATURES = [
    7.4066027089111657,
    7.5597132079016554,
    1.5665087706755862,
    4.6490579710291478,
    -2.5264469200965856,
    7.860849271698772,
    -6.337436147096695,
    2.0628109583406875,
    -4.254938302611587,
    3.633163454785699,
    -5.107916651471434,
    1.6433769301102163,
    6.7046895397078,
    9.981072406846568,
    -5.430418028041622,
    -0.360220804985552,
    -6.987583755758182,
    7.910097913897921,
    1.5301421895823601,
    2.2637241751567814,
    -7.79893602959183,
    -1.507993294377318,
    -6.816525075480911,
    6.898376134493653,
    -1.156980916246095,
    -6.927399343214396,
    0.16835062510090815,
    1.57340816168327,
]


print("=" * 70)
print("AEGISPROXY — E7 END-TO-END ADAPTIVE ATTACK SCENARIO")
print("=" * 70)

limiter = AdaptiveLimiter()

print("\nInitial request")
print("-" * 70)

initial = limiter.check_request(IP)
print(initial)

print("\nSending repeated attack detections")
print("-" * 70)

records = []

for i in range(1, 10):

    result = predict(ATTACK_FEATURES)

    predicted = result.get("predicted_class_name")
    confidence = float(
        result.get("classification_confidence", 0.0)
    )

    attack_probability = float(
        result.get("attack_probability", 0.0)
    )

    predicted_class = int(
        result.get("predicted_class", 0)
    )

    # Update reputation using model evidence.
    reputation = limiter.update_reputation(
        IP,
        attack_probability,
        predicted_class,
        confidence,
    )

    state = limiter.check_request(IP)

    records.append({
        "request": i,
        "predicted_class": predicted,
        "confidence": confidence,
        "attack_probability": attack_probability,
        "reputation": reputation,
        "rate": state.get("allowed_rate"),
        "capacity": state.get("capacity"),
        "decision": state.get("decision"),
    })

    print(
        f"Request {i:2d} | "
        f"Class={predicted:18s} | "
        f"Confidence={confidence:.4f} | "
        f"AttackProb={attack_probability:.4f} | "
        f"Reputation={reputation:6.2f} | "
        f"Rate={state.get('allowed_rate'):6.2f} | "
        f"Decision={state.get('decision')}"
    )

print("\nFinal state")
print("-" * 70)

final_state = limiter.check_request(IP)

print(final_state)

print("\nE7 SUMMARY")
print("-" * 70)

print(f"Initial reputation : {initial.get('reputation')}")
print(f"Final reputation   : {final_state.get('reputation')}")
print(f"Final rate         : {final_state.get('allowed_rate')}")
print(f"Final capacity     : {final_state.get('capacity')}")
print(f"Final decision     : {final_state.get('decision')}")

print("\nE7 evaluation completed.")
print("=" * 70)