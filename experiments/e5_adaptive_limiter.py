from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.adaptive_limiter import AdaptiveLimiter


print("=" * 70)
print("AEGISPROXY — E5 ADAPTIVE LIMITER EVALUATION")
print("=" * 70)

limiter = AdaptiveLimiter(
    base_rate=50.0,
    base_capacity=100.0,
    gamma=2.0,
    window_seconds=1.0,
    block_threshold=100.0,
    reputation_decay=1.0,
)

ip = "10.10.10.10"

print("\nInitial state")
print("-" * 70)

result = limiter.check_request(ip)
print(result)


print("\nReputation → Rate progression")
print("-" * 70)

for reputation in [0, 25, 50, 75, 90, 95, 100]:

    rate = limiter.calculate_rate(reputation)
    capacity = limiter.calculate_capacity(reputation)

    print(
        f"Reputation={reputation:3} | "
        f"Rate={rate:7.2f} req/s | "
        f"Capacity={capacity:7.2f}"
    )


print("\nSimulating attack detections")
print("-" * 70)

for i in range(9):

    reputation = limiter.update_reputation(
        ip=ip,
        attack_probability=0.99,
        predicted_class=3,
        classification_confidence=0.99,
    )

    rate = limiter.calculate_rate(reputation)
    capacity = limiter.calculate_capacity(reputation)

    print(
        f"Attack {i + 1:2} | "
        f"Reputation={reputation:6.2f} | "
        f"Rate={rate:7.2f} | "
        f"Capacity={capacity:7.2f}"
    )


print("\nFinal request decision")
print("-" * 70)

final_result = limiter.check_request(ip)

print(final_result)


print("\nE5 evaluation completed.")
print("=" * 70)