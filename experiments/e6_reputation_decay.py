from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.adaptive_limiter import AdaptiveLimiter


print("=" * 70)
print("AEGISPROXY — E6 REPUTATION DECAY EVALUATION")
print("=" * 70)

limiter = AdaptiveLimiter(
    base_rate=50.0,
    base_capacity=100.0,
    gamma=2.0,
    window_seconds=1.0,
    block_threshold=100.0,
    reputation_decay=10.0,
)

ip = "10.20.30.40"

print("\nInitial state")
print("-" * 70)

print(
    "Reputation:",
    round(limiter.get_reputation(ip), 2)
)

print(
    "Rate:",
    round(limiter.calculate_rate(
        limiter.get_reputation(ip)
    ), 2)
)


print("\nInjecting attack detections")
print("-" * 70)

for i in range(5):

    reputation = limiter.update_reputation(
        ip=ip,
        attack_probability=0.99,
        predicted_class=3,
        classification_confidence=0.99,
    )

    print(
        f"Attack {i + 1}: "
        f"Reputation={reputation:.2f}, "
        f"Rate={limiter.calculate_rate(reputation):.2f}"
    )


print("\nState immediately after attacks")
print("-" * 70)

reputation = limiter.get_reputation(ip)

print(
    f"Reputation={reputation:.2f}, "
    f"Rate={limiter.calculate_rate(reputation):.2f}"
)


print("\nWaiting for reputation decay...")
print("-" * 70)

for i in range(1, 6):

    time.sleep(1)

    reputation = limiter.get_reputation(ip)

    rate = limiter.calculate_rate(reputation)

    print(
        f"After {i} second(s): "
        f"Reputation={reputation:.2f}, "
        f"Rate={rate:.2f} req/s"
    )


print("\nE6 evaluation completed.")
print("=" * 70)