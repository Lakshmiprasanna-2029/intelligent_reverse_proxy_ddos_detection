"""
AegisProxy Adaptive Risk-Aware Rate Limiter

Reputation:
    0   -> trusted
    100 -> highly malicious

The limiter converts reputation into a graduated request rate.

Decision:
    ALLOW
    THROTTLE
    BLOCK
"""

import time
from collections import defaultdict, deque
from threading import Lock


class AdaptiveLimiter:

    def __init__(
        self,
        base_rate=50.0,
        base_capacity=100.0,
        gamma=2.0,
        window_seconds=1.0,
        block_threshold=100.0,
        reputation_decay=1.0,
    ):
        self.base_rate = float(base_rate)
        self.base_capacity = float(base_capacity)
        self.gamma = float(gamma)

        self.window_seconds = float(window_seconds)
        self.block_threshold = float(block_threshold)
        self.reputation_decay = float(reputation_decay)

        # IP -> reputation
        self.reputations = defaultdict(float)

        # IP -> request timestamps
        self.requests = defaultdict(deque)

        # Last time reputation was updated
        self.last_update = {}

        self.lock = Lock()

    # =========================================================
    # REPUTATION
    # =========================================================

    def get_reputation(self, ip):
        """
        Return current reputation after applying passive decay.
        """

        now = time.time()

        reputation = self.reputations[ip]

        if ip in self.last_update:
            elapsed = now - self.last_update[ip]

            decay = self.reputation_decay * elapsed

            reputation = max(
                0.0,
                reputation - decay
            )

            self.reputations[ip] = reputation

        self.last_update[ip] = now

        return reputation

    def update_reputation(
        self,
        ip,
        attack_probability,
        predicted_class,
        classification_confidence,
    ):
        """
        Update reputation after ML detection.

        Higher attack probability produces a larger reputation
        increase.

        BENIGN/high-confidence traffic decreases reputation.
        """

        with self.lock:

            current = self.get_reputation(ip)

            attack_probability = max(
                0.0,
                min(1.0, float(attack_probability))
            )

            classification_confidence = max(
                0.0,
                min(1.0, float(classification_confidence))
            )

            # -------------------------------------------------
            # BENIGN
            # -------------------------------------------------

            if predicted_class == 0:

                decrease = (
                    2.0 * classification_confidence
                )

                new_reputation = max(
                    0.0,
                    current - decrease
                )

            # -------------------------------------------------
            # ATTACK
            # -------------------------------------------------

            else:

                increase = (
                    12.0
                    * attack_probability
                    * classification_confidence
                )

                new_reputation = min(
                    100.0,
                    current + increase
                )

            self.reputations[ip] = new_reputation
            self.last_update[ip] = time.time()

            return new_reputation

    # =========================================================
    # ADAPTIVE RATE
    # =========================================================

    def calculate_rate(self, reputation):
        """
        Convert reputation into allowed request rate.

        reputation 0   -> 50 req/s
        reputation 25  -> ~28 req/s
        reputation 50  -> ~12.5 req/s
        reputation 75  -> ~3 req/s
        reputation 100 -> 1 req/s
        """

        reputation = max(
            0.0,
            min(100.0, float(reputation))
        )

        normalized = reputation / 100.0

        factor = max(
            0.0,
            1.0 - normalized
        ) ** self.gamma

        rate = max(
            1.0,
            self.base_rate * factor
        )

        return rate

    def calculate_capacity(self, reputation):
        """
        Calculate burst capacity.
        """

        reputation = max(
            0.0,
            min(100.0, float(reputation))
        )

        normalized = reputation / 100.0

        capacity = max(
            5.0,
            self.base_capacity * (1.0 - normalized)
        )

        return capacity

    # =========================================================
    # REQUEST WINDOW
    # =========================================================

    def _cleanup(self, ip, now):

        timestamps = self.requests[ip]

        cutoff = now - self.window_seconds

        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

    # =========================================================
    # REQUEST DECISION
    # =========================================================

    def check_request(self, ip):

        with self.lock:

            now = time.time()

            reputation = self.get_reputation(ip)

            rate = self.calculate_rate(
                reputation
            )

            capacity = self.calculate_capacity(
                reputation
            )

            # -------------------------------------------------
            # HARD BLOCK
            # -------------------------------------------------

            if reputation >= self.block_threshold:

                return {
                    "allowed": False,
                    "decision": "BLOCK",
                    "ip": ip,
                    "reputation": round(reputation, 3),
                    "allowed_rate": round(rate, 3),
                    "capacity": round(capacity, 3),
                }

            # -------------------------------------------------
            # CLEAN OLD REQUESTS
            # -------------------------------------------------

            self._cleanup(ip, now)

            timestamps = self.requests[ip]

            # -------------------------------------------------
            # RATE LIMIT
            # -------------------------------------------------

            request_count = len(timestamps)

            allowed_requests = max(
                1,
                int(rate * self.window_seconds)
            )

            if request_count >= allowed_requests:

                return {
                    "allowed": False,
                    "decision": "THROTTLE",
                    "ip": ip,
                    "reputation": round(reputation, 3),
                    "allowed_rate": round(rate, 3),
                    "capacity": round(capacity, 3),
                    "requests_in_window": request_count,
                }

            # -------------------------------------------------
            # ALLOW
            # -------------------------------------------------

            timestamps.append(now)

            return {
                "allowed": True,
                "decision": "ALLOW",
                "ip": ip,
                "reputation": round(reputation, 3),
                "allowed_rate": round(rate, 3),
                "capacity": round(capacity, 3),
                "requests_in_window": request_count + 1,
            }


# =============================================================
# SIMPLE LOCAL TEST
# =============================================================

if __name__ == "__main__":

    limiter = AdaptiveLimiter()

    ip = "192.168.1.100"

    print("=" * 60)
    print("AEGISPROXY ADAPTIVE LIMITER TEST")
    print("=" * 60)

    # ---------------------------------------------------------
    # Reputation → rate table
    # ---------------------------------------------------------

    print("\nReputation → Allowed Rate")

    for reputation in [0, 25, 50, 75, 100]:

        rate = limiter.calculate_rate(
            reputation
        )

        capacity = limiter.calculate_capacity(
            reputation
        )

        print(
            f"Reputation {reputation:3} "
            f"→ Rate {rate:7.2f} req/s "
            f"→ Capacity {capacity:7.2f}"
        )

    # ---------------------------------------------------------
    # Benign traffic
    # ---------------------------------------------------------

    print("\nInitial request:")

    print(
        limiter.check_request(ip)
    )

    # ---------------------------------------------------------
    # Simulate attack detections
    # ---------------------------------------------------------

    print("\nUpdating reputation with attack detections...")

    for i in range(5):

        reputation = limiter.update_reputation(
            ip=ip,
            attack_probability=0.99,
            predicted_class=3,
            classification_confidence=0.99,
        )

        print(
            f"Attack {i + 1}: "
            f"reputation = {reputation:.2f}, "
            f"rate = {limiter.calculate_rate(reputation):.2f}"
        )

    # ---------------------------------------------------------
    # Final request
    # ---------------------------------------------------------

    print("\nRequest after reputation increase:")

    print(
        limiter.check_request(ip)
    )