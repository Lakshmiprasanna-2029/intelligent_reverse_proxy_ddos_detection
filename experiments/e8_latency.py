"""
AegisProxy E8 — Inference and End-to-End Latency Evaluation
"""

from pathlib import Path
import sys
import time
import statistics

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.cascade import predict


FEATURES = [
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
print("AEGISPROXY — E8 LATENCY EVALUATION")
print("=" * 70)

# Warm-up
for _ in range(10):
    predict(FEATURES)

times = []

N = 100

for _ in range(N):

    start = time.perf_counter()

    predict(FEATURES)

    end = time.perf_counter()

    times.append((end - start) * 1000)


avg = statistics.mean(times)
median = statistics.median(times)
minimum = min(times)
maximum = max(times)

p95_index = int(0.95 * len(times)) - 1
p95 = sorted(times)[p95_index]

print("\nResults")
print("-" * 70)

print(f"Requests measured : {N}")
print(f"Average latency   : {avg:.3f} ms")
print(f"Median latency    : {median:.3f} ms")
print(f"Minimum latency   : {minimum:.3f} ms")
print(f"Maximum latency   : {maximum:.3f} ms")
print(f"P95 latency       : {p95:.3f} ms")

print("\nE8 evaluation completed.")
print("=" * 70)