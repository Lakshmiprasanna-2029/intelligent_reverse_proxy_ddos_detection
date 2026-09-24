# ============================================================
# RATE LIMITER
# ============================================================

RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW = 60
TEMP_BLOCK_SECONDS = 60

rate_limit_store = {}
blocked_ips = {}


def check_rate_limit(client_ip):
    """
    Simple sliding-window rate limiter.

    Returns:
        blocked       -> temporarily blocked IP
        rate_limited  -> request exceeded rate limit
        remaining     -> requests remaining
        count         -> requests in current window
    """

    now = time.time()

    # --------------------------------------------------------
    # Temporary block check
    # --------------------------------------------------------

    if client_ip in blocked_ips:

        block_until = blocked_ips[client_ip]

        if now < block_until:
            return {
                "blocked": True,
                "rate_limited": False,
                "remaining": 0,
                "count": RATE_LIMIT_REQUESTS,
                "limit": RATE_LIMIT_REQUESTS,
                "window_seconds": RATE_LIMIT_WINDOW,
            }

        del blocked_ips[client_ip]

    # --------------------------------------------------------
    # Get request timestamps
    # --------------------------------------------------------

    timestamps = rate_limit_store.get(
        client_ip,
        []
    )

    # Keep only requests inside current window
    timestamps = [
        timestamp
        for timestamp in timestamps
        if now - timestamp < RATE_LIMIT_WINDOW
    ]

    # Add current request
    timestamps.append(now)

    rate_limit_store[client_ip] = timestamps

    count = len(timestamps)

    remaining = max(
        0,
        RATE_LIMIT_REQUESTS - count
    )

    # --------------------------------------------------------
    # Rate limit decision
    # --------------------------------------------------------

    if count > RATE_LIMIT_REQUESTS:

        return {
            "blocked": False,
            "rate_limited": True,
            "remaining": 0,
            "count": count,
            "limit": RATE_LIMIT_REQUESTS,
            "window_seconds": RATE_LIMIT_WINDOW,
        }

    return {
        "blocked": False,
        "rate_limited": False,
        "remaining": remaining,
        "count": count,
        "limit": RATE_LIMIT_REQUESTS,
        "window_seconds": RATE_LIMIT_WINDOW,
    }