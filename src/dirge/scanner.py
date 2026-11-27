"""NoSQL injection detection logic based on response comparison."""

ERROR_PATTERNS = [
    "MongoError",
    "MongoDB",
    "$where",
    "BSONTypeError",
    "Cannot use $",
    "mongo",
    "CouchbaseError",
    "N1QL",
    "cassandra",
    "Datastax",
    "BulkWriteError",
    "WriteError",
]

SUCCESS_PATTERNS = [
    "true",
    "admin",
    "success",
    "token",
    "jwt",
    "bearer",
    "logged in",
    "welcome",
    "dashboard",
]


def detect_nosql_injection_response(
    baseline_body: str,
    probe_body: str,
    baseline_code: int,
    probe_code: int,
) -> dict:
    """Detect if a NoSQL injection payload caused a change indicating injection.

    Returns {"detected": bool, "confidence": float, "indicators": list[str]}
    """
    indicators = []
    confidence = 0.0

    # Auth bypass: probe succeeded where baseline failed
    if probe_code == 200 and baseline_code not in (200, 201):
        indicators.append(f"Status changed from {baseline_code} to 200 (possible auth bypass)")
        confidence += 0.6

    # Error disclosure in probe response
    probe_lower = probe_body.lower()
    for pattern in ERROR_PATTERNS:
        if pattern.lower() in probe_lower and pattern.lower() not in baseline_body.lower():
            indicators.append(f"Error pattern '{pattern}' exposed in probe response")
            confidence += 0.3
            break

    # Success keywords appeared in probe but not baseline
    for pattern in SUCCESS_PATTERNS:
        if pattern in probe_lower and pattern not in baseline_body.lower():
            indicators.append(f"Success indicator '{pattern}' appeared in probe response")
            confidence += 0.2
            break

    # Significant response length difference
    length_diff = abs(len(probe_body) - len(baseline_body))
    if length_diff > 200:
        indicators.append(f"Response length changed by {length_diff} bytes")
        confidence += 0.2

    confidence = min(confidence, 1.0)
    detected = len(indicators) > 0 and confidence >= 0.2

    return {
        "detected": detected,
        "confidence": round(confidence, 2),
        "indicators": indicators,
    }
