"""HTTP parameter prober — sends NoSQL payloads and collects responses."""

import json
import urllib.error
import urllib.parse
import urllib.request

from dirge.payloads import NoSQLPayload
from dirge.scanner import detect_nosql_injection_response


def _send_request(
    url: str,
    param_name: str,
    value: str,
    method: str,
) -> tuple[int, str]:
    """Send a single HTTP request and return (status_code, body)."""
    if method.upper() == "GET":
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param_name] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        full_url = parsed._replace(query=new_query).geturl()
        req = urllib.request.Request(full_url, method="GET")
    else:
        body = urllib.parse.urlencode({param_name: value}).encode()
        req = urllib.request.Request(url, data=body, method=method.upper())
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, body


def probe_param(
    url: str,
    param_name: str,
    payloads: list[NoSQLPayload],
    method: str = "POST",
) -> list[dict]:
    """Send NoSQL injection payloads to a URL parameter.

    Returns list of {payload, response_code, detected, indicators, confidence}.
    """
    if not payloads:
        return []

    # Establish baseline with an empty value
    try:
        baseline_code, baseline_body = _send_request(url, param_name, "", method)
    except (urllib.error.URLError, OSError):
        baseline_code, baseline_body = 0, ""

    results = []
    for p in payloads:
        try:
            code, body = _send_request(url, param_name, p.payload, method)
        except (urllib.error.URLError, OSError) as exc:
            results.append({
                "payload": p,
                "response_code": 0,
                "detected": False,
                "confidence": 0.0,
                "indicators": [f"Connection error: {exc}"],
                "error": str(exc),
            })
            continue

        detection = detect_nosql_injection_response(
            baseline_body, body, baseline_code, code
        )
        results.append({
            "payload": p,
            "response_code": code,
            "detected": detection["detected"],
            "confidence": detection["confidence"],
            "indicators": detection["indicators"],
        })

    return results
