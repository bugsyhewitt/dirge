"""Tests for NoSQL injection detection logic."""

import pytest

from dirge.scanner import ERROR_PATTERNS, detect_nosql_injection_response

BASELINE_ERROR = '{"error": "authentication failed"}'
PROBE_SUCCESS = '{"success": true, "user": {"name": "admin", "role": "admin"}}'


def test_detect_auth_bypass_code_change():
    result = detect_nosql_injection_response(BASELINE_ERROR, PROBE_SUCCESS, 401, 200)
    assert result["detected"] is True


def test_detect_no_injection_same_body():
    result = detect_nosql_injection_response(
        BASELINE_ERROR, BASELINE_ERROR, 200, 200
    )
    assert result["detected"] is False


def test_error_patterns_has_at_least_5():
    assert len(ERROR_PATTERNS) >= 5


def test_error_patterns_contains_mongoerror():
    assert "MongoError" in ERROR_PATTERNS


def test_confidence_in_range():
    result = detect_nosql_injection_response(BASELINE_ERROR, PROBE_SUCCESS, 401, 200)
    assert 0.0 <= result["confidence"] <= 1.0


def test_indicators_non_empty_when_detected():
    result = detect_nosql_injection_response(BASELINE_ERROR, PROBE_SUCCESS, 401, 200)
    assert result["detected"] is True
    assert len(result["indicators"]) > 0


def test_detect_error_disclosure_in_probe():
    probe_body = '{"error": "MongoError: invalid query operator"}'
    result = detect_nosql_injection_response(BASELINE_ERROR, probe_body, 400, 400)
    assert result["detected"] is True


def test_no_detection_same_code_and_length():
    body = '{"error": "auth failed"}'
    result = detect_nosql_injection_response(body, body, 401, 401)
    assert result["detected"] is False


def test_detect_large_response_length_difference():
    large_body = '{"data": "' + "x" * 500 + '"}'
    result = detect_nosql_injection_response(BASELINE_ERROR, large_body, 200, 200)
    assert result["detected"] is True


def test_detect_returns_dict_with_required_keys():
    result = detect_nosql_injection_response(BASELINE_ERROR, PROBE_SUCCESS, 401, 200)
    assert "detected" in result
    assert "confidence" in result
    assert "indicators" in result


def test_detect_confidence_zero_when_no_indicators():
    body = '{"error": "not found"}'
    result = detect_nosql_injection_response(body, body, 404, 404)
    assert result["confidence"] == 0.0
