"""Tests for the HTTP parameter prober (all requests mocked)."""

from unittest.mock import MagicMock, patch

import pytest

from dirge.payloads import NoSQLPayload, mongodb_payloads
from dirge.prober import probe_param


def _make_payload(payload: str = '{"$gt": ""}') -> NoSQLPayload:
    return NoSQLPayload(
        database="mongodb",
        technique="operator-injection",
        param_format="json",
        payload=payload,
        description="Test payload",
    )


def _mock_response(status: int, body: str) -> MagicMock:
    mock = MagicMock()
    mock.status = status
    mock.read.return_value = body.encode()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    return mock


@patch("dirge.prober.urllib.request.urlopen")
def test_probe_param_returns_list(mock_urlopen):
    mock_urlopen.return_value = _mock_response(401, '{"error": "auth failed"}')
    result = probe_param("http://example.com/login", "username", [_make_payload()])
    assert isinstance(result, list)


def test_probe_param_no_payloads_returns_empty():
    result = probe_param("http://example.com/login", "username", [])
    assert result == []


@patch("dirge.prober.urllib.request.urlopen")
def test_probe_param_post_method(mock_urlopen):
    mock_urlopen.return_value = _mock_response(200, '{"success": true}')
    probe_param("http://example.com/login", "username", [_make_payload()], method="POST")
    # Verify urlopen was called (POST is default for data-carrying requests)
    assert mock_urlopen.called


@patch("dirge.prober.urllib.request.urlopen")
def test_probe_param_get_method(mock_urlopen):
    mock_urlopen.return_value = _mock_response(200, '{"result": "ok"}')
    probe_param("http://example.com/search", "q", [_make_payload()], method="GET")
    assert mock_urlopen.called
    # GET request should have no data body
    call_args = mock_urlopen.call_args
    req = call_args[0][0]
    assert req.method == "GET"


@patch("dirge.prober.urllib.request.urlopen")
def test_probe_param_detected_on_auth_bypass(mock_urlopen):
    responses = [
        _mock_response(401, '{"error": "auth failed"}'),  # baseline
        _mock_response(200, '{"success": true, "user": "admin"}'),  # probe
    ]
    mock_urlopen.side_effect = responses
    result = probe_param("http://example.com/login", "username", [_make_payload()])
    assert len(result) == 1
    assert result[0]["detected"] is True


@patch("dirge.prober.urllib.request.urlopen")
def test_probe_param_response_code_matches_mock(mock_urlopen):
    responses = [
        _mock_response(401, '{"error": "auth failed"}'),  # baseline
        _mock_response(403, '{"error": "forbidden"}'),    # probe
    ]
    mock_urlopen.side_effect = responses
    result = probe_param("http://example.com/login", "username", [_make_payload()])
    assert result[0]["response_code"] == 403


@patch("dirge.prober.urllib.request.urlopen")
def test_probe_param_handles_connection_error(mock_urlopen):
    import urllib.error
    mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
    result = probe_param("http://localhost:9999/login", "username", [_make_payload()])
    # Should return a result entry with error handled gracefully
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["detected"] is False


@patch("dirge.prober.urllib.request.urlopen")
def test_probe_param_multiple_payloads(mock_urlopen):
    payloads = mongodb_payloads()[:3]
    # baseline + 3 probes = 4 calls
    mock_urlopen.return_value = _mock_response(401, '{"error": "auth failed"}')
    result = probe_param("http://example.com/login", "username", payloads)
    assert len(result) == 3
