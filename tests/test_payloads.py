"""Tests for NoSQL payload generation."""

import pytest

from dirge.payloads import (
    NoSQLPayload,
    couchbase_payloads,
    generic_nosql_payloads,
    mongodb_payloads,
)


def test_mongodb_payloads_returns_at_least_10():
    assert len(mongodb_payloads()) >= 10


def test_mongodb_payloads_contains_gt():
    payloads = [p.payload for p in mongodb_payloads()]
    assert any("$gt" in p for p in payloads)


def test_mongodb_payloads_contains_ne():
    payloads = [p.payload for p in mongodb_payloads()]
    assert any("$ne" in p for p in payloads)


def test_mongodb_payloads_contains_regex():
    payloads = [p.payload for p in mongodb_payloads()]
    assert any("$regex" in p for p in payloads)


def test_mongodb_payloads_contains_where():
    payloads = [p.payload for p in mongodb_payloads()]
    assert any("$where" in p for p in payloads)


def test_mongodb_query_string_format_contains_bracket_operator():
    qs_payloads = [p for p in mongodb_payloads() if p.param_format == "query-string"]
    assert any("[$gt]" in p.payload or "[$ne]" in p.payload for p in qs_payloads)


def test_couchbase_payloads_non_empty():
    assert len(couchbase_payloads()) > 0


def test_couchbase_payload_contains_or():
    payloads = [p.payload for p in couchbase_payloads()]
    assert any("OR" in p for p in payloads)


def test_generic_nosql_payloads_returns_at_least_5():
    assert len(generic_nosql_payloads()) >= 5


def test_all_payloads_have_non_empty_description():
    all_payloads = mongodb_payloads() + couchbase_payloads() + generic_nosql_payloads()
    for p in all_payloads:
        assert p.description, f"Empty description on payload: {p.payload}"


def test_mongodb_payloads_are_nosqlpayload_instances():
    for p in mongodb_payloads():
        assert isinstance(p, NoSQLPayload)


def test_mongodb_payloads_database_field():
    for p in mongodb_payloads():
        assert p.database == "mongodb"


def test_couchbase_payloads_database_field():
    for p in couchbase_payloads():
        assert p.database == "couchbase"


def test_generic_payloads_database_field():
    for p in generic_nosql_payloads():
        assert p.database == "generic"
