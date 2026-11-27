# dirge

NoSQL injection payload generator and scanner for MongoDB, Couchbase, and generic NoSQL backends.

## Install

```bash
pip install dirge
# or from source:
pip install -e .
```

## Usage

### Generate payloads

```bash
# All payloads for all databases
dirge generate

# MongoDB JSON payloads only
dirge generate --database mongodb --format json

# Couchbase query-string payloads
dirge generate --database couchbase --format query-string
```

### Scan a target

```bash
# Test username and password parameters on a login endpoint
dirge scan --url http://api.example.com/login --param username,password

# GET method, MongoDB payloads only
dirge scan --url http://api.example.com/search --param q --method GET --database mongodb
```

Output is JSON. Exit code 1 if injection detected, 0 if clean.

## What it tests

| Database | Technique | Example |
|---|---|---|
| MongoDB | Operator injection | `{"$gt": ""}`, `{"$ne": "invalid"}` |
| MongoDB | Regex injection | `{"$regex": "^admin"}` |
| MongoDB | JavaScript injection | `{"$where": "1 == 1"}` |
| MongoDB | Query-string operators | `username[$gt]=` |
| Couchbase | N1QL injection | `' OR '1'='1` |
| Generic | Type confusion | `true`, `{}`, `null` |

## Detection

dirge compares a baseline response (empty parameter value) against each probe response. It flags injection when:

- Status code changes from non-200 to 200 (authentication bypass)
- Error messages expose database internals (MongoError, BSONTypeError, N1QL, etc.)
- Success keywords appear in the probe response but not the baseline
- Response size changes by more than 200 bytes

## License

MIT
