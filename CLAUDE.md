# dirge

NoSQL injection payload generator and scanner for MongoDB, Couchbase, and Cassandra.

## Niche

Fills the gap between ossuary (SQL injection) and the rest of the injection-class tools. Targets applications backed by MongoDB, Couchbase, or unidentified NoSQL stores.

## Stack

- Python 3.11+
- click (CLI)
- Pure stdlib for HTTP (urllib) — no requests dependency
- pytest for tests
- uv for dependency management

## Architecture

```
src/dirge/
  payloads.py   — payload definitions (NoSQLPayload dataclass)
  scanner.py    — response comparison and injection detection
  prober.py     — HTTP probe loop (baseline + payloads per param)
  cli.py        — Click CLI: generate, scan subcommands
```

## v0.1 scope

- MongoDB operator injection ($gt, $ne, $gte, $lte, $lt, $or, $nor, $not, $regex, $where)
- MongoDB query-string format (bracket notation: username[$gt]=)
- Couchbase N1QL tautology payloads
- Generic NoSQL payloads (type confusion, $exists, $in)
- Response comparison detector: status code, error disclosure, success keywords, length delta
- CLI: `dirge generate` and `dirge scan`

## NOT in v0.1

- Cassandra CQL injection (placeholder in database list; not implemented)
- Authenticated scans (cookie/token injection)
- Automatic parameter discovery (requires a crawler)
- Burp Suite extension or proxy integration
- Output formats other than JSON (HTML, CSV)

## Post-v0.1 directions

1. Cassandra CQL injection payloads
2. Cookie and Authorization header injection
3. JSON body scanning (Content-Type: application/json detection)
4. Crawl-and-scan mode (discover parameters automatically)
5. Confidence calibration from real-world feedback
