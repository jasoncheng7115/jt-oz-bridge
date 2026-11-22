# Testing and evidence boundaries

[繁體中文](TESTING_zh-tw.md)

Use a Python 3.13 environment with [uv](https://docs.astral.sh/uv/):

```sh
uv sync --locked
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run mypy src
uv run pytest -q
uv run python -m scripts.public_gate .
uv build
uv run pip-audit --local --skip-editable
```

Unit tests cover strict example configuration, unsafe overrides, file-secret permissions, parameter catalogs and literal command boundaries. Integration tests use real temporary SQLite WAL databases and actual Alembic migrations. They exercise atomic receipts/checkpoints, concurrent deduplication, a failed-commit injection, CAS dispatch races, held/ambiguous recovery, outbox target revisions, consumer leases, scoped input/output authorization, locale persistence and admin authentication/CSRF/throttling/body limits.

Transport tests use HTTPX MockTransport and documentation-derived fixtures with provenance/hashes. They prove request/error handling in isolation, not actual OpenCode compatibility. V1/Zulip fixtures are curated examples; V2 fixtures are full official public/source-tag OpenAPI snapshots with recorded hashes. API UI tests use an ASGI client; real-browser/Playwright rendering and mobile workflow tests are not yet run.

A passing automated test is not acceptance of the feature it covers. What has been checked by real people, on real servers and on phones is stated in each guide and in the [compatibility matrix](COMPATIBILITY.md); everything else is unverified.

A finished release still requires installed-backend contracts, real original-session ownership, genuine permission/form interactions, disposable Git publishing tests, crash boundaries around real upstream acceptance, TLS failure behavior, retention/quota enforcement, SQLite restore, PostgreSQL runtime/migration, Linux architectures, performance workload and actual official iOS/Android evidence. None is replaced by the local passing count.

Run dependency auditing against the installed lock; an unavailable advisory service is a failure to verify, not a clean result.

Every feature addition, feature change and version change runs the complete suite above, not only the tests near the change; a result from an earlier commit does not count for a later one. Continuous integration runs the same lint, type, test and content-gate steps on every push, and a release tag also builds the wheel and its SBOM.

Some tests in the maintainers' copy read recordings of real OpenCode and Zulip servers. Those recordings hold real messages and identifiers, so they and the tests that read them are not published.
