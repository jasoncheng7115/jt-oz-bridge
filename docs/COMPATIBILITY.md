# Compatibility status

[繁體中文](COMPATIBILITY_zh-tw.md)

**No OpenCode/Zulip/mobile combination is certified.** The application package version is not a compatibility certificate. The table lists what the code targets and what kind of evidence exists for each component.

| Component | Evidence | Status |
|---|---|---|
| Python 3.13 / macOS arm64 | Native dependency installation, local tests and type checks | Local development baseline. Not a Linux runtime certification. |
| Python 3.13 / Linux amd64 | Packaged import, dependency check, Zulip gateway/source/audience and native read RPC checks on a development host | Scoped runtime evidence; full Linux database/backend/phone certification pending. |
| SQLite WAL | Real local migrations, transactions, recovery and concurrency tests | Foundation storage tested; restore/retention certification pending. |
| PostgreSQL | Dependency and dialect code present | Not yet tested at runtime. |
| OpenCode V1 | Official server documentation reviewed; curated health fixture and mock transport tests | Read-only discovery implementation; no installed V1 backend qualified. |
| OpenCode V2 (developed against 2.0.32) | Public/source-tag fixtures plus an authenticated installed 2.0.32 OpenAPI and actual read RPCs | Installed schema/auth known for 2.0.32. The default CLI does not replay durable events; the live feed works. Original owner, full mutation/recovery and phone qualification pending. |
| Zulip 12.3 (feature level 500) | Dedicated ordinary Bot in a private channel; packaged Linux post/read/find/edit and scope/source checks | These scoped API checks pass; full consumer and phone integration pending. |
| Official iOS / Android | No real-device bridge evidence | Not yet verified. |

No auto-detection retries anonymous access after 401/403. URL/path/session title matching does not establish execution identity. Read-only probe success does not enable writes. Before enabling mutation, capture the actual installed contract hash, auth behavior, backend identity/owner, project scope and required permission/form/event behavior. Record test date, OS, versions, case IDs and sanitized evidence.

Official references reviewed for the foundation: [OpenCode server](https://opencode.ai/docs/server/), [Zulip queues](https://zulip.com/api/register-queue), [Zulip events](https://zulip.com/api/get-events), [FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/), [SQLAlchemy asyncio](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html). Documentation-derived fixtures remain distinct from installed-backend captures.

The public V2 OpenAPI and official v2.0.30 source-tag snapshot are hashed in `tests/fixtures/contracts/manifest.json`. Matching a source tag does not certify an installed server.

Installed captures have their own provenance manifest, separate from documentation-derived fixtures. Every installed backend is qualified against its own captured contract; another installation's captures do not carry over.
