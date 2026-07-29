# Shieldgrid — Phase 0 Ticket Backlog

Target: `shieldgrid-core` runnable end-to-end with one connector (Wazuh, read-only), no auth, local dev only. Matches Phase 0 in the [system design doc](./soc-platform-system-design.md) and repo README.

Tickets are ordered — each assumes the previous ones are merged. Paste each as a separate GitHub issue in `shieldgrid-core`. Acceptance criteria are written so an agent (or you) can self-verify completion without asking you to judge subjectively.

---

### Ticket 1 — Scaffold the Rust/Axum project
**Description:** Initialize a Cargo project for the backend API. Set up the base folder structure separating routes, services, and data models, matching the connector-registry architecture in the design doc.

**Scope:**
- `cargo new shieldgrid-core --bin`
- Add dependencies: `axum`, `tokio`, `serde`, `serde_json`, `sqlx` (postgres feature), `dotenvy`
- Folder structure: `src/routes/`, `src/services/`, `src/models/`, `src/connectors/`
- `.gitignore` for Rust (target/, .env)

**Acceptance criteria:**
- `cargo build` succeeds with no warnings
- `cargo run` starts a server that logs "listening on 0.0.0.0:PORT" and exits cleanly on Ctrl+C

---

### Ticket 2 — Config loading from environment
**Description:** Load configuration (port, database URL, Wazuh/OpenSearch endpoint + credentials) from environment variables via `.env`, with a documented `.env.example`.

**Scope:**
- `src/config.rs` — a `Config` struct populated from env vars at startup
- Fail fast with a clear error message if required vars are missing
- `.env.example` committed with placeholder values and comments

**Acceptance criteria:**
- Running without a `.env` file produces a clear "missing required env var: X" error, not a panic with no context
- All config values are read in exactly one place (`config.rs`), not scattered across the codebase

---

### Ticket 3 — Define the Connector trait and NormalizedAlert schema
**Description:** Implement the core abstraction from the design doc — the `Connector` trait and `NormalizedAlert` struct that every future integration maps into.

**Scope:**
- `src/connectors/mod.rs` — the trait:
  ```rust
  #[async_trait]
  trait Connector {
      fn id(&self) -> &str;
      async fn health_check(&self) -> HealthStatus;
      async fn fetch_alerts(&self, since: DateTime<Utc>) -> Result<Vec<NormalizedAlert>>;
  }
  ```
- `src/models/alert.rs` — `NormalizedAlert` struct (id, connector_id, severity, source, timestamp, raw_payload, status)
- `HealthStatus` enum (Healthy, Degraded, Down) with a reason field

**Acceptance criteria:**
- Trait and structs compile with doc comments explaining each field's purpose
- No connector implementation yet — this ticket is the contract only

---

### Ticket 4 — Wazuh connector implementation
**Description:** Implement `Connector` for Wazuh by querying its underlying OpenSearch/Elasticsearch index directly (no separate ingestion pipeline per Phase 0 scope).

**Scope:**
- `src/connectors/wazuh.rs`
- HTTP client to OpenSearch's `_search` API, filtered by timestamp
- Map Wazuh's native alert JSON shape into `NormalizedAlert`
- `health_check()` pings the OpenSearch cluster health endpoint

**Acceptance criteria:**
- Given a real (or docker-compose'd test) Wazuh/OpenSearch instance, `fetch_alerts()` returns real alerts mapped into `NormalizedAlert`
- Unit test with a mocked OpenSearch response verifies field mapping is correct

---

### Ticket 5 — `/health` endpoint
**Description:** Expose an endpoint that reports the API's own status plus the health of every registered connector.

**Scope:**
- `GET /health` → `{ "status": "ok", "connectors": [{ "id": "wazuh", "status": "healthy" }] }`

**Acceptance criteria:**
- Returns 200 with connector statuses when Wazuh is reachable
- Returns 200 but reports `"status": "down"` for the connector (not a 500) when Wazuh is unreachable — the API itself should stay up even if a connector is down

---

### Ticket 6 — `/api/v1/alerts` endpoint
**Description:** Expose the first real data endpoint — alerts from all registered connectors, normalized and merged.

**Scope:**
- `GET /api/v1/alerts?since=<timestamp>` — calls `fetch_alerts()` on every registered connector, merges and sorts by timestamp
- Pagination not required yet (Phase 0 scope) — cap results at a sane default (e.g. 500) and note it's a known limitation

**Acceptance criteria:**
- Returns a JSON array of `NormalizedAlert` objects
- Works with zero connectors registered (returns empty array, not an error)

---

### Ticket 7 — Basic CI
**Description:** GitHub Actions workflow that builds, lints, and tests on every push, matching the pattern already used on Alkelang.

**Scope:**
- `.github/workflows/ci.yml` — `cargo build`, `cargo clippy -- -D warnings`, `cargo test`
- Runs on push to any branch (per your existing preference from Alkelang)

**Acceptance criteria:**
- A PR with a deliberately broken build fails CI visibly
- A clean PR passes all three steps

---

### Ticket 8 — Dockerfile
**Description:** Containerize `shieldgrid-core` for local dev via docker-compose and eventual K8s deployment.

**Scope:**
- Multi-stage Dockerfile (build stage with full Rust toolchain, slim runtime stage)
- `docker-compose.yml` at repo root wiring `shieldgrid-core` + a local Postgres for dev

**Acceptance criteria:**
- `docker compose up` gets the API responding on `/health` with no manual steps beyond `.env` setup

---

## Not in Phase 0 (explicitly deferred)

- Auth/RBAC → Phase 1
- Case management → Phase 1
- Second connector → Phase 2
- Response actions → Phase 3
- Frontend (`shieldgrid-web`) tickets are a separate backlog, start once Ticket 6 is merged so there's real data to display against

---

## Suggested agent master-prompt framing

When handing this to Antigravity (or similar), frame it the same way as your Explorers World Academy backlog: one ticket per agent task, in order, each referencing this file plus `shieldgrid-core/README.md` for context, and instruct the agent not to start ticket N+1 until N's acceptance criteria are verifiably met (build passes, tests pass) — not just "code written."