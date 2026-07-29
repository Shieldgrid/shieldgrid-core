# Shieldgrid Core

The core platform for **Shieldgrid** — a single-pane-of-glass SOC operations platform. This repo owns identity, authorization, case management, and the connector registry that unifies alerts from external security tools (Wazuh first, more later) into one normalized data model.

> Shieldgrid is an independent project inspired by the architectural ideas behind open-source SOC tooling (e.g. socfortress/CoPilot). No code is shared or ported from that project — this is a clean-room implementation.

## Status

🚧 Phase 0 — foundation. Single connector (Wazuh, read-only), no auth yet, local dev only.

## Stack

- **Language:** Rust
- **Web framework:** Axum
- **Database:** PostgreSQL (app state — users, cases, connector configs)
- **Alert source:** queries OpenSearch/Elasticsearch directly (Wazuh's existing index) — no duplicate ingestion pipeline in Phase 0

## Architecture

See [shieldgrid-docs](https://github.com/Shieldgrid/shieldgrid-docs) for the full system design document. Short version:

```
Frontend (shieldgrid-web)
        │ REST/JSON
        ▼
   API Layer (this repo)
   - Auth / RBAC
   - Case management
   - Connector registry
        │
        ▼
  Connector trait (Wazuh, ...)
```

Every connector implements a common interface:

```rust
trait Connector {
    fn id(&self) -> &str;
    async fn health_check(&self) -> HealthStatus;
    async fn fetch_alerts(&self, since: DateTime) -> Vec<NormalizedAlert>;
    async fn push_action(&self, action: ResponseAction) -> ActionResult;
}
```

Adding a new tool means writing one new implementation of this trait — the core API, DB schema, and frontend never need tool-specific logic.

## Getting Started

```bash
# clone
git clone https://github.com/Shieldgrid/shieldgrid-core.git
cd shieldgrid-core

# copy env template and fill in your Wazuh/OpenSearch endpoint + credentials
cp .env.example .env

# run
cargo run
```

Requires Rust (stable toolchain) and a running PostgreSQL instance. See `.env.example` for required variables.

## Roadmap

| Phase | Scope |
|---|---|
| 0 | Wazuh connector (read-only), basic dashboard, no auth |
| 1 | Case management, RBAC, real auth |
| 2 | Second connector — proves the abstraction holds |
| 3 | Response actions (e.g. block IP) |
| 4 | MCP agent layer ([shieldgrid-mcp](https://github.com/Shieldgrid/shieldgrid-mcp)) |

## License

[AGPL-3.0](LICENSE) — free to use, modify, and self-host. If you run a modified version as a network service, the source of your modifications must also be made available under AGPL-3.0.

## Contributing

Issues and PRs welcome. Please open an issue before large changes so we can align on approach first.

### Local CI & Git Hooks

To save GitHub Actions resources and catch failures early, we mirror CI checks locally.
You can run all CI checks (formatting, build, linting, tests) manually via:
```bash
./scripts/ci-local.sh
```

**Recommended:** Wire this script to run automatically before every `git push` by installing the pre-push hook (run once per clone):
```bash
./scripts/install-hooks.sh
```

If you ever genuinely need to bypass the hook (e.g. saving WIP work to a remote branch), use `git push --no-verify`.
