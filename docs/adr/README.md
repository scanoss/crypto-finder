# Architecture Decision Records

Architecture Decision Records (ADRs) for crypto-finder land in this directory, one file per decision (`NNNN-short-title.md`).

| ADR | Decision |
| --- | --- |
| [0001](0001-opt-in-structured-progress.md) | Structured progress is opt-in via `--progress`. |
| [0002](0002-call-chains-sample-size.md) | Live export and served stitch keep a default `call_chains` sample of 128. Live UIs opt in to 8 or 1. `crypto_entry_points` stays complete. |

The domain vocabulary lives in the root [CONTEXT.md](../../CONTEXT.md).
Architectural invariants and the package map live in [docs/ARCHITECTURE.md](../ARCHITECTURE.md).
Partner-facing schema history lives in [CHANGELOG.md](../../CHANGELOG.md) and [docs/OUTPUT_FORMATS.md](../OUTPUT_FORMATS.md).

Domain-modeling workflows create ADRs lazily when an architectural decision is resolved (see [docs/agents/domain.md](../agents/domain.md)).
