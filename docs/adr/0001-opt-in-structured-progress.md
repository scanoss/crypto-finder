# Make structured progress output opt-in

## Decision

Issue #237 needs machine-readable scan lifecycle events without changing existing CLI output for current consumers. Structured progress is explicitly enabled by `--progress` and remains disabled by default. When enabled, progress events are newline-delimited JSON on stderr, human-readable logs are suppressed, and stdout/`--output` remain dedicated to findings. `--error-format=json` remains allowed and is redundant; `--error-format=text` is rejected as incompatible with progress mode during preflight.

Each event uses this versioned envelope:

```json
{
  "event": "scan_progress",
  "schema_version": "1",
  "phase": "detection",
  "status": "started",
  "parent_phase": "scan"
}
```

`status` is one of `started`, `completed`, `failed`, `canceled`, or `skipped`. `parent_phase`, `details`, and `duration_ms` are optional. `duration_ms` is an integer elapsed wall-clock duration and appears only on terminal statuses (`completed`, `failed`, or `canceled`). Events are written as complete JSONL records immediately at each transition, without buffering or reordering.

The v1 envelope is published as a JSON Schema and validated in tests. Additive optional fields remain within v1; breaking changes require a schema-version bump. V1 reports lifecycle transitions, measured durations, dependency aggregate counts, and stable skip reasons only. It does not report percentages, estimates, per-file progress, or worker-level progress.

Progress begins only after CLI preflight validation succeeds, so invalid input produces the existing structured error without a misleading scan event. Phase names and ordering follow the actual scan pipeline rather than inventing a fixed sequence:

- `scan` is the overall lifecycle phase.
- `rules` covers rule loading, filtering, and validation.
- `detection` covers language detection, scanner setup/execution, and result processing.
- `dependencies` is optional. Dependency callgraph work is nested with `parent_phase: "dependencies"`.
- `export` is optional. Export-only callgraph work is nested with `parent_phase: "export"`.
- `callgraph` is reported only when callgraph work actually runs.

Optional `dependencies` and `export` phases emit `skipped` with `details.reason: "not_requested"` when their work is not requested. A requested dependency phase that cannot run emits `skipped` with one of `ecosystem_unknown`, `resolver_unavailable`, `parser_unavailable`, or `callgraph_unavailable`, preserving the current warn-and-continue behavior. A requested phase that resolves no dependencies completes with zero-valued counts. Child phases close before their parents, and concurrent dependency workers are represented only by aggregate dependency counts.

For a completed aggregate dependency phase, `details` contains only these non-negative integer fields: `deps_scanned`, `deps_skipped`, `deps_failed`, `deps_with_findings`, and `total_dep_findings`. For skipped phases, `details` contains the stable `reason` field. No free-form human `message` field is part of v1.

On failure or cancellation, child terminal events are followed by parent terminal events from the inside out, then the existing final structured failure payload. Cancellation uses `status: "canceled"` and the existing `scanner_canceled` code.

## Consequences

- Existing scripts and integrations keep their current output unless they opt in.
- The progress contract must define behavior only for scans that explicitly enable it.
- Consumers can read progress without competing with findings written to stdout or `--output`.
- Progress mode is mutually exclusive with human-readable logs, preventing mixed text and JSON on stderr.
- Machine mode keeps terminal failure details in the existing failure schema instead of inventing a second error contract.
- Cancellation remains distinguishable from failure through the existing `scanner_canceled` code and a matching `canceled` progress status.
- The first event contract can evolve by schema version instead of silently changing fields.
- Aggregate dependency progress avoids coupling the public stream to the number or ordering of dependency workers.
- A `skipped` event distinguishes a phase that was not requested or unavailable from a missing progress record.
- Changing the default later would be a compatibility change, not a harmless implementation detail.
