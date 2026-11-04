# Review guide

Instructions for automated code review (`.github/workflows/pr-review.yml` hands Claude this file as the base branch has it) and for any agent asked to review a diff. Human reviewers can use it too.

Report what makes crypto-finder miss a crypto finding, report one it should not, give a consumer output it cannot read, or stall on a real project. `make lint`, the tests, the graph-algorithm guard and `PR hygiene` already cover formatting, complexity, the feature map and the `## Evidence` section; do not repeat them. The rules below come from [AGENTS.md](AGENTS.md), [CODE_REVIEW_GUIDELINES.md](CODE_REVIEW_GUIDELINES.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); follow the links for the detail.

## Always flag

- **Reachability precision.** A change that makes reachability depend on `metadata.api` again (selection or classification), instead of the matched source text (`inferMatchedOperationKind`) and the call's position (`findCryptoCallNode`). A rule or code path that brings back the `supporting-call` assetType or a `supportingCall` sentinel: supporting calls are derived from the call graph (`internal/scan/supporting_calls.go`). A parser that sets `StartCol`/`EndCol` in a convention other than 1-based, end-exclusive, or drops `ReceiverVar`, `AssignedVar` or `ChainID` it used to set. Name the finding that gains or loses a route. AGENTS.md, "Detection vs reachability".
- **Output contracts.** A changed field, value or meaning in the interim report, the callgraph export or the graph fragment without the matching version bump (`schema.InterimFormatVersion`, `graphfrag.CallgraphInternedSchemaVersion` / `CallgraphSchemaVersion`, `graphfrag.SchemaVersion`), the published schema under `schemas/`, and the note in `docs/OUTPUT_FORMATS.md`. A callgraph construction change without a `graphfrag.GraphAlgoVersion` bump, or a `-update -force` of the guard's golden the PR does not explain. docs/ARCHITECTURE.md, "Schema Versioning".
- **Failure codes.** A renamed or reused `failure.Code` that has shipped, or a deep package (`internal/callgraph`, `internal/scan`, `internal/converter`, parsers) that imports `internal/failure`. AGENTS.md, "Error handling".
- **Changelog and user guide.** A user-facing change (flag, behaviour, schema bump, fix, performance, removal) with no fragment under `changelog.d/`, a direct edit of `CHANGELOG.md` for it, or a fragment written for reviewers instead of consumers. A change to commands, flags, outputs or supported workflows that leaves `docs/user-guide/user-guide.html` behind, or edits its coverage paragraphs instead of adding a `docs/user-guide/coverage.d/` fragment. Internal-only changes need neither.
- **Knowledge-base YAML** (`internal/callgraph/contracts/`). A file that covers more than one library version, a `library.name` already used, `parameter_types` or `canonical_return_type` given while same-arity overloads remain ambiguous, a `trait_associated_types` entry that invents a type, a Go method name not in `FunctionID.String()` form, or a contract whose return type is not what the library's documented API returns. The loader already rejects schema `"1"`, arity mismatches and conflicting merges; do not repeat it. AGENTS.md, "Knowledge base layout".
- **Determinism of exports.** Output order, IDs (`finding_id`, `occurrence_key`, ambiguous-call group IDs) or hashes that depend on map iteration, goroutine completion order or the scan's wall clock, so two runs of the same input disagree.
- **Performance on large dependency graphs.** Parallel work that ignores the `maxWorkers` cap or spawns a goroutine per item, a traversal with no bound where a large graph can make it exponential (the export reports `traversal_truncated` for this), an expensive step (dependency resolution, bytecode analysis, rule fetching) that skips the cache, or a quadratic pass over every function or edge. CODE_REVIEW_GUIDELINES.md, "Concurrency Patterns" and "Performance".
- **Layering and stdout.** `entities/` importing an internal package, business logic in a Cobra command, a new singleton, or a log line written to stdout, which breaks piping the JSON or CycloneDX output.
- **Secrets and commands.** An API key reaching a log, an error string or an export; an external process run without `exec.CommandContext`; a command argument or path built from untrusted input without validation (gosec G204 and G304 are excluded from lint, so review them).
- **The merge gate.** Anything in `scripts/mergeready`, `.claude/settings.json` or a workflow that lets a pull request merge without green checks, Claude's review, a merge-risk assessment, or a person's say-so on a medium or high one.

## Do not flag

- Style, wording, naming or comment density, unless the name is wrong about what the code does.
- Recorded fixtures and goldens under `testdata/`, `docs/research/`, `openspec/`, and `go.sum`.
- The prose of a changelog fragment, when it names what changed for a consumer.
- A missing test, when the PR's Evidence shows the behaviour proven another way.

## Severity

Mark a finding as important only when you can name the input or state that breaks and what the user then sees: a finding lost or invented, a consumer that rejects the output, a scan that stalls. Without that, it is a question: ask it as one.
