# AGENTS.md — crypto-finder

Project-specific conventions for AI agents and human contributors working in this repo.
Read this file before making non-trivial changes. It documents conventions that are
load-bearing but not enforceable by lint or compiler alone.

Human-readable counterparts: the architecture, pipeline, and package map live in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the published failure code/stage
taxonomy lives in [docs/ERROR_CODES.md](docs/ERROR_CODES.md); graph ids and their
guard in [docs/GRAPH_IDS.md](docs/GRAPH_IDS.md).

## Quick path: the hard requirements

| Requirement | Check before pushing |
|---|---|
| No ruleset content in this repository | `git diff` holds no rules, cards, conditions, fixtures or data derived from the private ruleset ([below](#ruleset-content-hard-requirement)) |
| No internal names or home paths in code, PR titles, bodies or commits | `go run ./scripts/featuremap check-pr ...` ([below](#leak-guard)) |
| Changelog fragment for every user-facing change | A new `changelog.d/<slug>.<section>.md` ([below](#changelog-hard-requirement)) |
| User guide follows user-facing changes | `docs/user-guide/user-guide.html` updated in the same PR |
| Errors: plain `%w` in deep code, `failure.Wrap` at the boundary | [Error handling](#error-handling) |
| Engine changes go to reach, never back here | `go test ./internal/boundary` |
| Graph changes bump the ecosystem's graph algorithm id | `go test ./internal/graphalgoguard/` ([docs/GRAPH_IDS.md](docs/GRAPH_IDS.md)) |
| Merge only through the gate | `go run ./scripts/mergeready check --pr <n>` ([below](#pull-requests-and-merging)) |

## Ruleset content (HARD REQUIREMENT)

The detection ruleset is private to SCANOSS. This repository is public (or
will be), and so is its history. Never add its rules, rule ids, cards,
parameter conditions, rule YAML excerpts, rule test fixtures or any data
derived from them, in code, tests, testdata or docs. Naming that the private
ruleset exists and how the CLI loads it (`--rules-dir`, `--cards-index`,
`--cards-dir`, leased bundles) is fine. Tests that need rules build small,
invented ones inline.

## Leak guard

PR titles, bodies, comments and commit messages are public too. Never write
internal names in them or in the code: private repositories, internal
services, hosts, internal projects or benchmarks, or a person's home path
(`/home/<user>/`, `/Users/<user>/`).

`go run ./scripts/featuremap check-pr` (run by the `PR hygiene` workflow on
every PR) also runs the leak guard (`scripts/internal/leakguard`) over the PR
title, body and commit messages, the lines the diff adds and the YAML files it
adds or changes. It fails on:

- a denied internal name, matched whatever the case or separator (`foo-bar`,
  `foo_bar`, `foo.bar`, `foo/bar`, `foo bar`, `FooBar`, also inside a longer
  CamelCase identifier such as `newFooBarClient`), or only in its exact spelling for a name
  whose words also occur legitimately in public text;
- an absolute home path, except the synthetic users tests and docs use and
  the stock users of common images (`/home/u/`, `/home/crypto/`,
  `/home/nonroot/`, ...; `syntheticUsers` in the package);
- an added or changed YAML file shaped like a detection ruleset (`rules:`
  entries whose `metadata.crypto` holds CycloneDX fields), in `testdata/` too.
  A file of invented rules (a test fixture) carries the comment
  `# leakguard: invented-rules`, which its author adds and its reviewer
  checks.

The title and body of a PR Dependabot opened (they quote upstream release
notes) are not scanned; its diff and commits are. Other apps, agents among
them, are scanned like people. Findings name the place and
the category, never the matched text. The denylist,
`scripts/internal/leakguard/denylist.txt`, holds only SHA-256 hashes, so it
does not reveal the names. To add a name, type it on stdin so it is never
written down:

```bash
go run ./scripts/leakguard hash --category host -        # or --exact for exact spelling only
# append the printed line to scripts/internal/leakguard/denylist.txt, then
go run ./scripts/leakguard scan-tree                     # must stay clean
```

`scan-tree --rulesets` also lists ruleset-shaped files without the marker. A
name `scan-tree` finds in today's tree must be scoped with `--exact` or left
out. Never name a denied name in the PR that adds its hash.

## Changelog (HARD REQUIREMENT)

Every user-facing change — new flag, behavior change, schema bump, bug fix, performance
work, removal — MUST land with a matching changelog **fragment**, in the same PR as the
change. Do not edit `CHANGELOG.md` for it: add one file under `changelog.d/` named
`<slug>.<section>.md` (`section` is `added`, `changed`, `deprecated`, `removed`, `fixed`
or `security`) holding one or more `- ` bullets. See [changelog.d/README.md](changelog.d/README.md).
The final format is still [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Fragments exist so that two PRs never conflict on the same lines of `CHANGELOG.md`.

- Write entries for consumers of the tool, not for reviewers: name the flag, the schema
  version, the exported package, the observable behavior — not the internal refactor.
- Internal-only changes (test refactors, CI tweaks, comment fixes) do not need an entry.
- When cutting a release, run `go run ./scripts/relprep changelog -version X.Y.Z` and
  `go run ./scripts/relprep guide` in a release-prep PR before tagging. They fold the
  fragments into a new `## [X.Y.Z]` section of `CHANGELOG.md` and into the user guide, and
  delete them. Entries already under `[Unreleased]` are released with the fragments. Do
  not let releases ship with the changelog behind — reconstructing history from merged
  PRs afterwards is expensive and error-prone.

## User guide

Relevant user-facing capability or behavior changes - commands, flags, outputs, supported workflows, deployment behavior, dependency scanning, or limitations - MUST update the sole-source HTML guide `docs/user-guide/user-guide.html` in the same PR. The guide is standalone, inline-CSS/vanilla-JS, and HTML-first. Do not restore DOCX/PDF deliverables, Node build sources, generated review images, package files, or vendored document engines. Keep only necessary public logo assets under `docs/user-guide/assets/`.

Do not edit the contract-coverage paragraphs of the guide directly. A PR that adds or extends
coverage adds one `<p>` fragment under `docs/user-guide/coverage.d/` (see its README), so two
PRs never conflict on the same lines. Release prep appends the fragments to the guide.

Verify the guide with an HTML parser, prohibited-term grep, `git diff --check`, and a lightweight local HTTP server/browser check as documented in `docs/user-guide/AGENTS.md`.

## Error handling

This project uses a **two-layer error model**. Mixing the layers is a defect.

### 1. Deep library code

Packages: `reach/callgraph`, `internal/scan`, `internal/converter`, `internal/cache`,
`internal/rules`, `internal/output`, parsers, loaders, helpers — anything that does not
make terminal/policy decisions.

- Return errors via `fmt.Errorf("<package-prefix>: ...: %w", err)`.
- Use `%w` so callers can `errors.Is` / `errors.As` through the chain.
- Use a stable package prefix (`contracts:`, `callgraph:`, `scan:`, ...) so error
  origins are greppable.
- **Do NOT** import `internal/failure` from these packages. Deep code stays portable
  and testable without coupling to the failure taxonomy.

### 2. Boundary code

Packages: `internal/cli`, `internal/engine`, `internal/scanner`, `internal/dependency` —
anywhere errors become terminal (CLI exit code, JSON failure payload, retry decisions).

- Wrap incoming deep-layer errors with `failure.Wrap` or `failure.WrapUnknown`.
- Assign the appropriate `failure.Code` and `failure.Stage` at the wrap site.
- Already-typed `*failure.Error` values pass through untouched (`WrapUnknown`
  preserves them; only plain errors get wrapped).

### Adding a new failure mode

When a new terminal failure mode is introduced:

1. Add a new `Code` constant in `pkg/failure/error.go` and re-export it through `internal/failure` for existing implementation imports.
2. Add a corresponding `Stage` if the failure belongs to a new pipeline stage.
3. **Never rename a `Code` that has shipped** — codes are stable identifiers consumed
   by external tooling and CI parsers.

### Why this layering

Deep code stays composable, unit-testable, and reusable across pipelines. The boundary
is the only place where errors become policy. Inverting this rule — sprinkling `failure`
calls deep in parsers — leaks the CLI's policy concerns into library code and makes
those packages harder to repurpose.

## Engine boundary (HARD REQUIREMENT)

The engine (call graph, contracts loader, graph fragments, stitcher, entry points and their
support packages) lives in its own module, [`github.com/scanoss/reach`](https://github.com/scanoss/reach)
(MIT), which imports nothing from crypto-finder. Engine changes go to reach, never back into
crypto-finder: `go test ./internal/boundary` fails when a package reappears at a path the engine
moved from (`internal/boundary.MovedEnginePackages`). Crypto knowledge (KB YAML, crypto tables)
goes in `internal/cryptokb` and is injected (`contracts.SetSource` / `contracts.SetHints`),
never hard-coded in the engine; client concerns (config, paths) are passed in by the caller.
`go.mod` requires a tagged reach version. For engine work, develop in a reach
checkout, add a temporary `replace github.com/scanoss/reach => ../reach`, and drop it before
merging: crypto-finder only ships against a tagged reach.
`make test-reach` runs reach's tests against the crypto KB (`REACH_TEST_CONTRACTS`).
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#engine-boundary).

## Knowledge base layout (callgraph inferred-types)

The callgraph inference engine consumes language-agnostic YAML knowledge bases. The
engine embeds none: the loader, types and validation live in reach's `callgraph/contracts`
package (`github.com/scanoss/reach/callgraph/contracts`), and crypto-finder's crypto KB lives in `internal/cryptokb/` (domain), which
installs itself as the contracts source (`contracts.SetSource`) when imported. The
structure is:

```
github.com/scanoss/reach/callgraph/contracts/
└── contracts.go           # loader, types, validation (engine; no YAML)
internal/cryptokb/
├── cryptokb.go            # go:embed of the YAML below, installs it as the source
├── c/                     # one YAML per library version, e.g. openssl-evp, libsodium, mbedtls
├── cpp/                   # cryptopp, botan, tink, ...
├── go/                    # stdlib-crypto, golang-x-crypto, ...
├── java/                  # jdk-crypto, bouncycastle, tink, jjwt, nimbus-jose-jwt, ...
├── node/                  # node crypto, argon2, aws-sdk clients, ...
├── python/                # pyca-cryptography, pycryptodome, pyjwt, ...
└── rust/                  # RustCrypto crates, ring, openssl, ...
```

**One YAML file = one library version**. Adding a new library is a new YAML, not a code
change. A new ecosystem may temporarily use one empty `<ecosystem>-bootstrap` YAML because
`go:embed` requires a matching file; remove it when the first library KB lands. The loader (`contracts.ForEcosystem(ecosystem)` over the installed source; `contracts.LoadFS(fsys, ecosystem)` for any fs.FS) discovers all `*.yaml` files in
the ecosystem directory, validates each, and merges them via `contracts.Merge()` with
conflict-detection rules:

| Situation | Outcome |
|---|---|
| Same method+arity+condition, identical return | Idempotent (no error) |
| Same method+arity+condition, different return | HARD ERROR naming both libraries |
| Hierarchy `child → [A]` in both libraries | Idempotent |
| Hierarchy `child → [A]` vs `[B]` (no subset) | HARD ERROR naming both libraries |
| Hierarchy `child → [A]` vs `[A, B]` | Union (subset accepted) |

Each YAML carries a `library:` block with `name`, optional `coordinates`, optional
`version_range`, and optional `description`. The `library.name` propagates onto every
contract's `SourceLibrary` field for diagnostic identification across libraries.

Contracts may declare `parameter_types` and `canonical_return_type` when method plus
arity (and any resolved condition) identifies one unambiguous declared signature.
The parameter list length must equal `arity`. Omit canonical fields when multiple
same-arity overloads remain possible; call-site source provenance then selects the
concrete signature instead of the KB guessing one overload. Keep these fields distinct
from semantic `return.type`, which may intentionally model only one inferred value.

A YAML may also declare `trait_associated_types`, a flat list of `{trait, name,
type}` entries (`type` optional). This resolves a generic parameter's associated
type past its trait bound: a `C: KeyInit` bound already gives `C` the `KeyInit`
identity (first-trait-bound rule), and a `trait_associated_types` entry for
`{trait: KeyInit, name: KeySize}` lets `C::KeySize` resolve to what the entry
names, instead of stopping at the bare trait name. An entry with no `type` still
counts as cataloged (the trait is known to declare that associated type) but
resolves to nothing usable, which callers must treat the same as an uncataloged
pair — never invent a value. Merge applies the same rule 1/2 discipline as
contracts: identical entries across libraries are idempotent; the same
`(trait, name)` with a different `type` is a HARD ERROR naming both libraries.

A contract may declare `material_roles`, a list of `{index, name, material}`
entries naming which argument is related crypto material: the iv of
`new IvParameterSpec(iv)`, the salt of `PBKDF2HMAC(salt=...)`, the nonce of
`AEAD.Seal(dst, nonce, ...)`. `material` must be a CycloneDX 1.7
relatedCryptoMaterial type (`salt`, `nonce`, `initialization-vector`, `seed`,
`key`, `secret-key`, ...; never `other` or `unknown`). `index` (0-based, below
`arity`) matches a positional argument and `name` a keyword argument; give both
for a Python parameter callers pass either way. The scan follows a random draw
into such an argument across application functions and reports the drawn value
as that material (see "Detection vs reachability"). The field is additive, so
the schema stays `"2"`. Merge applies the rule 1/2 discipline: the same roles
are idempotent, different roles for the same method+arity+condition are a HARD
ERROR naming both libraries.

Schema version is `"2"` — schema `"1"` is hard-rejected. The YAML schema version is
INTERNAL to the loader; the partner-facing export schemas are independent of it
(callgraph `6.18` for default CLI exports and `6.14` for zero-value SDK/stitch,
graph fragment `graph-fragment-1.39`; the constants in `reach/graphfrag` and
[docs/GRAPH_IDS.md](docs/GRAPH_IDS.md) are the source of truth).

To add a library:
1. Drop a new YAML at `internal/cryptokb/<ecosystem>/<library>.yaml`.
2. Set `schema_version: "2"`, `ecosystem: <name>`, and a unique `library.name`.
3. Author contracts and hierarchy edges following the same shape as `jdk-crypto.yaml`.
4. Tests run automatically — no Go code changes required.

Go contract method names use the canonical `FunctionID.String()` form:
`package/path.Function` or `package/path.(*Receiver).Method`.

## Detection vs reachability (rules, supporting calls, new languages)

There is a hard separation of concerns. Violating it is the most common mistake when
extending this tool.

- **Detection rules** (the private ruleset, loaded as a leased bundle or with `--rules-dir`) detect **terminal
  crypto operations only**, and carry **standard CycloneDX metadata** (assetType,
  algorithmFamily/primitive/operation, etc.). Rules MUST NOT carry crypto-finder
  routing concerns. In particular there is no `supporting-call` assetType and no
  `supportingCall: "true"` sentinel — those are gone; do not reintroduce them.

- **Supporting calls** (setup/lifecycle/config calls around a crypto object, e.g.
  `digest.update`/`doFinal`, `Password.hash`/`addRandomSalt`/`getResult`) are **derived
  structurally from the call graph**, not tagged by rules. See
  `internal/scan/supporting_calls.go` (`deriveObjectLifecycleCalls`): a finding's
  "object" is the var its terminal call is invoked on (`ReceiverVar`) or assigned to
  (`AssignedVar`); supporting calls are the other calls on that var, the fluent-chain
  links (`ChainID`), and the producing constructor. This scales to any library without
  per-call rules.

- **Related material across functions** (a salt, nonce or iv drawn in one function and
  consumed in another) is also derived from the call graph, not tagged by rules. See
  `internal/scan/related_material.go` (`MaterializeRelatedMaterial`): a rule reports the
  draw as a `drbg` algorithm; the engine follows the drawn variable (`AssignedVar`, or a
  buffer a known random-fill call such as `rand.Read(buf)` writes) through calls into application callees,
  mapped onto the receiving parameter by name, up to three hops, until a contract
  `material_roles` entry names the argument. It adds a standard `related-crypto-material`
  asset at the draw and never emits when the callee does not resolve exactly, the variable
  may be rebound before the use, or the matching contracts disagree.

- **Reachability MUST NOT depend on `metadata.api`.** `api` is informational CBOM
  metadata only. `matched_operation.kind` is classified from the matched **source text**
  (`inferMatchedOperationKind`), and the crypto call is located by **position** (match
  columns ∩ call-node columns) with a fluent-chain-root tie-break and a line-only
  fallback (`findCryptoCallNode`). A missing or wrong `api` must never zero out a
  finding's reachability. Do not re-add api-based selection/classification.

### Adding a new language/framework parser

For a new-language parser to get **full** reachability + supporting calls, populate these
`callgraph.FunctionCall` fields (Java does this in `reach/callgraph/java_parser.go`;
see `parseMethodInvocation` / `parseObjectCreation`):

| Field | Meaning |
|---|---|
| `ReceiverVar` | The variable a method is invoked on (`x` in `x.foo()`); empty for static/class receivers |
| `AssignedVar` | The variable a call's result binds to; for fluent chains, set only on the chain **root** (outermost call) |
| `ChainID` | A stable id shared by all links of one fluent chain |
| `StartCol` / `EndCol` | **1-based, start inclusive, end exclusive** (OpenGrep's convention, which the cards engine reproduces; tree-sitter columns are 0-based, so `+1`). Pin it against recorded OpenGrep matches, not a hand-built fixture (`TestCardsMatchAsOpenGrep` in `internal/cardmatch`) |

Omitting any of these is safe — the system **degrades gracefully** to line-only
matching and a chain-root/best-resolved heuristic — but precision on multi-call lines
drops. Library-specific fluent/return-type resolution belongs in the contract KB above,
not in the parser.

## Pull requests and merging

`main` has no branch protection; this rule and `scripts/mergeready` are the merge gate.

- The agent that opens a PR drives it to mergeable: every check green, no merge
  conflict, and every review comment either fixed or answered with a reply that names
  the fixing commit or says why not.
- Claude reviews every PR once, when it is opened or marked ready (`.github/workflows/pr-review.yml`,
  on the CI Claude seat, against `REVIEW.md` as `main` has it). It comments as
  `claude[bot]`; the gate requires a comment or review from it and a reply to each of its
  inline comments. After fixes that need another look, comment `@claude review`. The
  workflow cannot review a PR that changes `pr-review.yml`; a person's approval or the
  `risk-accepted` label stands in for the review then.
- Every PR needs a merge-risk assessment of its head commit, posted by its author with the
  `merge-risk` skill (`.claude/skills/merge-risk/SKILL.md`,
  `go run ./scripts/mergeready risk --pr <n> --verdicts <file>`), again after every push.
  The changed paths set a floor the gate recomputes: CI and release workflows, the merge
  gate and release packaging are high; `go.mod`/`go.sum`, output contracts and CI check
  configuration are medium. Low: the agent merges. Medium or high: a person decides, with
  an approving review of the head commit from someone other than the author, or the
  `risk-accepted` label added after the latest assessment. Tell them and wait. An agent
  never adds or removes that label.
- Before merging, run `go run ./scripts/mergeready check --pr <n>`. It exits 0 only when
  the PR is ready (checks green, no conflict, no request for changes, Claude's review with
  every inline comment answered, and the merge-risk rule above) and otherwise lists every
  reason.
- A `PreToolUse` hook in `.claude/settings.json` runs the same check on any Bash command
  that merges a PR, and blocks it when the PR is not ready or cannot be identified. It also
  blocks any command that could add or remove the `risk-accepted` label. Fix the reasons;
  never work around the hook. It reads commands as text, so write text that only mentions
  a merge or that label (a commit message, a PR body) with a file tool, not an `echo`.
- The `Merge audit` workflow comments on any PR that merged before its checks were green.
- A PR body needs a `## Evidence` section naming every feature the diff touches (a changed
  file matching a glob in a `.claude/skills/verify/features/<id>.md` `## Code paths`), as
  `<id>: <evidence>` or `<id>: N/A: <reason>`. Evidence comes from the verify skill
  (`.claude/skills/verify/scripts/run.sh <id>`). Check it before pushing with
  `go run ./scripts/featuremap check-pr --base origin/main --head HEAD --body-file <file>`;
  the `PR hygiene` workflow runs the same check.
- After the merge, the `Post-merge QA` workflow drives the touched features with an agent
  and comments a verdict per feature on the PR; a `fail` opens an issue. See "Post-merge
  QA" in `.claude/skills/verify/SKILL.md`.
- Metrics: every Monday the `Delivery metrics` workflow writes CI minutes and QA usage per
  PR, revert rate and red-main incidents per week into the one `Delivery metrics` issue;
  `go run ./scripts/deliverymetrics` prints the same tables locally, read-only.
- Stop and ask the owner after three red fix-push rounds on one PR, or at a design decision.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in this repository's GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the canonical five-label triage vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Use the single-context domain documentation layout. See `docs/agents/domain.md`.
