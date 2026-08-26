# Exploration: Python parser parity with Java (crypto-finder callgraph)

Engram topic: `sdd/python-parser-java-parity/explore` (id 981). Date: 2026-08-26.

## Executive summary

The Python parser (`internal/callgraph/python_parser.go`, 862 lines) already ported the structural fields Java pioneered — `ReceiverVar`/`AssignedVar`/`ChainID`/`StartCol`/`EndCol`/`OwnerBases` — plus MRO/subclass dispatch and arity-tolerant KB lookup (CHANGELOG #44/#45/#46). What it never got is Java's **variable/type tracking layer** (`varTypes`, `varOrigins`, `fieldAssignments`, `collectParameterTypes/Origins`, `extractReturnSources`) and Java's **binding-site coverage** (try-with-resources/for-each/catch/anonymous-class equivalents). `PythonContractTypeResolver` is explicitly documented as "NOT a general type inference engine... does not traverse import or assignment chains" (REQ-4.2/CC-4) — a deliberate scope cut, not an oversight.

Result: Python's `ReceiverVar` attribution works ONLY for a call on a bare local variable directly assigned via a plain `x = ...` statement in the SAME function body. Every other binding form (function **parameters** used as receivers, `self.attr`, `with...as`, `for...in`, `except...as`, tuple/star unpacking, walrus) silently degrades to no receiver identity, which breaks `internal/scan/supporting_calls.go`'s `deriveObjectLifecycleCalls` (string-equality on `ReceiverVar`/`AssignedVar`/`ChainID`; language-agnostic, no Java-only assumptions) for those patterns. The dependency-scan path compounds the parameter/`self.attr` gaps because Python dependencies get full syntactic parsing (no bytecode shortcut) with the SAME weak binding coverage. The export schema (`pkg/graphfrag`, callgraph `6.13`, fragment `graph-fragment-1.13`) is 100% language-agnostic, so every identified gap is fixable without a schema bump.

Baseline verified by the orchestrator on 2026-08-26: `go test ./internal/callgraph/ -run Python` and `go test ./internal/scan/` both pass.

## Capability matrix

Severity: Critical = breaks reachability/supporting-call correctness for common idioms; High = degrades precision for common idioms; Medium = narrower idioms; Low = cosmetic/rare. Path: L = local scan (with/without `--scan-dependencies`), M = mining export surface, K = KB-authoring concern.

| # | Capability | Java (file:line) | Python status | Evidence | Severity | Path | Size |
|---|---|---|---|---|---|---|---|
| 1 | Parameter used as receiver (`def f(cipher): cipher.update(x)`) | `java_parser.go:1236` `collectParameterTypes`, `:1397` `collectParameterOrigins` | **Missing.** `collectPythonLocalVars` (`python_parser.go:418-439`) walks only `assignment` nodes; parameters never visited. `pythonReceiverVarName` (`:666`) requires `localVars[object]==true` → `ReceiverVar=""` | No test; `TestPythonParser_ReceiverVar_MethodCall` only covers a body-local var | **Critical** | L,M | S |
| 2 | Instance-attribute receiver provenance (`self.x = Cipher(...)` in `__init__`, `self.x.encrypt()` elsewhere) | `java_parser.go:679-719` `collectClassFieldAssignments`/`extractFieldAssignments`, `varOrigin{kind:"field"}` | **Missing.** `parseAttributeCall` (`:536`) special-cases only literal `"self"`; `self.x` falls to generic fallback → synthetic `FunctionID{Type:"self.x"}`. `self.x = ...` never registered (`collectPythonLocalVarsInNode` handles only `left.Type()==identifier`) | `python_parser_test.go:60` passes `self.key` as an argument, never as receiver | **Critical** | L,M | M |
| 3 | Non-assignment bindings: `with...as`, `for...in`, `except...as`, comprehension targets, walrus, tuple/star unpacking | `java_parser.go:1329` `javaSingleDeclaredVar` (a5d69d4) | **Missing entirely.** Only `pythonNodeAssignment` with identifier left side; `pythonAssignedVarFromParent` (`:824`) matches only a direct `assignment` parent or one `expression_statement` wrapper | No test | **Critical** | L,M | M |
| 4 | Conditional / lazy / relative imports (`try/except ImportError`, `if TYPE_CHECKING:`, function-local import, `from . import x`, `from ..pkg import y`) | n/a (Java imports are file-scoped) | **Two bugs.** (a) `extractImports` (`:138`) iterates only direct root children — nested imports dropped. (b) `processImportFromStatement` (`:183`) discards `import_prefix`; `from . import x` yields empty `modulePath` and is dropped; `from .foo import Bar` resolves `foo` as absolute | No test | **High** | L,M | M |
| 5 | Fluent/constructor chains, ChainID, AssignedVar-on-root | chain root walker (1b1a3b6) | **At parity.** `pythonCallChainContext`/`pythonChainRootNode` (`:729-796`); `TestPythonParser_ChainID_FluentChain` | — | — | L,M | — |
| 6 | Column convention (1-based inclusive start / exclusive end) | `TestOpengrep_EndColConventionPinning` | **Populated, not pinned for Python.** `parseCallExpr` (`:470`); only `TestPythonParser_FunctionCallCarriesNonZeroColumns` (non-zero check) | No Python opengrep pinning test | **Medium** | L,M | S |
| 7 | Subclass/MRO dispatch, `getattr`/`importlib` dynamic dispatch | 7ee21ca | **Partial.** `python_mro_dispatch_test.go` covers MRO; no `getattr`/`importlib` | 4 tests, none dynamic | **Medium** | L,M | M |
| 8 | Decorators (`@property`, `@staticmethod`, `@classmethod`, custom) | n/a | **Unwrapped, semantically ignored.** `extractDecoratedMethod`/`processDecorated` (`:374`, `:389`) discard decorators; `cls` falls into gap #1 | No test | **Medium** | L | S |
| 9 | `super().__init__(...)` and `super()` receivers | 2287a76 | **Not handled.** `super` resolves to `FunctionID{Package: analysis.PackagePath, Name:"super"}`; chain link resolves against wrong root | No test | **Medium** | L | S |
| 10 | Keyword arguments / arity tolerance in KB lookup | Java exact-arity | **At parity (more permissive).** `ContractsForTolerant` (CHANGELOG #44), `pythonFunctionFQN` | tested | — | L,M,K | — |
| 11 | `functools.partial`, `__call__`/`__enter__` dunder invocation | n/a | **Missing.** `parseCallExpr` recognizes only `identifier`/`attribute` function nodes | No test | **Low-Medium** | L | M |
| 12 | Module-level / class-body statement entry points (Java `<clinit>`: 0f1eef7/fbe926c/71439d3) | `java_parser.go:566-671` `parseClassInitDecl`/`classInitNodes` | **Missing.** No synthetic module-level or class-body entry point; `extractDeclarations` (`:223`) registers only function/class/decorated defs; module-root and class-body statements are never walked for calls | No test | **Critical** | L,M | M |
| 13 | Type hints (`Optional[...]`, `Union`, `TYPE_CHECKING`) feeding resolution | Java bytecode generic signatures | **Not consumed.** `parsePythonReturnType` (`:849`) extracts raw text; no normalization | No test | **Medium** | L,M | M |
| 14 | Dependency-scan external type resolution | `JavaBytecodeTypeResolver` (JAR/JDK bytecode, 8 workers) | **No analogue, lower severity.** `PythonContractTypeResolver` is KB-lookup only. Python deps are pip-resolved `.py` source → full syntactic parsing (no Java-only type-only fast path, `dependency_scanner.go:363,621`). Precision gap, not coverage gap | `docs/DEPENDENCY_SCANNING.md` | **Medium** | L (`--scan-dependencies`) | L |
| 15 | Cross-package `__init__.py` re-export resolution | wildcard/static-wildcard import tracking | **Partial.** Per-file `analysis.Imports` are independent; builder does not stitch `__init__.py` re-exports into sibling files | No two-file test | **High** | L,M | M |
| 16 | f-strings containing calls | n/a | **Likely fine** (unconditional recursion in `walkForCalls`) | No dedicated test | **Low** | L | S |
| 17 | `async`/`await` | n/a | **Likely fine structurally**; grammar behavior not confirmed against the pinned `go-tree-sitter` python grammar | No test | **Low (verify)** | L | S |
| 18 | `owner_visibility` (827fe39) | `java_parser.go:915-1020` | **Not modeled.** No visibility set on Python `FunctionDecl` | Confirmed by full read | **Low** | L,M | S |
| 19 | Generic type erasure on receiver (109d04e) | `stripGenericSuffix`/`erasedTypeName` | **N/A for Python** | — | — | — | — |
| 20 | Recurse into constructor arguments for provenance (2959b64) | `extractFieldAssignments` recursion | **Partial.** Raw argument text captured for KB `when:`; no recursive provenance chain; largely subsumed by #2/#3 | — | **Medium** | L,M | M |

## Already at parity (do not redo)

- `ReceiverVar` / `AssignedVar` / `ChainID` populated for the simple case (bare local var, direct assignment, same function).
- Fluent/constructor chain root detection mirrors Java exactly; tested.
- `StartCol`/`EndCol` convention implemented (needs a pinning test, not a mechanism change).
- `OwnerBases` populated and feeding MRO dispatch; regression guard for Java interface dispatch.
- Arity-tolerant KB lookup (`ContractsForTolerant`).
- `.pyi` stubs take precedence over implementation (CHANGELOG #45); module aliasing preserves same-named functions.
- Extensive Python KB (24 YAML libraries) — a KB achievement orthogonal to parser gaps.
- `internal/scan/supporting_calls.go` is language-agnostic — every fix lives in `python_parser.go`.
- `pkg/graphfrag` exporters have zero language conditionals — no schema bump needed for any row.
- `python_e2e_integration_test.go` (12 tests) gives export-level regression coverage.

## Consumption paths

### Local scans (with and without `--scan-dependencies`)

`internal/dependency/pip_resolver.go` resolves distributions via `importlib.metadata.packages_distributions()` with a `dist-info`/`RECORD` fallback, against `VIRTUAL_ENV` → project `.venv`/`venv` → ambient interpreter. Resolved packages are real `.py` source and get full syntactic parsing via the same `PythonParser`; there is no separate vendoring concept. The Java-only type-only fast path does not apply, so Python does more parsing work per dependency but suffers no coverage loss (performance-only asymmetry, row 14). Rows 1–4, 12, 15 reproduce at dependency scale: crypto objects built in a package's `__init__.py` and consumed via `self.attr` or a helper parameter lose reachability precision exactly as in user code.

### Mining (crypto-mining-service consumer)

Exported surface: `pkg/graphfrag` (`CallgraphSchemaVersion = "6.13"`, fragment `graph-fragment-1.13`), `internal/scan/export.go`, `internal/scan/fragment_export.go`. The exporter is generic over `FunctionDecl`/`FunctionCall` fields (`ReceiverVar`, `AssignedVar`, `ChainID`, columns, `OwnerBases`, `crypto_entry_points[]`, `supporting_calls[]`, `occurrence_key`). Every row is parser-internal: fixes change output volume/precision for Python findings, not schema shape. The only thing that would require a schema decision — a Python analogue of Java's `resolved_key_length` (6.12→6.13) for `dklen=`/`kdf.derive` — is explicitly NOT proposed here.

Performance at mining scale is the main mining-specific risk: fixing row 12 increases synthetic entry-point `FunctionDecl` count for library-style code (bounded, mirrors Java `<clinit>`). `PythonParser.ParseDirectory` is sequential per directory, but the builder parallelizes across directories and dependency workers are uncapped for non-Java ecosystems, so no Python-specific throughput bottleneck was found beyond the inherent no-bytecode parsing cost.

## Recommended scope for `python-parser-java-parity`

**In scope (parser-internal, schema-safe, highest ROI):**
1. Row 1 — parameter-as-receiver binding.
2. Row 3 — non-assignment bindings (`with...as`, `for...in`, `except...as`, walrus, tuple/star unpacking).
3. Row 2 — `self.attr` instance-attribute provenance (class-scoped field tracking across methods; largest design effort).
4. Row 12 — module-level and class-body synthetic entry points (Python `<clinit>` analogue).
5. Row 4 — import robustness: recurse into `try/except`/`if`/function bodies; fix relative imports.
6. Row 15 — `__init__.py` re-export propagation across files.

**Deferred follow-ups:** row 7 (dynamic dispatch), row 6 (column pinning test — fast-follow test-only PR), rows 8/9 (decorators, `super()`), row 11 (`partial`/`__call__`), row 13 (type hints), row 14 (stub-based external resolver), row 17 (async grammar check — early spike in design), `resolved_key_length`-style KDF field (separate product decision + schema bump).

**KB-vs-parser boundary:** none of the rows are KB (YAML) concerns; the existing Python KB fires correctly once calls carry the right FQN and structure.

## Open questions

1. Scope size — ship all 6 in-scope rows in one change, or split into "binding-site coverage" (rows 1,3,4,15) vs "field/module-level provenance" (rows 2,12)?
2. Row 12 — synthetic entry points for BOTH module-level and class-body code, or module-level only in this change?
3. Row 17 — pre-flight async/await grammar spike in design, or skip?

## Orchestrator resolutions (2026-08-26)

- Q1: single change, all 6 rows — session preflight fixed `delivery_strategy=exception-ok` with no size stop.
- Q2: both module-level and class-body, mirroring Java `<clinit>` (covers static and instance-field initializers); parity is the goal.
- Q3: yes — a short empirical grammar check is a design-phase task, not a user decision.
