# Pre-Commit Guidelines — crypto-finder

These guidelines define the quality checks every developer must pass **before committing** code to this repository. They are tailored to this codebase's architecture, patterns, and tooling. For general contribution setup, see [CONTRIBUTING.md](CONTRIBUTING.md).

**When to use this**: Before every `git commit`. Treat each section as a self-review checklist.

---

## Table of Contents

- [Required Local Checks](#required-local-checks)
- [Architecture Adherence](#architecture-adherence)
- [Interface Design](#interface-design)
- [Error Handling](#error-handling)
- [Testing Standards](#testing-standards)
- [Concurrency Patterns](#concurrency-patterns)
- [Security](#security)
- [Performance](#performance)
- [Code Style and Linting Thresholds](#code-style-and-linting-thresholds)
- [Naming Conventions](#naming-conventions)
- [Common Mistakes to Avoid](#common-mistakes-to-avoid)
- [Pre-Commit Quick Reference](#pre-commit-quick-reference)

---

## Required Local Checks

**Do NOT commit if any of these fail.** Run them locally before every commit:

```bash
# 1. Lint — must pass with zero issues
make lint

# 2. Tests — must pass with race detector enabled
make test

# 3. Coverage — must meet the 80% project-wide threshold
make coverage-check
```

| Check | Command | What it validates |
|-------|---------|-------------------|
| **Linting** | `make lint` | golangci-lint v2 with 30+ linters (pinned version from `.golangci-lint-version`) |
| **Tests** | `make test` | All tests with `-race` flag, `-v` for verbose output |
| **Coverage** | `make coverage-check` | 80% project-wide threshold (configured in `.testcoverage.yml`) |

### First-time setup

```bash
# Install the pinned golangci-lint version
make lint-install

# Install the coverage threshold checker
go install github.com/vladopajic/go-test-coverage/v2@latest
```

### What's excluded from coverage

Coverage excludes `cmd/` and `internal/cli/` (CLI boilerplate) and generated files (`*.pb.go`, `*_generated.go`). See `.testcoverage.yml` for the full exclusion list.

### If a check fails

- **Lint failure**: Fix the issue. Do not add `//nolint` without a specific linter and explanation.
- **Test failure**: Investigate the root cause. Do not skip or comment out tests.
- **Coverage failure**: Add tests for your new code. The threshold is 80% project-wide.

---

## Architecture Adherence

The project follows a hexagonal (clean) architecture. Dependencies flow inward:

```
cli/  -->  engine/  -->  scanner/, rules/, dependency/, language/  -->  entities/
 |                            |
 |                       cache/, api/, output/ (infrastructure)
 v
cmd/crypto-finder/main.go  (calls only cli.Execute())
```

### Before committing, verify

- [ ] Your code respects layer boundaries — no upward imports (e.g., `scanner/` must never import `engine/` or `cli/`).
- [ ] Adapter implementations (`scanner/opengrep/`, `scanner/semgrep/`, `dependency/`) depend on their interface package, not on concrete siblings.
- [ ] `entities/` has **zero** internal imports — it is the innermost layer. Adding an import here breaks the architecture.
- [ ] New scanning logic goes through `engine.Orchestrator`, not directly in `cli/` commands.
- [ ] `cli/` commands only: validate input, wire dependencies, call `engine/` or `scan/`, handle output. No business logic in Cobra command functions.
- [ ] All packages remain under `internal/` — this project exposes no public Go API.
- [ ] New packages include a package-level doc comment explaining their responsibility.

---

## Interface Design

Reference implementations: `scanner.Scanner` (`internal/scanner/interface.go`), `rules.RuleSource` (`internal/rules/source.go`), `dependency.Resolver` (`internal/dependency/resolver.go`), `language.Detector` (`internal/language/detector.go`).

### Before committing, verify

- [ ] Interfaces are defined at the **consumer** package, not the provider. The `scanner.Scanner` interface lives in `scanner/`, not in `scanner/opengrep/`.
- [ ] Your interface has **2-4 methods**. More than 5 is a design smell — consider splitting.
- [ ] New implementations register with the appropriate registry (`scanner.Registry`, `dependency.Registry`).
- [ ] You did not create an interface for a single concrete implementation unless testing requires it. Prefer inline struct mocks.
- [ ] Optional configuration uses the **functional options** pattern (see `callgraph.ParserOption` on `parserConfig`). Avoid builder chains or config structs with many boolean fields.

---

## Error Handling

Reference: `internal/errors/formatter.go` for CLI-facing error utilities.

### Rules

- **Always wrap with context**: `fmt.Errorf("failed to <verb> <noun>: %w", err)`. Describe WHAT failed.
- **Use `%w`** (not `%v` or `%s`) to preserve the error chain.
- **Use `errors.Is()` / `errors.As()`** instead of direct `==` comparison (`errorlint` enforces this).
- **CLI-facing errors** use utilities from `internal/errors/`: `FormatError`, `FormatScannerError`, `FormatValidationError`, `WrapWithSuggestion`, `FormatMultiError`.
- **Non-critical failures** (cache misses, graph enrichment, optional API calls) log warnings via zerolog and continue. Only return errors that should stop the pipeline.
- **Type assertions** must use the `ok` pattern (`errcheck` has `check-type-assertions: true`).

### What NOT to do

```go
// BAD: swallowing error
_ = file.Close()

// BAD: direct comparison (breaks with wrapping)
if err == os.ErrNotExist { ... }

// BAD: wrapping without context
return fmt.Errorf("%w", err)

// BAD: %v breaks error chain
return fmt.Errorf("scan failed: %v", err)

// GOOD:
return fmt.Errorf("failed to close report file: %w", err)
if errors.Is(err, os.ErrNotExist) { ... }
```

### Before committing, verify

- [ ] All errors are wrapped with `%w` and descriptive context.
- [ ] `errors.Is()` / `errors.As()` used instead of `==` comparison.
- [ ] Type assertions use the `ok` pattern.
- [ ] CLI-facing errors use `internal/errors/` utilities.
- [ ] Non-critical failures log warnings but don't fail the pipeline.

---

## Testing Standards

Reference: `internal/engine/orchestrator_test.go`, `internal/converter/primitives_test.go`, `internal/cache/manager_test.go`.

### Rules

- **`t.Parallel()`** on every test function AND every `t.Run()` subtest. No exceptions.
- **Inline struct mocks** with func fields (e.g., `mockRuleSource { loadFunc func() }`, `stubParser { parseFunc func() }`). Do NOT add `gomock`, `mockgen`, `testify/mock`, or any code-gen mocking library to this project.
- **Table-driven tests** with `tests := []struct{ name string; ... }` and `tt` as the loop variable (not `tc` or `test`).
- **`t.TempDir()`** for any filesystem operations. Never write to fixed paths or leave test artifacts.
- **`t.Helper()`** on every test helper function that calls `t.Fatal`, `t.Error`, or similar.
- **Integration tests** go in `*_integration_test.go` files and must guard with `t.Skip()` when external tools are unavailable (see `checkOpengrepAvailable` pattern).
- **Assertions**: Use `require` from testify for fatal preconditions (setup failures), `assert` for non-fatal verifications.
- **Coverage**: Your code must maintain the **80% project-wide threshold**. Run `make coverage-check`.
- Test files are excluded from complexity linters (`gocognit`, `gocyclo`, `funlen`, `goconst`, `gosec`, `errcheck`).

### Before committing, verify

- [ ] Every test function and subtest calls `t.Parallel()`.
- [ ] Mocks are inline struct types with func fields — no external mock libraries.
- [ ] Table-driven tests use `tt` as the loop variable.
- [ ] `t.TempDir()` used for filesystem operations.
- [ ] `t.Helper()` on every test helper function.
- [ ] Integration tests guard with `t.Skip()` when tools are unavailable.
- [ ] `require` for fatal preconditions, `assert` for non-fatal checks.
- [ ] Coverage maintained at >= 80% (`make coverage-check`).

---

## Concurrency Patterns

Reference: `internal/engine/dependency_scanner.go` (worker pool), `internal/config/config.go` (singleton with `sync.Once`), `internal/scanner/registry.go` (thread-safe registry).

### Rules

- **`context.Context` as first parameter** on all blocking or long-running operations. The `noctx` linter catches HTTP requests missing context.
- **`sync.RWMutex`**: Use `RLock()` for read-only operations, `Lock()` for mutations. Do not use `Lock()` for everything.
- **Worker pool pattern**: Buffered channels sized to `len(items)`, `sync.WaitGroup` for tracking, capped at `maxWorkers = 8`. See `scanDependenciesParallel` for the canonical implementation.
- **All goroutines tracked** via `sync.WaitGroup` or equivalent. No fire-and-forget goroutines.
- **`exec.CommandContext`** for external process execution — ensures cancellation kills the process.

### What NOT to do

```go
// BAD: unbuffered channel with multiple senders (deadlock risk)
ch := make(chan result)

// BAD: missing context
func (s *Scanner) Scan(target string, ...) // should accept ctx

// BAD: Lock() for read-only operation
r.mu.Lock() // should be r.mu.RLock() if only reading

// BAD: untracked goroutine
go func() { process(item) }() // leaked goroutine
```

### Before committing, verify

- [ ] `context.Context` is the first parameter on all blocking operations.
- [ ] `RLock()` for reads, `Lock()` for writes.
- [ ] Worker pools use buffered channels sized to input length.
- [ ] All goroutines tracked via `sync.WaitGroup`.
- [ ] Worker count respects the `maxWorkers` cap.

---

## Security

### Rules

- **File permissions**: `0o600` for sensitive files (config, API keys), `0o750` for directories. Never `0o777` or `0o666`.
- **API key handling**: Keys come from `config.GetAPIKey()` or `SCANOSS_API_KEY`. Never log API keys. Never include them in error messages. Reference: `x-api-key` header in `internal/api/`.
- **Command execution**: Scanner adapters run external tools. Use `exec.CommandContext` with timeout. Verify command arguments are not constructed from untrusted user input without validation.
- **Atomic file writes**: For crash-safe operations, follow the pattern in `DiskFindingsCache.Put`: write to temp file, sync, close, rename.
- **gosec exclusions**: G204 (command execution) and G304 (file path taint) are excluded from automated linting. You must self-review these patterns manually before committing.
- **GPL-2.0-only headers**: Every new `.go` file must include the full copyright header. See `CONTRIBUTING.md` for the exact format.

### Before committing, verify

- [ ] File permissions: `0o600` for sensitive files, `0o750` for directories.
- [ ] No API keys or secrets in log messages or error strings.
- [ ] `exec.CommandContext` used with timeout for external processes.
- [ ] User-controlled paths validated before use (self-review for G304).
- [ ] Command arguments validated before execution (self-review for G204).
- [ ] Atomic write pattern used for crash-safe file operations.
- [ ] GPL-2.0-only header present on all new `.go` files.

---

## Performance

### Rules

- **Slice pre-allocation**: Use `make([]T, 0, expectedLen)` when capacity is known. The `prealloc` linter catches simple cases, range loops, and for loops.
- **HTTP response body close**: `bodyclose` linter is enabled. Always `defer resp.Body.Close()` immediately after the error check.
- **Cache-first**: Expensive operations (dependency resolution, bytecode analysis, rule fetching) must check cache before computing. Reference: `FindingsCache` and `cache.Manager`.
- **Large structs by pointer**: `gocritic` flags structs over 256 bytes. Pass them by pointer, use pointer receivers.
- **Rule filtering**: The orchestrator filters rules by detected language BEFORE passing them to the scanner. New scanner workflows must include this optimization.
- **No unnecessary type conversions**: The `unconvert` linter catches these.

### Before committing, verify

- [ ] Slices pre-allocated when capacity is known.
- [ ] HTTP response bodies always closed.
- [ ] Expensive operations check cache before computing.
- [ ] Large structs (>256 bytes) passed by pointer.
- [ ] Rule sets filtered by language before scanner invocation.

---

## Code Style and Linting Thresholds

All thresholds are configured in `.golangci.yml`. These are the hard numbers — `make lint` enforces them:

| Metric | Threshold | Scope |
|--------|-----------|-------|
| Function length | 120 lines / 60 statements | Production code (excluded in tests and `cmd/`) |
| Cyclomatic complexity | 15 | Production code (excluded in tests) |
| Cognitive complexity | 20 | Production code (excluded in tests and `cmd/`) |
| Nesting depth | 5 | Production code |
| String repetition | 3+ occurrences, 3+ chars | Production code (excluded in tests) |
| Huge parameter | 256 bytes | All code |

### Import Ordering

Three groups, enforced by `goimports` with local prefix `github.com/scanoss/crypto-finder`:

```go
import (
    // Standard library
    "context"
    "fmt"

    // External dependencies
    "github.com/rs/zerolog/log"

    // Internal packages
    "github.com/scanoss/crypto-finder/internal/entities"
    "github.com/scanoss/crypto-finder/internal/scanner"
)
```

### `//nolint` Directives

Every `//nolint` directive **MUST** specify the exact linter AND include an explanation. The `nolintlint` linter enforces this. If you need to suppress a warning, justify it:

```go
// GOOD:
//nolint:gosec // G304 -- path is validated by validateTargetPath() before this call.

// BAD — will fail lint:
//nolint
//nolint:gosec
```

### Other Style Rules

- **Comments end in a period.** Exception: `// TODO` comments (`godot` linter).
- **`context.Context` is always the first parameter** (`revive: context-as-argument`).
- **`error` is always the last return value** (`revive: error-return`).
- **Early returns for errors** — no `else` after a return (`revive: indent-error-flow`).

### Before committing, verify

- [ ] `make lint` passes with zero issues.
- [ ] Functions under 120 lines / 60 statements.
- [ ] Cyclomatic complexity under 15, cognitive complexity under 20.
- [ ] Nesting depth under 5.
- [ ] `//nolint` directives specify the linter + an explanation.
- [ ] Import groups: stdlib | external | internal.
- [ ] Comments end in a period (except `// TODO`).

---

## Naming Conventions

These conventions are derived from existing codebase patterns:

| Element | Convention | Examples |
|---------|-----------|----------|
| **Packages** | Lowercase, single word | `scanner`, `rules`, `cache`, `entities` |
| **Sub-packages** | Implementation-specific | `scanner/opengrep`, `scanner/semgrep` |
| **Interfaces** | Capability/role names | `Scanner`, `Detector`, `Resolver`, `Writer` |
| **Constructors** | `NewXxx()` | `NewOrchestrator()`, `NewRegistry()` |
| **Alt constructors** | `NewXxxWithYyy()` | `NewDiskFindingsCacheWithDir()` |
| **Config structs** | Suffix `Options` | `ScanOptions`, `DepScanOptions` |
| **Functional options** | Suffix `Option` | `ParserOption` |
| **Status enums** | Unexported, `iota` | `depScanStatus` with `statusPending`, `statusDone` |
| **Test files** | Co-located `*_test.go` | `orchestrator_test.go` alongside `orchestrator.go` |
| **Integration tests** | `*_integration_test.go` | `scanner_integration_test.go` |

**Do NOT** use `IScanner`, `ScannerInterface`, or Hungarian notation.

---

## Common Mistakes to Avoid

Self-check for these codebase-specific issues before committing:

1. **Direct `config.GetInstance()` in domain logic.** The config singleton should only be accessed in `cli/` for wiring. Deeper packages receive configuration through constructor parameters (dependency injection).

2. **Importing `cli/` from non-CLI packages.** The `cli/` package is the outermost layer. Nothing in `engine/`, `scanner/`, `entities/`, or any other package should import it.

3. **Adding external mock libraries.** This project uses inline struct mocks with func fields. Do not add `gomock`, `mockgen`, `testify/mock`, or similar.

4. **Logging to stdout.** All logging goes to stderr via zerolog. Stdout is reserved for program output (JSON reports, CycloneDX). Mixing these breaks piping.

5. **Ignoring context cancellation.** Scanner adapters execute external processes. If `ctx` is cancelled, the process must be killed. Always use `exec.CommandContext`.

6. **Creating new singletons.** The project has ONE singleton (`config.Config`). New singletons are an anti-pattern. Use dependency injection.

7. **Business logic in Cobra commands.** Commands validate input, wire dependencies, call `engine/`, and handle output. That's it.

8. **Breaking `entities/` purity.** The `entities/` package must not import any other `internal/` package.

9. **Hardcoding file paths.** Use `config.GetCacheDir()`, `t.TempDir()`, or `os.UserHomeDir()`. Never hardcode `/home/`, `/tmp/`, or absolute paths.

10. **Unbounded goroutine creation.** Parallel work must respect the `maxWorkers` cap. Spawning unbounded goroutines will overwhelm the system with scanner subprocesses.

---

## Pre-Commit Quick Reference

Run through this before every `git commit`:

### Local checks (must all pass)

```bash
make lint            # Zero lint issues
make test            # All tests pass with -race
make coverage-check  # 80% coverage threshold met
```

### Self-review checklist

- [ ] `make lint` passes.
- [ ] `make test` passes (with `-race`).
- [ ] `make coverage-check` passes (80% threshold).
- [ ] No upward layer imports — architecture boundaries respected.
- [ ] `entities/` has zero internal imports.
- [ ] Errors wrapped with `%w` and descriptive context.
- [ ] `t.Parallel()` on all tests and subtests.
- [ ] Inline struct mocks only — no external mock libraries.
- [ ] `t.TempDir()` for filesystem operations in tests.
- [ ] GPL-2.0-only header on all new `.go` files.
- [ ] No secrets in logs or error messages.
- [ ] `exec.CommandContext` for external processes.
- [ ] CHANGELOG.md updated under "Unreleased".
