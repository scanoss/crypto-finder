# Dependency Scanning & Call Chain Attribution

This document explains how crypto-finder discovers cryptographic usage in project dependencies and traces it back to user code through call graph analysis.

Contract note: the current implementation keeps the interim report focused on findings metadata (`source`, `dependency_info`, `finding_id`). The finding-centric reachability slices such as `call_chains`, `entry_call`, and `crypto_call` are emitted by the dedicated `--export-callgraph` artifact rather than embedded in the interim report.

## Overview

When `--scan-dependencies` is enabled, crypto-finder goes beyond scanning the user's source code. It resolves the project's dependency tree, scans each dependency for cryptographic usage, builds a cross-package call graph, and traces each finding back to the user's code to answer: **"Does my code actually reach this crypto function?"**

```mermaid
flowchart TB
    subgraph Input
        UC[User Code<br/><i>your project</i>]
        DEP[Dependencies<br/><i>go.sum / pom.xml / ...</i>]
    end

    subgraph Pipeline["ScanWithDependencies Pipeline"]
        direction TB
        S1["① Resolve Dependencies"]
        S2["② Load & Filter Rules"]
        S3["③ Scan Dependencies in Parallel"]
        S4["④ Build Call Graph"]
        S5["⑤ Trace & Attribute Findings"]
        S6["⑥ Merge Reports"]

        S1 --> S2 --> S3 --> S4 --> S5 --> S6
    end

    UC --> S1
    DEP --> S1

    S6 --> OUT[Final Report<br/><i>with source, finding_id,<br/>dependency_info</i>]
```

## The Six-Step Pipeline

The full pipeline lives in [`DependencyScanner.ScanWithDependencies()`](../internal/engine/dependency_scanner.go). Here's what each step does and why.

### Step 1: Resolve Dependencies

```mermaid
flowchart LR
    Target["Project Dir"] --> Resolver
    Resolver --> RR["ResolveResult"]
    RR --> Modules["[]Dependency<br/>{Module, Version, Dir}"]
    RR --> RootMod["RootModule<br/><i>e.g. github.com/myorg/app</i>"]
```

The [`Resolver` interface](../internal/dependency/resolver.go) discovers all dependencies and locates their source code on disk. Each ecosystem has its own resolver implementation (see [Supported Ecosystems](#supported-ecosystems) below). Each `Dependency` carries:

| Field     | Go Example                          | Java Example                     | Python Example                   | Rust Example                     | Purpose                          |
|-----------|-------------------------------------|----------------------------------|----------------------------------|----------------------------------|----------------------------------|
| `Module`  | `golang.org/x/crypto`              | `org.bouncycastle:bcprov-jdk18on`| `cryptography`                   | `ring`                           | Import path / coordinate         |
| `Version` | `v0.17.0`                           | `1.77`                           | `42.0.5`                         | `0.17.8`                         | Resolved version                 |
| `Dir`     | `~/go/pkg/mod/golang.org/x/crypto@v0.17.0` | `~/.crypto-finder/cache/sources/org.bouncycastle:bcprov-jdk18on/1.77/` | `~/.local/lib/python3.x/site-packages/cryptography/` | `~/.cargo/registry/src/.../ring-0.17.8/` | Filesystem path to scan |

The `RootModule` (e.g. `github.com/myorg/app` for Go, `com.myorg` for Java) is used later to determine which packages are "user code" vs. "dependency code".

### Step 2: Load & Filter Rules

Rules are pre-loaded once and filtered to the ecosystem's language(s). For a Go project, only `go` rules are kept; for Java, only `java` rules. This avoids running irrelevant rules against source code, significantly reducing scanner overhead.

### Step 3: Scan Dependencies in Parallel

```mermaid
flowchart TB
    Work["Deduplicated Deps"] --> Pool["Worker Pool<br/><i>default: 4 goroutines</i>"]
    Pool --> W1["Worker 1"] --> R1["Report A"]
    Pool --> W2["Worker 2"] --> R2["Report B"]
    Pool --> W3["Worker 3"] --> R3["Report C"]
    Pool --> W4["Worker 4"] --> R4["Report D"]
```

Each dependency is scanned independently using the same `Orchestrator.Scan()` pipeline as user code (Semgrep/OpenGrep rules → deduplication → enrichment). Dependencies are deduplicated by `module@version` and processed in a stable order (`module`, `version`, `dir`) so repeated scans produce deterministic report and call graph inputs.

Dependencies without a usable local source directory are **not** sent to the scanner. They are logged as `Skipping dependency source scan: no local source directory` instead of triggering empty-path scanner failures. For Java, those dependencies still proceed to step 4 as **type-only** inputs as long as `module@version` can be resolved to a compiled JAR.

### Step 4: Build the Call Graph

This is where the architecture gets interesting. The call graph builder uses **syntactic parsing** to process source files, which means it works on raw source without needing a full Go toolchain, Java compiler, Python interpreter, or Rust toolchain. The [`Parser` interface](../internal/callgraph/builder.go) abstracts all language-specific behavior:

```go
type Parser interface {
    ParseDirectory(dir string, packagePath string) ([]*FileAnalysis, error)
    SkipDirs() map[string]bool
    SubPackagePath(parentPath, dirName string) string
    PackageSeparator() string  // "/" for Go, "." for Java/Python, "::" for Rust
}
```

The [`NewParserForEcosystem()`](../internal/callgraph/parser_registry.go) factory selects the right parser (`GoParser`, `JavaParser`, `PythonParser`, or `RustParser`) based on the detected ecosystem.

```mermaid
flowchart TB
    subgraph "Graph Packages (full source parsing)"
        U["User Code Dir<br/><i>+ import path</i>"]
        D1["Dep with findings<br/><i>golang.org/x/crypto</i>"]
        D2["Dep with findings<br/><i>org.bouncycastle:bcprov-jdk18on</i>"]
    end

    subgraph "Type-Only Packages (bytecode index only)"
        T1["Dep without findings<br/><i>org.springframework:spring-core</i>"]
        T2["Dep without findings<br/><i>com.fasterxml.jackson:jackson-core</i>"]
    end

    subgraph "Builder.BuildFromDirectories()"
        direction TB
        Parse["Phase 1: Parser.ParseDirectory()<br/><i>syntactic parsing per source file</i>"]
        FnMap["Functions map<br/><i>FunctionID → FunctionDecl</i>"]
        RevIdx["Callers reverse index<br/><i>callee → []callerID</i>"]
        TypeRes["Phase 2: Bytecode type index<br/><i>class names + method signatures + return types</i>"]
        Fluent["Fluent chain resolution<br/><i>propagate return types</i>"]

        Parse --> FnMap
        FnMap --> RevIdx
        RevIdx --> TypeRes
        TypeRes --> Fluent
    end

    U --> Parse
    D1 --> Parse
    D2 --> Parse
    T1 --> TypeRes
    T2 --> TypeRes

    Fluent --> CG["CallGraph"]
```

> **Performance optimization**: Only dependencies with crypto findings get full source parsing.
> Dependencies without findings contribute only their bytecode type signatures (class names,
> method signatures, return types, interface hierarchy). This preserves 100% type resolution
> accuracy for fluent chains while skipping expensive source parsing for ~80% of dependencies.

#### What the parser extracts

Each language parser extracts the same semantic information into the shared `FileAnalysis` / `FunctionDecl` structures. For Go (`.go` files, excluding `_test.go`):

| Extracted | Example | Stored As |
|-----------|---------|-----------|
| Package imports | `import "crypto/aes"` | `Imports["aes"] = "crypto/aes"` |
| Function declarations | `func Encrypt(...)` | `FunctionDecl{ID, FilePath, StartLine, EndLine, Calls}` |
| Method declarations | `func (b *Block) Seal(...)` | Same, with `Type = "*Block"` |
| Call expressions | `aes.NewCipher(key)` | `FunctionCall{Callee: {Package: "crypto/aes", Name: "NewCipher"}}` |

For Java (`.java` files):

| Extracted | Example | Stored As |
|-----------|---------|-----------|
| Package declaration | `package javax.crypto;` | `PackagePath = "javax.crypto"` |
| Imports (explicit) | `import javax.crypto.Cipher;` | `Imports["Cipher"] = "javax.crypto"` |
| Imports (wildcard) | `import java.security.*;` | `WildcardImports = ["java.security"]` |
| Class methods | `class Cipher { getInstance(...) }` | `FunctionDecl{..., Type: "Cipher", Name: "getInstance"}` |
| Constructors | `new SecretKeySpec(...)` | Call to `FunctionID{..., Type: "SecretKeySpec", Name: "<init>"}` |
| Method invocations | `Cipher.getInstance("AES")` | Resolved via imports → `FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance"}` |
| Local variable types | `Cipher cipher = Cipher.getInstance(...)` | Enables `cipher.doFinal()` → resolves `cipher` to `Cipher` type |

For Python (`.py` files, excluding `test_*.py` and `*_test.py`):

| Extracted | Example | Stored As |
|-----------|---------|-----------|
| Import statements | `import hashlib` | `Imports["hashlib"] = "hashlib"` |
| From imports | `from cryptography.hazmat.primitives import Cipher` | `Imports["Cipher"] = "cryptography.hazmat.primitives"` |
| Wildcard imports | `from hashlib import *` | `WildcardImports = ["hashlib"]` |
| Aliased imports | `import hashlib as hl` | `Imports["hl"] = "hashlib"` |
| Function definitions | `def encrypt(key, data):` | `FunctionDecl{ID, FilePath, StartLine, EndLine, Calls}` |
| Class methods | `class Cipher: def __init__(self):` | `FunctionDecl{..., Type: "Cipher", Name: "<init>"}` |
| Attribute calls | `hashlib.sha256()` | Resolved via imports → `FunctionID{Package: "hashlib", Name: "sha256"}` |
| Chained calls | `cryptography.hazmat.primitives.hashes.SHA256()` | Resolved via first segment import |
| `self` calls | `self.encrypt()` | `FunctionID{Package: current_package, Name: "encrypt"}` |

For Rust (`.rs` files, excluding `*_test.rs` and `tests.rs`):

| Extracted | Example | Stored As |
|-----------|---------|-----------|
| Use declarations | `use ring::aead::Aead;` | `Imports["Aead"] = "ring::aead"` |
| Scoped use lists | `use ring::aead::{Aead, AeadCore};` | `Imports["Aead"] = "ring::aead"`, `Imports["AeadCore"] = "ring::aead"` |
| Wildcard use | `use ring::aead::*;` | `WildcardImports = ["ring::aead"]` |
| Free functions | `fn encrypt(key: &[u8]) {...}` | `FunctionDecl{ID, FilePath, StartLine, EndLine, Calls}` |
| Impl methods | `impl Aead { fn new(...) {...} }` | `FunctionDecl{..., Type: "Aead", Name: "new"}` |
| Scoped calls | `Aead::new(...)` | Resolved via imports → `FunctionID{Package: "ring::aead", Type: "Aead", Name: "new"}` |
| Field calls | `self.encrypt(...)` | `FunctionID{Package: current_module, Name: "encrypt"}` |

#### The two data structures

The `CallGraph` holds two maps:

```
Functions:  "crypto/aes.NewCipher"         → FunctionDecl{...}
            "example.com/app.Encrypt"      → FunctionDecl{Calls: [...]}
            "example.com/app.main"         → FunctionDecl{Calls: [...]}

Callers:    "crypto/aes.NewCipher"         → ["example.com/app.Encrypt"]
            "example.com/app.Encrypt"      → ["example.com/app.main"]
```

- **`Functions`** maps `FunctionID.String()` → `*FunctionDecl` (forward: function → its outgoing calls)
- **`Callers`** maps callee → `[]callerID` (reverse: who calls this function?)

The reverse index is what enables **backward tracing** — starting from a crypto finding and walking up to user code.

#### Type resolution

After building the caller index, the builder runs additional resolution passes to improve type accuracy:

1. **`TypeResolver`** (language-specific): For Java, a bytecode-based resolver reads `.class` files from resolver-supplied dependency JARs (Maven or Gradle) plus the selected JDK platform archives to extract fully-qualified method signatures. JAR indexing runs in parallel and uses a per-artifact bytecode cache under `~/.scanoss/crypto-finder/cache/bytecode/`, keyed by exact artifact identity. This provides accurate parameter types (e.g., `io.jsonwebtoken.SignatureAlgorithm` instead of generic `K`) and return types for fluent chain resolution. The Java resolver can be configured per scan with `java_jdk_major` (`auto`, `8`, `11`, `17`, `21`) and `java_jdk_homes`, which also makes Java dependency resolution JDK-aware. The `TypeResolver` interface is extensible — each language can implement its own approach (Go: `go/types`, Python: `.pyi` stubs, Rust: `rust-analyzer`).

2. **Fluent chain resolution**: For chained calls like `Jwts.builder().setId(id).signWith(algo, key)`, return types are propagated through the chain. If `builder()` returns `JwtBuilder`, then `setId()` is resolved as `JwtBuilder.setId`. Interface inheritance is also followed (e.g., `JwtBuilder` extends `ClaimsMutator`, so `setId` resolves to `ClaimsMutator.setId`).

3. **Argument source tracing**: For each function call, the parser traces where argument values come from — literal constants, local variables, class fields, method parameters, or call results. This produces recursive `source_nodes` showing the data flow into each argument.

### Step 5: Trace & Attribute Findings

This is the core of the attribution system. For each crypto finding in a dependency:

```mermaid
flowchart TB
    Finding["Crypto Finding<br/><i>file: chacha20.go, line: 42</i>"] --> Contain["FindContainingFunction()<br/><i>Which function spans line 42?</i>"]
    Contain --> FnID["FunctionID<br/><i>chacha20poly1305.New</i>"]
    FnID --> Trace["TraceBack(target, userPackages)"]

    subgraph "BFS Backward Trace"
        direction TB
        Start["Start: chacha20poly1305.New"]
        Mid["Caller: mypkg.SecureEncrypt"]
        End["Caller: main.main ✓<br/><i>user package reached!</i>"]

        Start -.->|"Callers[] lookup"| Mid
        Mid -.->|"Callers[] lookup"| End
    end

    Trace --> BFS
    BFS --> Chain["CallChain<br/>[main.main → mypkg.SecureEncrypt → chacha20poly1305.New]"]
```

#### How `TraceBack` works (BFS)

1. **Start** with the target function (where the crypto finding was detected)
2. **Look up** all callers via the reverse index (`graph.Callers[targetKey]`)
3. **Prepend** each caller to the chain being built (so the chain grows backward: `[caller, ...existing]`)
4. **Terminate** when a root function is reached (a function with no callers, e.g., `main`)
5. **Validate** that the complete chain passes through at least one user-package function
6. **Cycle detection** prevents infinite loops in recursive call graphs
7. **Return** all complete chains (BFS finds all paths from entry points to the crypto call site)

The result is an ordered array: **`[program_entry_point, ..., intermediate, ..., crypto_call_site]`** — array position `[i]` calls position `[i+1]`.

#### Attribution output

After tracing, each finding gets structured attribution metadata in the interim report, and the detailed reachability slices are emitted by the separate call graph export.

**Dependency finding:**
```json
{
  "source": "dependency",
  "finding_id": "a1b2c3d4",
  "dependency_info": {
    "module": "golang.org/x/crypto",
    "version": "v0.17.0"
  }
}
```

Dependency finding `file_path` values are relative to the dependency root. The artifact identity stays in `dependency_info`, so consumers do not need to parse `module@version` back out of the path string.

**User code finding**:
```json
{
  "source": "direct",
  "finding_id": "e5f6a7b8"
}
```

**Call graph export slice**:
```json
{
  "finding_id": "a1b2c3d4",
  "call_chains": [
    [
      {"function_name": "main", "file_path": "main.go", "start_line": 15},
      {
        "function_name": "example.com/app/mypkg.SecureEncrypt",
        "file_path": "mypkg/crypto.go",
        "start_line": 8
      },
      {
        "function_name": "golang.org/x/crypto/chacha20poly1305.New",
        "file_path": "chacha20.go",
        "start_line": 42,
        "dependency_info": {
          "module": "golang.org/x/crypto",
          "version": "v0.17.0"
        }
      }
    ]
  ]
}
```

### Step 6: Merge Reports

```mermaid
flowchart TB
    UR["User Report<br/><i>source: direct</i>"]
    DR1["Dep Report 1"]
    DR2["Dep Report 2"]

    UR --> Merged["Merged Report"]
    DR1 --> Merged
    DR2 --> Merged
```

The current implementation merges dependency findings into the interim report and defers reachability slicing to the call graph export. In other words, interim-report inclusion is not gated on whether a finding later produces one or more exported call chains.

User code findings are always included and marked with `source: "direct"`.

---

## Practical Walkthrough

This section traces the entire pipeline using the test project at `testdata/projects/go_with_crypto_dep/`. Every value shown is real — produced by running `crypto-finder scan --scan-dependencies` against this project.

### The Source Code

Three files make up the project:

**`go.mod`** — declares one direct dependency:
```
module example.com/crypto-test
go 1.21
require golang.org/x/crypto v0.31.0
require golang.org/x/sys v0.28.0 // indirect
```

**`main.go`** — the entry point. Does **not** use crypto directly:
```go
package main

import "example.com/crypto-test/mypkg"

func main() {
    key := make([]byte, 32)
    message := []byte("Hello, crypto-finder dependency scanning!")

    encrypted, err := mypkg.SecureEncrypt(key, message)   // line 14
    decrypted, err := mypkg.SecureDecrypt(key, encrypted)  // line 19
}
```

**`mypkg/crypto.go`** — user's wrapper package. Uses crypto from a dependency:
```go
package mypkg

import (
    "crypto/rand"
    "golang.org/x/crypto/chacha20poly1305"
)

func SecureEncrypt(key []byte, plaintext []byte) ([]byte, error) {  // line 12
    aead, err := chacha20poly1305.New(key)                          // line 13 — crypto!
    nonce := make([]byte, aead.NonceSize())
    rand.Read(nonce)                                                // line 19 — crypto!
    ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

func SecureDecrypt(key []byte, ciphertext []byte) ([]byte, error) { // line 28
    aead, err := chacha20poly1305.New(key)                          // line 29 — crypto!
    // ...
}
```

### Step 1: Scan User Code (the normal scan)

The orchestrator runs Semgrep/OpenGrep rules against user code. It finds **3 assets** in `mypkg/crypto.go`:

| Line | Match | Rule |
|------|-------|------|
| 13 | `chacha20poly1305.New(key)` | `go.xcrypto.chacha20poly1305.aead` |
| 19 | `rand.Read(nonce)` | `go.crypto.rand.usage` |
| 29 | `chacha20poly1305.New(key)` | `go.xcrypto.chacha20poly1305.aead` |

This produces the **user report**. At this point there are no `source`, `call_chain`, or `dependency_info` fields — just raw findings.

### Step 2: Resolve Dependencies

The Go resolver runs `go list -m -json all`. It returns:

```
RootModule: "example.com/crypto-test"

Dependencies:
  Module                    Version   Dir
  golang.org/x/crypto       v0.31.0   ~/go/pkg/mod/golang.org/x/crypto@v0.31.0
  golang.org/x/sys          v0.28.0   ~/go/pkg/mod/golang.org/x/sys@v0.28.0
```

The `RootModule` (`example.com/crypto-test`) is the key — any package whose import path starts with this prefix is considered **user code**. Everything else is a dependency.

### Step 3: Scan Dependencies in Parallel

Each dependency gets scanned with the same rules, limited to Go rules only:

| Dependency | Crypto Assets Found | Why |
|------------|--------------------:|-----|
| `golang.org/x/crypto` | ~870 | It **is** a crypto library — virtually every file matches |
| `golang.org/x/sys` | ~3 | False positives (function names like `Generate` matching crypto rules) |

Total: **~873 dependency findings**. Both dependencies have findings, so both proceed to step 4.

### Step 4: Build the Call Graph

The builder receives three package directories:

```
PackageDirs = [
    {Dir: ".../go_with_crypto_dep",           ImportPath: "example.com/crypto-test"},
    {Dir: ".../golang.org/x/crypto@v0.31.0",  ImportPath: "golang.org/x/crypto"},
    {Dir: ".../golang.org/x/sys@v0.28.0",     ImportPath: "golang.org/x/sys"},
]
```

The syntactic parsing parser processes every `.go` file and extracts function declarations with their calls.

**From `main.go`:**
```
FunctionDecl: example.com/crypto-test.main
  File: main.go, Lines: 10–26
  Calls:
    → example.com/crypto-test/mypkg.SecureEncrypt  (line 14)
    → example.com/crypto-test/mypkg.SecureDecrypt  (line 19)
```

**From `mypkg/crypto.go`:**
```
FunctionDecl: example.com/crypto-test/mypkg.SecureEncrypt
  File: mypkg/crypto.go, Lines: 12–25
  Calls:
    → golang.org/x/crypto/chacha20poly1305.New     (line 13)
    → crypto/rand.Read                             (line 19)

FunctionDecl: example.com/crypto-test/mypkg.SecureDecrypt
  File: mypkg/crypto.go, Lines: 28–46
  Calls:
    → golang.org/x/crypto/chacha20poly1305.New     (line 29)
```

**From `golang.org/x/crypto/...`:** hundreds more function declarations.

Then `buildCallerIndex()` creates the **reverse index** (callee → who calls it):

```
Callers["example.com/crypto-test/mypkg.SecureEncrypt"]
    = ["example.com/crypto-test.main"]

Callers["example.com/crypto-test/mypkg.SecureDecrypt"]
    = ["example.com/crypto-test.main"]

Callers["golang.org/x/crypto/chacha20poly1305.New"]
    = ["example.com/crypto-test/mypkg.SecureEncrypt",
       "example.com/crypto-test/mypkg.SecureDecrypt"]
```

This reverse index is what makes backward tracing possible.

### Step 5: Trace & Attribute

The system now traces **each finding** back through the call graph to user code. Three different scenarios play out:

#### Scenario A: User finding — `chacha20poly1305.New` at line 13

This finding is in `mypkg/crypto.go` (user code). The enrichment flow:

**5a-1. Find the containing function:**

`FindContainingFunction("mypkg/crypto.go", 13)` iterates all `FunctionDecl`s, looking for one whose `FilePath` matches and whose `StartLine..EndLine` spans line 13. It finds **`SecureEncrypt`** (lines 12–25).

**5a-2. Trace back to entry point:**

`TraceBack(SecureEncrypt, userPackages={"example.com/crypto-test"}, maxDepth=0)`:

```
BFS queue: [ [SecureEncrypt] ]

Iteration 1:
  chain = [SecureEncrypt]
  head  = SecureEncrypt
  Look up Callers["...mypkg.SecureEncrypt"] → ["...main"]
  Prepend caller: chain becomes [main, SecureEncrypt]
  → push to queue

Iteration 2:
  chain = [main, SecureEncrypt]
  head  = main
  Look up Callers["...main"] → [] (no callers — root function)
  Chain reaches user code? YES (both functions are user code)
  Chain length > 1? YES
  → CHAIN COMPLETE! Add to results.
```

**5a-3. Exported slice:**

```json
"source": "direct",
"finding_id": "a1b2c3d4",
"call_chains": [
    [
        {"function_name": "main", "namespace": "example.com/crypto-test", "file_path": "main.go", "line": 14},
        {"function_name": "SecureEncrypt", "namespace": "example.com/crypto-test/mypkg", "file_path": "mypkg/crypto.go", "line": 12}
    ]
]
```

Note: `main`'s line is **14** (the line where `main` *calls* `SecureEncrypt`), not line 10 where `main` is declared. This is because `findCallLine()` searches `main`'s `Calls` list for the specific call to `SecureEncrypt` and returns that call-site line number.

#### Scenario B: User finding — `chacha20poly1305.New` at line 29

Same logic, but traces through `SecureDecrypt`:

```
FindContainingFunction("mypkg/crypto.go", 29) → SecureDecrypt (lines 28–46)

TraceBack(SecureDecrypt):
  [SecureDecrypt]
  → prepend caller → [main, SecureDecrypt]
  → main has no callers (root function), chain reaches user code → CHAIN COMPLETE
```

```json
"source": "direct",
"finding_id": "b2c3d4e5",
"call_chains": [
    [
        {"function_name": "main", "namespace": "example.com/crypto-test", "file_path": "main.go", "line": 19},
        {"function_name": "SecureDecrypt", "namespace": "example.com/crypto-test/mypkg", "file_path": "mypkg/crypto.go", "line": 28}
    ]
]
```

Note: `main`'s line is now **19** — the line where `main` calls `SecureDecrypt`, not 14.

#### Scenario C: Dependency finding — deep `x/crypto` internal functions (UNREACHABLE)

Take any internal function in `golang.org/x/crypto`, say `ssh.newAESCTR`:

```
FindContainingFunction(".../ssh/cipher.go", N) → ssh.newAESCTR

TraceBack(ssh.newAESCTR):
  [ssh.newAESCTR]
  → Callers: maybe some internal SSH functions
  → Keep walking back to root functions...
  → Root functions found, but no chain passes through "example.com/crypto-test"
  → All chains discarded (no user code reached).
```

Result: `call_chains` is **empty**.

In the current implementation, this means the finding may still exist in the interim report, but it will not contribute a useful reachability slice to the call graph export.

This is why the interesting downstream signal stays narrow even when a dependency contains a large amount of internal crypto usage. The vast majority of `golang.org/x/crypto`'s internal crypto usage is not reachable from the user's `main()`.

### Step 6: Merge

```
User report (findings metadata)
  + Dependency reports (findings metadata)
  ─────────────────────────────────────
  = Merged interim report
```

In this test project, the interesting reachability slices are all rooted in user code findings. Why? Because the user code calls `chacha20poly1305.New` **directly** inside `mypkg/crypto.go` — a file in the user's own module. The crypto usage is already captured as `source: "direct"`. There's no intermediate dependency wrapper that the user calls which *then* reaches crypto.

If the project had a longer chain — e.g. `main → mypkg.Encrypt → someMiddleware.Process → chacha20poly1305.New` where `someMiddleware` is a dependency — then we'd expect a dependency-backed reachability slice to appear in the call graph export.

### Actual Interim Report Output

The final interim report looks like this:

```json
{
  "version": "1.3",
  "tool": {"name": "crypto-finder", "version": "dev"},
  "findings": [
    {
      "file_path": "mypkg/crypto.go",
      "language": "go",
      "cryptographic_assets": [
        {
          "start_line": 13,
          "end_line": 13,
          "match": "aead, err := chacha20poly1305.New(key)",
          "rules": [{"id": "go.xcrypto.chacha20poly1305.aead", "message": "Detected ChaCha20-Poly1305 AEAD usage", "severity": "INFO"}],
          "status": "pending",
          "metadata": {"algorithmFamily": "ChaCha20", "assetType": "algorithm", "...": "..."},
          "source": "direct",
          "finding_id": "a1b2c3d4"
        },
        {
          "start_line": 19,
          "end_line": 19,
          "match": "if _, err := rand.Read(nonce); err != nil {",
          "rules": [{"id": "go.crypto.rand.usage", "message": "Detected cryptographically secure random number generation", "severity": "INFO"}],
          "status": "pending",
          "metadata": {"algorithmFamily": "CSPRNG", "assetType": "algorithm", "...": "..."},
          "source": "direct",
          "finding_id": "a1b2c3d4"
        },
        {
          "start_line": 29,
          "end_line": 29,
          "match": "aead, err := chacha20poly1305.New(key)",
          "rules": [{"id": "go.xcrypto.chacha20poly1305.aead", "message": "Detected ChaCha20-Poly1305 AEAD usage", "severity": "INFO"}],
          "status": "pending",
          "metadata": {"algorithmFamily": "ChaCha20", "assetType": "algorithm", "...": "..."},
          "source": "direct",
          "finding_id": "b2c3d4e5"
        }
      ]
    }
  ]
}
```

The corresponding reachability slices are emitted by the separate call graph export and joined through `finding_id`.

### Visual Summary

```
main.go:14  ──calls──→  mypkg/crypto.go:13  ──calls──→  x/crypto/chacha20poly1305.New
  (main)                  (SecureEncrypt)                   (dependency function)
                                │
                                ├── Finding: chacha20poly1305.New at L13
                                │   source: "direct" (it's in user code)
                                │   exported slice: [[main@L14 → SecureEncrypt@L12]]
                                │
                                └── Finding: rand.Read at L19
                                    source: "direct"
                                    exported slice: [[main@L14 → SecureEncrypt@L12]]

main.go:19  ──calls──→  mypkg/crypto.go:29  ──calls──→  x/crypto/chacha20poly1305.New
  (main)                  (SecureDecrypt)
                                │
                                └── Finding: chacha20poly1305.New at L29
                                    source: "direct"
                                    exported slice: [[main@L19 → SecureDecrypt@L28]]

golang.org/x/crypto/ssh/cipher.go:N  (internal SSH functions)
                                │
                                └── 870 findings with NO call chain
                                    source: "dependency"
                                    → no exported reachability slice
```

---

## Walkthrough 2: Multi-Hop Dependency Chain

The first walkthrough showed a case where user code calls crypto directly, so the useful reachability slices are anchored to direct findings. This second walkthrough uses `testdata/projects/go_with_dep_chain/` to demonstrate a **multi-hop chain** where crypto usage is buried inside a dependency and dependency-backed reachability slices become the interesting artifact.

### The Source Code

The key difference: user code never touches `chacha20poly1305` directly. Instead, it calls through a wrapper dependency (`cryptowrapper_dep/`), which has an internal function layer.

**`main.go`** — entry point, calls `mypkg`:
```go
func main() {
    encrypted, err := mypkg.SecureEncrypt(key, message)  // line 14
    decrypted, err := mypkg.SecureDecrypt(key, encrypted) // line 19
}
```

**`mypkg/crypto.go`** — user code, delegates to the dependency. **No crypto imports.**
```go
import "example.com/cryptowrapper"

func SecureEncrypt(key, plaintext []byte) ([]byte, error) {   // line 15
    encrypted, err := cryptowrapper.Encrypt(key, plaintext)    // line 16
    return encrypted, nil
}

func SecureDecrypt(key, ciphertext []byte) ([]byte, error) {   // line 24
    decrypted, err := cryptowrapper.Decrypt(key, ciphertext)   // line 25
    return decrypted, nil
}
```

**`../cryptowrapper_dep/wrapper.go`** — the dependency (separate module). Has a public API and an internal function:
```go
// Public: called by user code
func Encrypt(key, plaintext []byte) ([]byte, error) {  // line 19
    aead, err := newAEAD(key)                            // line 20 — calls internal fn
    nonce := make([]byte, aead.NonceSize())
    rand.Read(nonce)                                     // line 26 — crypto!
    return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {  // line 36
    aead, err := newAEAD(key)                            // line 37 — calls internal fn
    // ...
}

// Internal: adds depth to the call chain
func newAEAD(key []byte) (cipher.AEAD, error) {          // line 58
    return chacha20poly1305.New(key)                      // line 59 — crypto!
}
```

The intended call chains:
```
main → mypkg.SecureEncrypt → cryptowrapper.Encrypt → cryptowrapper.newAEAD → chacha20poly1305.New
main → mypkg.SecureDecrypt → cryptowrapper.Decrypt → cryptowrapper.newAEAD → chacha20poly1305.New
```

### What the Scan Produces

Running with `--scan-dependencies`:

```
Finding groups: 1    (wrapper.go in the dependency)
Total assets:   2    (both from the dependency, both reachable)
```

Only a small subset of the traced findings produce meaningful exported slices. Deep `x/crypto` and `x/sys` internals may still be scanned and identified, but they do not help downstream stitching unless the graph can connect them back to component-owned or user-owned entry points.

### Tracing the 3-Step Chain

The finding at `chacha20poly1305.New` (line 59 of `wrapper.go`) produces a **3-step chain**. Here's the BFS trace:

```
FindContainingFunction("wrapper.go", 59) → cryptowrapper.newAEAD (lines 58–59)

TraceBack(newAEAD, userPackages={"example.com/dep-chain-test"}):

BFS queue: [ [newAEAD] ]

Iteration 1:
  chain = [newAEAD]
  head  = newAEAD
  Is "example.com/cryptowrapper" a user package?
    → Does it start with "example.com/dep-chain-test/"? NO
  Look up Callers["example.com/cryptowrapper.newAEAD"]
    → ["example.com/cryptowrapper.Encrypt", "example.com/cryptowrapper.Decrypt"]
  Prepend each: push [Encrypt, newAEAD] and [Decrypt, newAEAD] to queue

Iteration 2a:
  chain = [Encrypt, newAEAD]
  head  = Encrypt
  Is "example.com/cryptowrapper" a user package? NO
  Look up Callers["example.com/cryptowrapper.Encrypt"]
    → ["example.com/dep-chain-test/mypkg.SecureEncrypt"]
  Prepend: push [SecureEncrypt, Encrypt, newAEAD]

Iteration 2b:
  chain = [Decrypt, newAEAD]
  head  = Decrypt
  Is "example.com/cryptowrapper" a user package? NO
  Look up Callers["example.com/cryptowrapper.Decrypt"]
    → ["example.com/dep-chain-test/mypkg.SecureDecrypt"]
  Prepend: push [SecureDecrypt, Decrypt, newAEAD]

Iteration 3a:
  chain = [SecureEncrypt, Encrypt, newAEAD]
  head  = SecureEncrypt
  Look up Callers["...mypkg.SecureEncrypt"] → ["...main"]
  Prepend: push [main, SecureEncrypt, Encrypt, newAEAD]

Iteration 3b:
  chain = [SecureDecrypt, Decrypt, newAEAD]
  head  = SecureDecrypt
  Look up Callers["...mypkg.SecureDecrypt"] → ["...main"]
  Prepend: push [main, SecureDecrypt, Decrypt, newAEAD]

Iteration 4a:
  chain = [main, SecureEncrypt, Encrypt, newAEAD]
  head  = main
  Look up Callers["...main"] → [] (no callers — root function)
  Chain reaches user code? YES
  → CHAIN COMPLETE! (4 steps)

Iteration 4b:
  chain = [main, SecureDecrypt, Decrypt, newAEAD]
  head  = main
  → Also a complete chain! (4 steps)
```

BFS found **two** complete chains. Both are stored in `call_chains`:

```json
{
  "source": "dependency",
  "dependency_info": {
    "module": "example.com/cryptowrapper",
    "version": "v0.0.0"
  },
  "finding_id": "c3d4e5f6",
  "call_chains": [
    [
      {"function_name": "main", "namespace": "example.com/dep-chain-test", "file_path": "main.go", "line": 14},
      {"function_name": "SecureEncrypt", "namespace": "example.com/dep-chain-test/mypkg", "file_path": "mypkg/crypto.go", "line": 16},
      {"function_name": "Encrypt", "namespace": "example.com/cryptowrapper", "file_path": "wrapper.go", "line": 20},
      {"function_name": "newAEAD", "namespace": "example.com/cryptowrapper", "file_path": "wrapper.go", "line": 58}
    ],
    [
      {"function_name": "main", "namespace": "example.com/dep-chain-test", "file_path": "main.go", "line": 19},
      {"function_name": "SecureDecrypt", "namespace": "example.com/dep-chain-test/mypkg", "file_path": "mypkg/crypto.go", "line": 25},
      {"function_name": "Decrypt", "namespace": "example.com/cryptowrapper", "file_path": "wrapper.go", "line": 37},
      {"function_name": "newAEAD", "namespace": "example.com/cryptowrapper", "file_path": "wrapper.go", "line": 58}
    ]
  ]
}
```

### Full Trace to `main`

The BFS walks all the way to **root functions** (functions with no callers, like `main`). This means the full chain `main → SecureEncrypt → Encrypt → newAEAD` is preserved. A chain is valid if it passes through at least one user-package function, so chains that only traverse dependency code are discarded.

### Visual Summary

```
main.go:14 → mypkg/crypto.go:16 → wrapper.go:20 → wrapper.go:59
  (main)       (SecureEncrypt)       (Encrypt)        (newAEAD)
     │                │                    │                │
     │ user code      │ user code          │ dependency     │ dependency
     │                │                    │                │
     └── chain starts here (root fn)       │                └── finding: chacha20poly1305.New
                                           │                    source: "dependency"
                                           └── intermediate hop in chain

main.go:19 → mypkg/crypto.go:25 → wrapper.go:37 → wrapper.go:59
  (main)       (SecureDecrypt)       (Decrypt)        (newAEAD)
     │                │                    │                │
     └── chain starts here (root fn)       │                └── same finding, alternate path
                                           └── intermediate hop
```

Key observations:
- **User code has 0 crypto findings** — `mypkg` has no crypto imports
- **2 dependency findings survive** reachability because the call graph proves user code reaches them
- **492 dependency findings dropped** — deep `x/crypto` internals unreachable from user code
- **`main` appears at the head of each chain** — BFS walks to root functions (no callers)
- **Both Encrypt and Decrypt paths preserved** — all chains stored in `call_chains`

---

## Interim Report Contract (v1.3)

Version 1.3 keeps the attribution fields needed to join findings to the separate reachability export. Dependency-backed paths are dependency-root-relative; `dependency_info` remains the canonical place for module and version.

| Field | Type | When Present | Description |
|-------|------|--------------|-------------|
| `source` | `string` | Always (when dependency scanning) | `"direct"` or `"dependency"` |
| `dependency_info` | `object` | Dependency findings only | `{module, version}` |
| `finding_id` | `string` | Always (when dependency scanning) | Short hash (SHA-256) for cross-referencing with the callgraph export |

## Call Graph Export

When `--export-callgraph` is enabled, Crypto Finder emits a finding-centric JSON export that uses the same relative-path convention as the main report.

Schema note: call graph export version `4.3` adds Java runtime provenance in `scan_metadata` for JDK-aware platform signature enrichment.

- Each top-level record stays keyed by `finding_id`, which is the join key back to the interim report.
- `call_chains` is the primary value-flow structure. Each chain is ordered from the first reachable caller to the function that contains the matched crypto call.
- Each chain node contains a fully qualified `function_name`, a normalized `file_path`, `start_line`, optional `dependency_info`, and optional `entry_call`.
- `entry_call` describes how execution entered the current function from the previous step. Its `file_path` and `line` are the call-site location in the previous node's source file.
- The last node in a chain carries `crypto_call`, which is the matched crypto-relevant call that triggered the finding.
- `entry_call.parameters[]` and `crypto_call.parameters[]` both export `parameter_index` (always `0`-based), best-effort `type`, `argument_expression`, `resolved_value`, `variable_name` for simple identifiers only, and recursive `source_nodes`.
- For Java scans, `scan_metadata` may also include `java_requested_jdk_major`, `java_runtime_version`, `java_platform_signatures_used`, `java_platform_signature_source`, and `java_platform_signature_unavailable_reason` to show which JDK major was requested and whether JDK platform signatures were available for enrichment.
- `source_nodes` can now carry interprocedural provenance across wrapper hops, for example `PARAMETER -> PARAMETER -> VALUE`, and propagated nested nodes keep `location.file_path` plus `location.line` when known.
- Method-call expressions are preserved as `CALL_RESULT` nodes instead of flattening away their receivers. When the invoked method can be resolved, the node also exports `call_target`, and receiver provenance stays nested under the `CALL_RESULT` (for example `CALL_RESULT -> PARAMETER alg -> VALUE SignatureAlgorithm.HS256`).
- Findings that cannot be resolved to a containing function or a specific crypto call remain in the export with `finding_location` and `unresolved_reason`.

### Call Chains Ordering

The `call_chains` field in the call graph export contains all traced paths from program entry points to the crypto call site. Each inner array is one complete path, ordered from **program entry point** (index 0) to **crypto call site** (last index). Entry `[i]` calls entry `[i+1]`.

Example:

```json
{
  "finding_id": "69669f02",
  "call_chains": [
    [
      {
        "function_name": "io.jsonwebtoken.jjwtfun.controller.SecretsController.traceToken",
        "file_path": "src/main/java/io/jsonwebtoken/jjwtfun/controller/SecretsController.java",
        "start_line": 33
      },
      {
        "function_name": "io.jsonwebtoken.jjwtfun.service.SecretService.issueTraceToken",
        "file_path": "src/main/java/io/jsonwebtoken/jjwtfun/service/SecretService.java",
        "start_line": 72,
        "entry_call": {
          "file_path": "src/main/java/io/jsonwebtoken/jjwtfun/controller/SecretsController.java",
          "line": 34,
          "parameters": [
            {
              "parameter_index": 0,
              "type": "io.jsonwebtoken.SignatureAlgorithm",
              "argument_expression": "SignatureAlgorithm.HS256",
              "resolved_value": "SignatureAlgorithm.HS256"
            }
          ]
        }
      },
      {
        "function_name": "org.springframework.security.core.token.Sha512DigestUtils.getSha512Digest",
        "file_path": "org/springframework/security/core/token/Sha512DigestUtils.java",
        "start_line": 43,
        "dependency_info": {
          "module": "org.springframework.security:spring-security-core",
          "version": "5.7.11"
        },
        "crypto_call": {
          "function_name": "java.security.MessageDigest.getInstance",
          "line": 45,
          "parameters": [
            {
              "parameter_index": 0,
              "type": "String",
              "argument_expression": "\"SHA-512\"",
              "resolved_value": "\"SHA-512\""
            }
          ]
        }
      }
    ]
  ]
}
```

## Findings Cache

Dependency scanning is dominated by opengrep execution time (~93% of pipeline time). Since `module@version` produces identical scan results with the same ruleset, caching eliminates redundant work entirely. On a second scan with the same dependencies and rules, the dependency scanning phase drops from minutes to near-zero.

### How It Works

The cache sits between Step 2 (rule loading) and Step 3 (parallel scanning) in the pipeline. Before scanning each dependency, `scanSingleDep` checks for a cached result. On a cache miss, the scan runs normally and the result is stored.

```mermaid
flowchart LR
    Dep["module@version"] --> Check{"Cache hit?"}
    Check -->|Yes| Report["Cached InterimReport"]
    Check -->|No| Scan["orchestrator.Scan()"]
    Scan --> Store["Store in cache"]
    Store --> Report
```

### Cache Key Design

The key captures everything that affects scan output:

```
<module>@<version>:<rulesHash>
```

- **Module + version**: e.g., `org.bouncycastle:bcprov-jdk18on@1.78`
- **Rules hash**: First 16 hex chars of SHA-256 over sorted rule file **contents** — if any rule is edited, the cache invalidates automatically

Example: `org.bouncycastle:bcprov-jdk18on@1.78:a3f8b2c1d4e5f678`

The `rulesHash` is computed once per scan (not per-dep), so I/O cost is negligible.

### Storage Layout

The default implementation (`DiskFindingsCache`) stores results as JSON files:

```
~/.scanoss/crypto-finder/cache/findings/
  org.bouncycastle:bcprov-jdk18on@1.78:a3f8b2c1d4e5f678.json
  com.google.guava:guava@33.0.0-jre:a3f8b2c1d4e5f678.json
  golang.org_x_crypto@v0.31.0:a3f8b2c1d4e5f678.json
```

Forward slashes in module paths (e.g., `golang.org/x/crypto`) are replaced with `_` for filesystem safety. Writes use temp file + atomic rename to prevent corruption from interrupted scans.

### `FindingsCache` Interface

```go
type FindingsCache interface {
    Get(ctx context.Context, key string) (*entities.InterimReport, bool, error)
    Put(ctx context.Context, key string, report *entities.InterimReport) error
}
```

The interface accepts `context.Context` on both methods to support network-backed implementations with timeouts and cancellation. The pipeline doesn't know or care which backend is behind the interface.

### Distributed Extensibility

The `FindingsCache` interface is the extension point for multi-node scanning:

| Backend | Implementation | Use Case |
|---------|---------------|----------|
| **Disk** | `DiskFindingsCache` | Single-node, dev workflow |
| **Redis** | `RedisFindingsCache` | Multi-node cluster, shared LAN |
| **S3/GCS** | `S3FindingsCache` | Global fleet, persist across deploys |
| **Two-tier** | `TieredCache{L1: memory, L2: redis}` | Hot + warm layers |

Each just implements `Get`/`Put`. The scanning pipeline is completely agnostic about the storage backend.

---

## Architecture Map

```
internal/
├── cli/scan.go                    # CLI wiring: ecosystem detection, registry setup, pipeline invocation
├── dependency/
│   ├── resolver.go                # Resolver interface + Dependency/ResolveResult types
│   ├── registry.go                # Ecosystem → Resolver registry
│   ├── go_resolver.go             # Go: `go list -m -json all`
│   ├── java_resolver.go           # Java: auto-detect Maven vs Gradle
│   ├── maven_resolver.go          # Java/Maven: `mvn dependency:list/sources/tree`
│   ├── gradle_resolver.go         # Java/Gradle: init-script export via `gradlew` / `gradle`
│   ├── pip_resolver.go            # Python: `pip list` + `pip show`
│   ├── cargo_resolver.go          # Rust: `cargo metadata --format-version=1`
│   └── source_cache.go            # Shared: ZIP/JAR extraction to ~/.crypto-finder/cache/sources/
├── callgraph/
│   ├── types.go                   # FunctionID, FunctionDecl, FileAnalysis, CallGraph types
│   ├── builder.go                 # Parser interface + language-agnostic CallGraph construction
│   ├── parser_registry.go         # Ecosystem → Parser factory (NewParserForEcosystem)
│   ├── go_parser.go               # Go: syntactic parsing of Go source
│   ├── java_parser.go             # Java: syntactic parsing of Java source
│   ├── bytecode_cache.go          # Java: per-artifact bytecode index cache
│   ├── python_parser.go           # Python: syntactic parsing of Python source
│   ├── rust_parser.go             # Rust: syntactic parsing of Rust source
│   └── tracer.go                  # BFS backward tracer with configurable package separator
└── engine/
    ├── dependency_scanner.go      # DependencyScanner: the 6-step pipeline (language-agnostic)
    └── findings_cache.go          # FindingsCache interface + DiskFindingsCache implementation
```

## Supported Ecosystems

The extensible architecture makes adding a new language a matter of implementing two interfaces and registering them. Currently supported:

### Go

- **Resolver**: [`GoResolver`](../internal/dependency/go_resolver.go) — uses `go list -m -json all` to resolve modules
- **Parser**: [`GoParser`](../internal/callgraph/go_parser.go) — syntactic parsing of Go source
- **Manifest**: `go.mod`
- **Module format**: Go import path (e.g., `golang.org/x/crypto`)
- **Package separator**: `/`
- **Source location**: Go module cache (`$GOPATH/pkg/mod/`)

### Java (Maven / Gradle)

- **Resolver**: [`JavaResolver`](../internal/dependency/java_resolver.go) — auto-detects Maven vs Gradle at the project root
- **Parser**: [`JavaParser`](../internal/callgraph/java_parser.go) — syntactic parsing of Java source
- **Manifest**: `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`
- **Module format**: `groupId:artifactId` (e.g., `org.bouncycastle:bcprov-jdk18on`)
- **Package separator**: `.`
- **Source location**: Source JARs resolved by the active build tool and extracted to `~/.scanoss/crypto-finder/cache/sources/`

#### Maven Resolution Details

The `MavenResolver` uses a **three-tier fallback strategy** to maximize dependency recovery, especially for multi-module projects:

**Tier 1 — Reactor with `--fail-never`** (always attempted):
- Runs `mvn dependency:list --fail-never -DappendOutput=true -DincludeScope=compile`
- The `--fail-never` flag continues past module failures; `-DappendOutput=true` accumulates results from all succeeding modules into a single output file
- If some modules resolve successfully, their dependencies are collected even if other modules fail

**Tier 2 — Per-module resolution** (if Tier 1 yields zero dependencies on a multi-module project):
- Detects modules from `<modules>` in the parent `pom.xml`
- Runs `mvn dependency:list -pl <module>` for each module independently
- Modules that fail are skipped; dependencies from succeeding modules are deduplicated and collected

**Tier 3 — Local install + retry** (if Tier 2 yields zero dependencies and inter-module failure is detected):
- Runs `mvn install -DskipTests --fail-never` to build all modules locally, populating `~/.m2/repository` with inter-module artifacts
- Retries Tier 1 after install
- This is expensive (requires compilation) but is the only way to resolve inter-module transitive dependencies

After dependency listing, the resolver also runs:
- **`mvn dependency:sources`** — downloads `-sources.jar` files to `~/.m2/repository/` (best-effort; ~65% of Java libraries publish source JARs)
- **`mvn dependency:tree --fail-never -DappendOutput=true`** — builds the dependency graph adjacency list (best-effort)

Dependencies without source JARs are included in the resolution results but without a source directory. They are skipped for source scanning and logged explicitly; if the compiled artifact is present in `~/.m2/repository`, Java bytecode indexing can still use it as a type-only dependency.

#### Gradle Resolution Details

The `GradleResolver` asks Gradle itself for a machine-readable dependency model via a temporary init script:

- Prefers `./gradlew` and falls back to `gradle` from `PATH`
- Resolves the main Java compile classpath for single-project and multi-project builds
- Treats included Gradle subprojects as `WorkspaceMembers` rather than external dependencies
- Captures external module coordinates, versioned dependency edges, compiled JAR paths, and best-effort source archive paths
- Reuses the shared source extraction cache so Gradle and Maven dependencies flow through the same Java scanning pipeline

#### Multi-Module Project Support

Multi-module Maven projects (parent POM with `<modules>`) are automatically detected. When detected:
- All modules are registered as `WorkspaceMembers`, meaning they are treated as **user code** for call chain tracing (same as Cargo workspace members)
- The `WorkspaceMember.Name` follows the format `groupId:moduleDirName`
- The three-tier fallback strategy handles common multi-module failures:
  - **Inter-module dependencies** (e.g., `eladmin-logging` depends on `eladmin-common`) — resolved via Tier 3
  - **HTTP mirror blocks** (Maven 3.8.1+ blocks insecure HTTP repositories) — partial results collected via Tier 1
  - **Missing parent POMs** or private repositories — gracefully degraded via Tier 1/2

#### Java Call Resolution

The `JavaParser` resolves method calls through import analysis:

1. **Explicit imports**: `import javax.crypto.Cipher;` → `Cipher.getInstance(...)` resolves to package `javax.crypto`
2. **Wildcard imports**: `import java.security.*;` → class names matched against wildcard packages
3. **Local variable types**: `Cipher c = Cipher.getInstance(...)` → `c.doFinal()` resolves `c` to type `Cipher` via local variable tracking
4. **Field types**: Class fields are tracked similarly to local variables
5. **Fallback**: Unresolved calls default to the current package (same as Go's behavior for unresolved variables)

### Python (pip)

- **Resolver**: [`PipResolver`](../internal/dependency/pip_resolver.go) — uses `python -m pip list --format=json` + `python -m pip show` to resolve packages with the same interpreter used for metadata lookups
- **Parser**: [`PythonParser`](../internal/callgraph/python_parser.go) — syntactic parsing of Python source
- **Manifests**: `pyproject.toml`, `requirements.txt`, `Pipfile`, `setup.py`
- **Module format**: Python package name (e.g., `cryptography`)
- **Package separator**: `.`
- **Source location**: Site-packages directory (e.g., `~/.local/lib/python3.x/site-packages/`)

#### Python Resolution Details

The `PipResolver` executes the following steps:

1. **Root module detection** — reads `pyproject.toml` for `[project] name`, falls back to directory name
2. **`python -m pip list --format=json`** — lists all installed packages with versions
3. **`python -m pip show <packages>`** — gets location and dependency info for each package (batched in groups of 50)
4. **Distribution-to-import mapping** — uses that SAME interpreter's `importlib.metadata.packages_distributions()` (Python 3.10+) to map distribution names to import names. Falls back to scanning `*.dist-info` directories (`top_level.txt` → `RECORD` file) for older Python versions
5. **Package directory resolution** — uses the import mapping, then heuristic name normalization, to find the source directory. Single-file modules (e.g., `six.py`) and C-extension packages are skipped

#### Python Call Resolution

The `PythonParser` resolves calls through import analysis:

1. **`import X`**: `X.func()` resolves `X` via imports
2. **`from X import Y`**: `Y()` resolves to package `X`, treated as constructor `Y.<init>()`
3. **Chained attributes**: `a.b.c.func()` — first segment resolved via imports, rest chained
4. **`self` calls**: `self.method()` resolves to the current package
5. **Wildcard imports**: `from X import *` recorded for fallback resolution
6. **Aliased imports**: `import X as Y` — `Y` maps to `X`
7. **Fallback**: Unresolved calls default to the current package

### Rust (Cargo)

- **Resolver**: [`CargoResolver`](../internal/dependency/cargo_resolver.go) — uses `cargo metadata --format-version=1`
- **Parser**: [`RustParser`](../internal/callgraph/rust_parser.go) — syntactic parsing of Rust source
- **Manifest**: `Cargo.toml`
- **Module format**: Crate name (e.g., `ring`)
- **Package separator**: `::`
- **Source location**: Cargo registry cache (e.g., `~/.cargo/registry/src/.../<crate>-<version>/`)

#### Rust Resolution Details

The `CargoResolver` runs `cargo metadata --format-version=1` which provides:

1. **All packages** with name, version, and manifest path
2. **Resolve graph** with dependency edges between packages
3. **Workspace detection** — packages with `source: null` (local/workspace crates) are treated as user code; all others are dependencies

Workspace members are identified as user code, so multi-crate workspaces are handled correctly — all workspace crates are considered "user code" for reachability analysis.

#### Rust Call Resolution

The `RustParser` resolves calls through `use` declaration analysis:

1. **Scoped identifiers**: `Aead::new(...)` — resolves `Aead` through `use` imports
2. **Qualified paths**: `ring::aead::new(...)` — first segment resolved via imports
3. **Scoped use lists**: `use ring::aead::{Aead, AeadCore}` — each item registered separately
4. **Wildcard use**: `use ring::aead::*` recorded for fallback resolution
5. **`self` calls**: `self.method()` resolves to the current module
6. **`src/` transparency**: The `src/` directory is transparent in module paths (e.g., `ring/src/aead/` → `ring::aead`, not `ring::src::aead`)
7. **Impl blocks**: Methods in `impl Type { fn method() {} }` are extracted with their type association
8. **Fallback**: Unresolved calls default to the current module

### Adding a New Language

To add support for a new ecosystem:

1. **Implement `callgraph.Parser`** — with syntactic parsing for the target language
2. **Implement `dependency.Resolver`** — shells out to the ecosystem's package manager
3. **Register the parser** in [`parser_registry.go`](../internal/callgraph/parser_registry.go) — add one `case`
4. **Register the resolver** in [`scan.go`](../internal/cli/scan.go) — add one `depRegistry.Register()` call
5. **Add manifest detection** in `detectEcosystem()` — add one `if` checking for the manifest file

No changes needed to: `builder.go`, `tracer.go`, `dependency_scanner.go`, entities, or schemas.

## Performance

### Two-Phase Call Graph Build

The call graph build is the most expensive step in the dependency scanning pipeline. To minimize cost while preserving 100% type resolution accuracy, the builder uses a **two-phase approach**:

**Phase 1 — Source parsing (targeted):** Only dependencies with crypto findings + user code modules get full source parsing via `Parser.ParseDirectory()`. This builds `FunctionDecl` entries with call sites, parameters, and return types.

**Phase 2 — Bytecode type indexing (comprehensive):** ALL dependencies (including those without findings) are indexed via `JavaBytecodeTypeResolver`. This reads `.class` files from Maven JARs to extract class names, method signatures, return types, and interface hierarchy. The type index is used to resolve fluent chains and enrich parameter types across dependency boundaries.

**Why both phases are needed:** Java fluent APIs (e.g., `Jwts.builder().signWith(key)`) require knowing return types from one dependency to resolve calls in another. A dependency without crypto findings may define the return type that bridges a call chain from user code to a crypto finding. Skipping its type information would break backward tracing.

#### Benchmarks (eladmin — 160 deps, 27 with findings, 269 crypto assets)

Current warm-run numbers with findings cache + Java bytecode cache enabled:

| Metric | Current |
|--------|---------|
| Packages source-parsed | 32 |
| Functions in graph | 168,386 |
| Caller index entries | 190,688 |
| Bytecode type packages | 165 |
| JARs indexed | 160 |
| Bytecode cache hits | 157 |
| Bytecode resolution duration | ~1.27s |
| Full dependency pipeline | ~33.0s |
| Wall time | ~44.0s |
| Findings | 269 |
| Exported call graph edges | 498,271 |

The largest recent improvements came from three changes:

- **Two-phase call graph build**: only findings-bearing dependencies get full source parsing
- **Parallel Java JAR indexing**: exact-version JARs are indexed concurrently
- **Per-artifact bytecode cache**: repeated scans avoid reparsing unchanged JARs

### Current Bottlenecks

The pipeline has three main time consumers:

1. **Source parsing for graph packages** (~23s on warm `eladmin`): Parses `.java` files from 32 packages (user code + 27 deps with findings) to build 168K function declarations with call sites.

2. **Dependency scanning with opengrep**: Still dominates cold scans. On warm scans most dependencies hit the findings cache; on first scans the cost depends on dependency source size and worker count (`--dep-workers`).

3. **Call graph post-processing** (~2-3s): Caller index construction, bytecode merge/rewrite, and fluent-chain resolution are no longer dominant but still scale with graph size.

### Future Optimization Opportunities

#### Source parsing and graph size reduction

The bytecode resolution bottleneck has largely been removed. Remaining performance opportunities are now upstream:

- **Reduce graph packages further**: Keep shrinking the set of dependencies that require full source parsing without breaking attribution accuracy.
- **Smarter pre-scan eligibility**: Skip dependencies that have source directories but no scannable files before invoking opengrep.
- **Containing-function lookup index**: `Tracer.FindContainingFunction()` still scans functions linearly; indexing by file could cut repeated lookups on large reports.
- **Selective bytecode indexing**: Only index JARs whose types appear in unresolved calls from graph packages. More complex, but now one of the few remaining bytecode-side wins.

#### Opengrep scanning

- **Result caching**: The existing `DiskFindingsCache` caches dependency scan results by `module@version:rulesHash`. On repeated scans of the same project, most dependencies hit the cache.
- **Cold-scan throughput**: First-scan performance still depends heavily on opengrep throughput over large dependency sources.

#### Call graph export

- **Export is fast** (~10-15s for 269 findings) and not currently a bottleneck. The finding-centric export only traces paths reachable from findings, producing a compact JSON (~9.5K lines for eladmin) regardless of full graph size.

## Limitations

### General
- **Static analysis** — The call graph is built from syntactic call expressions. It cannot resolve interface dispatch, reflection-based calls, or function values passed as arguments.
- **All paths stored** — When multiple call chains exist (BFS finds all paths), all are stored in `call_chains`. This ensures no reachability information is lost.

### Go-specific
- **No cross-module method resolution** — Method calls on variables (e.g., `cipher.Encrypt()`) are recorded with the variable name as the type, not the resolved type. Cross-package type resolution would require full type analysis.

### Java-specific
- **Gradle source archives are best-effort** — Gradle dependency resolution provides binary artifact paths deterministically, but source archive availability still depends on what upstream repositories publish.
- **Missing source JARs** — Dependencies without sources are skipped for source scanning, but they can still contribute Java bytecode types if the compiled JAR is present locally. They cannot produce source-level findings until sources are available.
- **Wildcard import resolution** — When multiple wildcard imports could match a class name, resolution is best-effort.
- **No inheritance/polymorphism** — Variable types are tracked syntactically; interface implementations and subclass overrides are not resolved.
- **Multi-module Maven partial resolution** — Multi-module Maven projects are supported via a three-tier fallback strategy. Tier 3 (`mvn install -DskipTests`) requires compilation and may fail if the project needs specific JDK versions or build tools not available in the scan environment.

### Python-specific
- **Requires a Python interpreter with `pip` available** — The resolver now runs `python -m pip` and `importlib.metadata` through the same interpreter. If `VIRTUAL_ENV` is set, that environment's Python is preferred; otherwise it falls back to `python3` then `python` from PATH.
- **Single-file modules skipped** — Packages distributed as a single `.py` file (e.g., `six.py`) are skipped since there is no directory to scan.
- **C-extension packages skipped** — Packages without Python source on disk (compiled C extensions) cannot be scanned.
- **Distribution-to-import mapping** — Relies on `importlib.metadata` (Python 3.10+) or `*.dist-info` fallback; packages with non-standard layouts may not be resolved.
- **No dynamic dispatch** — Calls resolved through `getattr`, `__getattr__`, or metaclass magic are not tracked.

### Rust-specific
- **Requires `cargo` in PATH** — The resolver shells out to `cargo metadata`.
- **No trait dispatch** — Method calls on trait objects (e.g., `dyn Cipher`) are resolved syntactically by type name; trait implementations are not followed.
- **Macro-generated code** — Functions generated by macros (e.g., `proc_macro`) are invisible to syntactic parsing.
- **`src/` transparency assumption** — The parser assumes `src/` is the crate root; non-standard `[lib] path` configurations may produce incorrect module paths.
