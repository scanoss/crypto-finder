# node-callgraph-identity-resolution Specification

## Purpose

Node/JavaScript call-site identity resolution in
`internal/callgraph/node_parser.go`: how a declared function acquires the
`Package`, `Type` and `Name` segments of its `FunctionID`, and which syntactic
shapes bind a call to a containing function, so that a finding carries
reachability instead of `unresolved_reason: no_containing_function`.

One parser serves `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts` and
`.cts`, selecting the `javascript`, `typescript` or `tsx` tree-sitter grammar
per file.

**The governing rule of this capability is that two functions must never share
one identity.** A missing construct loses a detection; a collision returns a
WRONG answer — one function's file path, span and call set stand in for
another's, and the loser is reported as having no containing function at all.
Nothing downstream can detect the substitution, because the key it was given is
well formed.

Out of scope: the rule layer (which patterns match a call), the Node contract
knowledge base, and TypeScript type inference.

## Requirements

### Requirement: A function's identity is scoped to its module, not its directory

The `Package` segment MUST identify the file that declares the function, not
the directory that contains it. Two files in one directory declaring a
same-named function MUST produce two functions with distinct keys.

The file's extension MUST be dropped, so that `a.js`, `a.ts` and `a.tsx` are one
module — which is what a Node resolver does. A file directly in the package root
MUST yield the package path unchanged, so single-file packages keep their key.

#### Scenario: Same-named functions in one directory keep distinct identities

- GIVEN `src/alpha.js` and `src/beta.js`, each with `export function hash(d)`
- WHEN the parser resolves both files
- THEN exactly two functions MUST be emitted, with different identity keys
- AND neither file may come back `no_containing_function`
- Pinned by: `TestNodeParser_SameNamedFunctionsInOneDirectoryKeepDistinctIdentities`

#### Scenario: A dotfile does not adopt its parent directory's key

- GIVEN `a/b.js` and `a/b/.js`, where trimming the extension would leave an empty base
- WHEN the parser resolves each, driven one directory at a time as the builder drives it
- THEN the two MUST NOT share an identity
- Pinned by: `TestNodeParser_DotfileModuleDoesNotCollideWithItsParentDirectory`

### Requirement: A method binds a containing function wherever it is written

A method MUST bind a containing function in every position JavaScript allows one,
not only inside a `class_declaration`. This covers at least a class expression
assigned to a binding, a shorthand method in an object literal, and a class field
initialiser.

A field initialiser has no method of its own to belong to, so its calls MUST be
attributed to one synthetic per-class initialiser function, following the
precedent already set for Java in `java_parser.go:parseClassInitDecl`. Its span
covers the class body; because a containing function is chosen by tightest span,
a call inside a real method still resolves to that method and not to the
initialiser.

#### Scenario: Methods outside class declarations bind a function

- GIVEN a class expression bound to a `const`, a shorthand method in an object
  literal, and a class field initialiser, each containing a crypto call
- WHEN the parser resolves each
- THEN each MUST bind a containing function
- Pinned by: `TestNodeParser_MethodsOutsideClassDeclarationsBindAFunction`

### Requirement: The grammar matrix is a committed measurement, with unique names

The set of constructs that can sit between a crypto call and its containing
function MUST be pinned as a test, one file per construct, each carrying the SAME
call so that only the construct varies.

Every probe's function name MUST be unique, and the test MUST ASSERT that
uniqueness. This is not hygiene. The first run of this matrix reported 2 of 23
constructs resolving; that number was wrong and is retracted. Every probe had
named its function `f`, identity was keyed on the directory, and all 23 collapsed
onto one key. The contradiction that exposed it was byte-identical code resolving
in one run and not in another. A duplicated name MUST fail the test rather than
silently shrink what it measures.

#### Scenario: Every construct in the matrix binds a containing function

- GIVEN 23 single-construct probes, each carrying `crypto.createHash(..).update(d).digest(..)`
- WHEN the parser resolves them
- THEN each MUST bind a containing function
- AND no two emitted identities may be equal
- Pinned by: `TestNodeParser_GrammarMatrixBindsAContainingFunction`

## Known gaps

These are measured shortfalls, not decisions.

### The static node-type inventory is not a gap list

The inventory is read from the `parser.c` that crypto-finder itself compiles —
`go-tree-sitter@v0.0.0-20240827094217`, not an upstream repo — so it is exactly
the grammar in play. Counting the distinct names in `ts_symbol_names[]`, skipping
hidden `sym__*` internals and anonymous token symbols:

| grammar | distinct named node types |
|---|---|
| javascript | **117** |
| typescript | 184 symbols |
| tsx | 195 symbols |

`node_parser.go` names **28** of the 117 literally.

An earlier draft of issue #478 reported 170 and 268. Those figures are retracted:
no counting rule over this `parser.c` reproduces them, and 268 is suspiciously
one off the 269 TOTAL entries in the JavaScript table, which suggests the
JavaScript total was mislabelled as TypeScript. The numbers above come with the
rule that produces them so the next reader can re-derive rather than trust them.

That 89-name difference is NOT 89 missing constructs, and reading it as one is
the error this paragraph exists to prevent. The parser walks most node types
generically without naming them. Measured: of 23 probes, **19 already resolved on
the unmodified parser**, including many the static list implied were missing —
`namespace_import`, `await_expression`, `optional_chain`,
`assignment_expression`, `augmented_assignment`, `catch_clause`,
`for_in_statement`, `labeled_statement`, `spread_element`, `template_string`,
`yield_expression`, object-literal values, `array_pattern`,
`assignment_pattern`, `rest_pattern`, `export_statement` and arrow functions.

Only the three shapes in the second requirement failed at the parser. A future
inventory diff must be measured the same way before it is called a gap.

### `crypto['createHash'](..)` matches no rule — RULE LAYER, not the parser

A computed member access is reported by no rule, so the call never reaches the
callgraph to begin with. The parser binds its containing function correctly; the
matrix's `computed_member_access` row asserts exactly that, so this gap cannot
later be misdiagnosed as a parser defect. Closing it is rule work, deliberately
outside this change.

### No Node library has ever been contracted

`internal/callgraph/contracts/node/` holds a single `bootstrap.yaml` with
`contracts: []`, whose own comment reads *"remove this file when the first Node
library KB lands."* Identity resolution is a precondition for contracts, not a
substitute: until a Node KB exists, these keys are correct and match nothing.
This is the reason the parser pass comes before any Node family, and it is the
next piece of work, not a defect in this one.

### A dotfile named exactly its extension collided with its parent — CLOSED

`a/b.js` and `a/b/.js` both keyed `a/b`: dropping the extension from the base
`.js` emptied it, and the empty base fell back to the package path, which for the
subdirectory IS `a/b`. Measured by driving `ParseDirectory` once per directory the
way `builder.go` does, not hypothesized. Closed by keeping the name whenever the
extension is the whole of it (`TestNodeParser_DotfileModuleDoesNotCollideWithItsParentDirectory`).
Degenerate input, but it was a wrong answer of exactly the class this capability
exists to prevent, so it is fixed rather than documented.

## Decisions deliberately not implemented

### Resolving a receiver's type

Node identities carry `Type` only where a class or object owner is syntactically
present. No attempt is made to infer the type of a receiver from its binding, as
`rust_type_semantics.go` does for Rust. That inference is worth building only
once a Node KB exists to be matched against, and building it earlier would mean
tuning it against nothing.

### Naming the synthetic initialiser anything Node-specific

The per-class field initialiser reuses the existing `clinitMethodName` constant
rather than inventing a JavaScript spelling. One synthetic name across languages
keeps every downstream consumer — export, join, contract match — indifferent to
which parser produced it.
