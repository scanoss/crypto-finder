# rust-callgraph-manifest-resolution Specification

## Purpose

Cargo manifest reading in `internal/callgraph/rust_manifest.go`: dependency
renames, workspace inheritance, `extern crate` aliases, per-directory crate
re-export aliases, and the declared-dependency set that
`rust-callgraph-identity-resolution` uses as evidence. Manifests are parsed with
`github.com/pelletier/go-toml/v2`.

A manifest may bind a dependency to a name other than the crate it resolves to.
Without reading it, every call written through that name carries a package that
names no crate and no contract can match — with no signal that the surface was
lost. The manifest is also the only evidence available for two negative rules:
that a path segment is not a crate, and that a name is not a dependency.

Out of scope: dependency resolution and version selection
(`internal/dependency`), and the KB YAML.

## Requirements

### Requirement: Dependency renames resolve to the real crate

A `package = "..."` key in any dependency table MUST be read, and calls written
through the binding name MUST carry the real crate's identity. Renames MUST be
read from every dependency table, including the target-specific and
dev-dependency tables.

#### Scenario: A renamed dependency resolves to its crate

- GIVEN `[dependencies.ffi]` with `package = "openssl-sys"`, as openssl 0.10.81 declares it
- WHEN the parser resolves a call written `ffi::EVP_sha256()`
- THEN it MUST carry the package `openssl_sys`, so `openssl-sys.yaml` matches
- Pinned by: `TestRustParser_ManifestDependencyRenamesResolveToTheRealCrate`

#### Scenario: A local module beats the rename

- GIVEN a crate declaring both `[dependencies.codec] package = "des"` and its own `mod codec`
- THEN the local module MUST win, and the DES contract MUST NOT match
- Pinned by: `TestRustParser_LocalModuleBeatsAManifestRename`

### Requirement: Workspace inheritance is resolved, and the member wins

A member declaring `workspace = true` MUST inherit the rename from the
workspace root's `[workspace.dependencies]`. A rename declared by the member
itself MUST take precedence over the workspace's.

#### Scenario: An inherited rename resolves

- GIVEN `[workspace.dependencies] ffi = { package = "openssl-sys" }` and `ffi = { workspace = true }` in the member
- THEN a call through `ffi` MUST carry `openssl_sys`, whether the scan is rooted at the member or at the workspace root
- Pinned by: `TestRustParser_WorkspaceInheritedRenameResolves`

#### Scenario: The member's own rename wins

- Pinned by: `TestRustParser_MemberRenameWinsOverTheWorkspaceRename`

### Requirement: `extern crate` aliases are crate-wide

A crate-root `extern crate y as x;` MUST be visible to every file of the crate,
matching the language's own scoping. A plain `extern crate x;` MUST be reachable
through `self::x::..`, as edition-2015 code writes it, and a
`use crate::<extern-alias>::<item>;` MUST resolve the alias.

#### Scenario: A crate-root alias reaches sibling files

- Pinned by: `TestRustParser_CrateRootExternCrateAliasIsVisibleToSiblingFiles`, `TestRustParser_ExternCrateRenameResolvesCrateIdentity`, `TestRustParser_PlainExternCrateIsReachableThroughSelf`, `TestRustParser_ExternCrateWithoutRenameKeepsCratePath`, `TestRustParser_CrateRootedPathResolvesAnExternAlias`

### Requirement: Crate re-export aliases resolve per directory

A `pub(crate) use <crate> as <alias>;` MUST be resolvable from sibling files in
the same directory. The alias MUST be resolved per DIRECTORY rather than
crate-wide, because a crate may declare the same alias once per backend and a
crate-wide table would have to call that ambiguous.

#### Scenario: An alias declared in one file reaches its siblings

- GIVEN rustls 0.23.20's `pub(crate) use ring as ring_like;` reached as `use super::ring_like::aead;` from the backend files beside it
- THEN the calls MUST carry the `ring` crate identity
- AND because rustls declares the alias twice, once per backend, the two directories MUST resolve independently
- Pinned by: `TestRustParser_CrateReExportAliasResolvesFromSiblingFiles`

### Requirement: A crate alias is seeded only from the manifest and `extern crate`

The crate-alias table MUST be seeded only from manifest renames and
`extern crate` declarations. A `type` alias MUST NOT be treated as a crate
alias, because a blanket check over the import table catches type aliases and
strips their crate.

#### Scenario: A bare type alias keeps its crate

- Pinned by: `TestRustBareTypeAliasCarriesItsCrate`, `TestRustParser_TypeAliasChainsResolveTransitively`

### Requirement: The declared-dependency set is available as evidence

The set of dependency names the manifest declares MUST be available to identity
resolution, so a segment that is neither a declared dependency nor the standard
library can be refused as a crate.

#### Scenario: No manifest degrades gracefully

- GIVEN a source tree with no `Cargo.toml` anywhere above it
- THEN the parser MUST still resolve what it can, and MUST NOT claim a
  glob-supplied name whose local declaration it cannot see
- AND a dependency the manifest omits MUST NOT lose its identity
- Pinned by: `TestRustParity_ParserInferenceAndGracefulDegradation`, `TestRustParser_GlobDoesNotClaimNamesWithoutCrateVisibility`

#### Scenario: A cargo-resolved dependency's source root is its manifest directory

- GIVEN dependency scanning enabled
- THEN the directory containing a dependency's manifest MUST be treated as its crate root
- Pinned by: `TestRustCrateIdentifier`, `TestRustParser_SubPackagePath`
