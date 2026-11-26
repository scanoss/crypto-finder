# Dependency scanning

`crypto-finder scan --scan-dependencies` reports the cryptography inside the
project's pinned dependencies, and whether the project reaches it. Online (the
default), the SCANOSS API answers for every dependency in one request; nothing
is downloaded and no dependency source is scanned on your machine.
Dependencies the API has no data for are analysed locally. `--offline` does
everything locally.

## Quick path

```bash
crypto-finder scan --scan-dependencies \
  --export-callgraph callgraph.json \
  --output findings.json ./service
```

Expected:

- `findings.json` holds first-party findings (`source: direct`) and
  dependency findings (`source: dependency`, with `dependency_info`).
- `callgraph.json` gives each finding a verdict in
  `finding_graphs[].reachability`: `reachable`, `unreachable` or `unknown`
  (with an `unresolved_reason`), and its call chains.
- With `--progress`, the completed `dependencies` event counts what was
  answered and lists what was skipped, with a reason (`deps_skipped_list`).

## Ecosystems

| Ecosystem | Reads | Needs |
|---|---|---|
| Java | Maven (`pom.xml`) or Gradle build | `mvn` or `gradle` (`./gradlew` when present), a JDK |
| Python | A lock (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `pylock.toml`), fully pinned requirements, or an installed environment | Nothing: files only |
| Go | `go.mod` | The Go module cache for typing; nothing is downloaded |
| JavaScript, TypeScript | `npm-shrinkwrap.json`, `package-lock.json` (lockfile version 2 or 3), `pnpm-lock.yaml` or `yarn.lock` | Nothing: files only |
| Rust | `Cargo.lock` | `cargo` on the `PATH` |
| Ruby | `Gemfile.lock` | Nothing: files only |
| C# | `packages.lock.json`, `project.assets.json` or `packages.config` | Nothing: files only, no restore |

Each resolver looks at the scan root and at module roots below it, and merges
what it finds. A target with nothing to resolve skips the dependency phase
(`dependencies` `skipped`, reason `manifest_absent` or
`ecosystem_not_supported`).

## How it works

1. **Resolve** the pinned dependency closure, with each dependency's `direct`
   flag and the dependencies it requires.
2. **Build the project's call graph once.** For Java the closure's compiled
   JARs type it (type information only, never scanned), so calls into a
   dependency carry exact targets. Detection and every export share this one
   graph.
3. **Ask.** One `POST /v3/cryptography/reachability/application` sends the
   closure and the project's calls into it ([what is sent](CLIENT_SERVER.md#what-a-dependency-scan-sends-and-receives)).
   Only calls from functions the project's entry points reach are sent, so a
   dependency called only from dead code is not reported as reachable.
4. **Merge** the answer. Each dependency finding joins the report with
   `source: dependency`, `dependency_info`, a path relative to the dependency,
   and a `finding_id` built from its coordinates. First-party findings are
   traced locally.

SCANOSS analyses published dependency versions ahead of time. For a version it
has not analysed, the API answers without data (reason
`no_reachability_data`), and crypto-finder analyses that dependency locally
with the `--offline` path. `--no-offline-fallback` turns this off: those
dependencies are then left out of the report. Details and failure handling:
[OFFLINE.md](OFFLINE.md#online-scans-the-offline-fallback).

A response with no dependency data fails the scan with
`dependency_resolution_failed`.

### Precision details

- **Factories.** On a Java call whose receiver is a local variable assigned
  once from a dependency function (`Hasher h = Hashers.standard(); h.sum(data);`),
  the verdict follows what the factory builds. When every `return` builds the
  same class with `new`, only that class's method is reached; otherwise the
  verdict stays `unknown` (`ambiguous_dispatch`).
- **Service loaders.** A call on a Java service type reaches the classes
  registered for it in `META-INF/services`. Other reflection is not followed.
- **Values passed between dependencies.** The request carries the ruleset's
  parameter-conditioned rules, so a generic finding in one dependency is
  specialized by the value another dependency passes it (for example an
  algorithm name).

## Java

- **Maven.** `mvn dependency:list` and `mvn dependency:tree` list the closure;
  each dependency's compiled JAR comes from the local repository.
  `settings.xml`, `MAVEN_OPTS` and `.mvn/maven.config` apply.
- **Gradle.** `./gradlew`, else `gradle`, reports the compile and runtime
  classpaths through a temporary init script. Included subprojects are the
  project, not dependencies.
- **Scopes.** The closure is the application's compile and runtime classpath
  (Maven `compile`, `provided`, `system`, `runtime`; Gradle
  `compileClasspath`, `runtimeClasspath`). Test dependencies are left out.
- **Application code** is the set of packages the project's own sources
  declare, every module included. A dependency that shares the project's
  groupId stays a dependency.
- **Repository code runs.** `mvn` and `gradle` can execute code the
  repository controls (plugins, extensions). Scan untrusted repositories in a
  sandbox, such as the `latest-deps` image with no credentials mounted.

## Python

- Resolved from files only: no pip, Python or build backend runs. The first
  of: a lock, requirements where every requirement is pinned with `==`, the
  installed environment (`.venv`, `venv`, then `VIRTUAL_ENV`), and the
  declared requirements. An installed environment completes a pinned list
  with what its packages require.
- Every environment-marker branch is in the closure; each dependency keeps its
  `markers` and `extras` on `dependency_info`. Development dependencies are
  left out.
- A requirement without a pin is not requested: `deps_skipped_list` lists it
  with reason `unpinned`.
- Package URLs are `pkg:pypi/<PEP 503 name>`; versions are read in PEP 440
  normal form.
- `--type-packages` types the project's calls with installed packages, read as
  data.

## Go

- Resolved from `go.mod` alone: every requirement at its version, direct
  unless `// indirect`, after `replace`. A `go.mod` older than Go 1.17 warns
  that the closure may be partial.
- A local replacement is the project's own code and is listed as `unpinned`.
- Calls are typed by the standard library of the installed Go toolchain and
  by the modules the module cache holds. A call into a module missing from the
  cache is resolved by name only, so what it reaches reads `unknown`, never
  `unreachable`. Run `go mod download` first.
- Package URLs are `pkg:golang/<module path>`.

## JavaScript and TypeScript

- Every package the lock pins, at its version. Workspace members of a monorepo
  are the project; dev-only packages are left out.
- A package locked at several versions is requested once, at the version the
  project loads (the copy at the top of `node_modules`, else the one a
  `package.json` declares, else the most depended on, else the highest). The
  others are in `deps_skipped_list` with reason `other_version_requested`, and
  a package only they require with reason `under_other_version`.
- A package pinned to a git, tarball or path source is `unpinned`.
- A lockfile version 1 (npm 6) skips its module root with a warning; with only
  version 1 locks, npm dependencies are skipped with reason
  `unsupported_lockfile`. Regenerate the lock with npm 7 or later. A target
  with only a `package.json` skips the phase (`manifest_absent`).
- Package URLs are `pkg:npm/<name>`, `pkg:npm/%40<scope>/<name>`.

## Rust

- `cargo metadata --format-version 1 --locked` reads `Cargo.lock` as it is;
  the lock is never updated. A `Cargo.toml` without `Cargo.lock` skips the
  phase (`manifest_absent`): run `cargo generate-lockfile` and commit it.
- Only the production closure is requested. Dev-dependencies and
  build-dependencies are left out.
- Workspace members and path dependencies are the project. A git dependency
  is `unpinned`; its registry dependencies are still requested.
- A crate locked at several versions is requested once, at the version a
  workspace member declares (else the highest), as for npm.
- `cargo` runs in the target directory, so its `.cargo/config.toml` applies.
  Online, it may fetch crates that are not cached; with `--offline` it never
  reaches a registry.
- Package URLs are `pkg:cargo/<name>`.

## Ruby

- Resolved from `Gemfile.lock` only, the exact versions Bundler resolved. A
  `Gemfile` alone states ranges and is not read: the phase is skipped
  (`manifest_absent`).
- With `--offline`, a gem is analysed from its installed source,
  `$GEM_HOME/gems/<name>-<version>`.

## C#

- Resolved from the files that carry a resolved version, in this order:
  `packages.lock.json`, `project.assets.json` (written by every restore), and
  the `packages.config` of a .NET Framework project. Nothing is restored. A
  `PackageReference` in a project file states a minimum, not a version, and is
  not read.
- With `--offline`, packages come from the local NuGet cache
  (`NUGET_PACKAGES`, else `~/.nuget/packages`). NuGet packages ship
  assemblies, not source, so a package often has nothing to analyse: it is
  still listed, with reason `no_reachability_data`.

## Skip reasons

| `deps_skipped_list` reason | Meaning |
|---|---|
| `no_reachability_data` | No data from the API, and the local fallback could not answer (or was off) |
| `unpinned` | No pinned registry version to ask for |
| `other_version_requested` | Another version of the same package was requested |
| `under_other_version` | Only required by a version that was not requested |

## Related

- [OFFLINE.md](OFFLINE.md): local analysis, its cache and flags
- [CLIENT_SERVER.md](CLIENT_SERVER.md): exactly what is sent and received
- [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md): report and call graph fields
- [KNOWN_LIMITS.md](KNOWN_LIMITS.md): what reads `unknown`, and why
