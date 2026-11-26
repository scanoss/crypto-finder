# Known limits

What crypto-finder does not do, or does not decide, and how each limit
shows up in the output. Read this before treating a missing finding as "no
cryptography" or an `unknown` verdict as an error.

## Summary

| Limit | Shows up as | Workaround |
|---|---|---|
| Java, Python, Go, JavaScript, TypeScript, Rust, Ruby, C, C++ and C# only | `language_not_supported` (exit 1) for a target only in other languages | — |
| Python and JavaScript verdicts often `unknown` | `unresolved_reason` `unresolved_dispatch` or `ambiguous_dispatch` ([below](#unknown-verdicts-are-common-on-dynamic-code)) | Treat `unknown` as possibly reachable |
| Dependency ecosystems: Java (Maven, Gradle), Python, Go, JavaScript/TypeScript (npm, yarn, pnpm locks), Rust (`Cargo.lock`, needs `cargo`), Ruby (`Gemfile.lock`), C# (NuGet lock or assets file, `packages.config`) | Dependency phase `skipped`, reason `ecosystem_not_supported` or `manifest_absent` | — |
| npm package locked at several versions | Only the version the project loads (top-level `node_modules`, else declared directly, else most depended on, else highest semver; across a monorepo's locks, an installed version, else the highest semver) is requested; the others are in `deps_skipped_list`, reason `other_version_requested`, and a package only those require with reason `under_other_version` | — |
| npm lock file of lockfileVersion 1 (npm 6) | Its module root is skipped with a warning (other roots resolve); with every lock version 1, npm dependencies `skipped`, reason `unsupported_lockfile`; other ecosystems are unaffected | Regenerate the lock with npm 7 or later |
| Dependency versions SCANOSS has not analysed | Online, the offline fallback analyses it locally; when it cannot (no sources, `--no-offline-fallback`), the dependency is in `deps_skipped_list`, reason `no_reachability_data` | Make its sources available locally ([OFFLINE.md](OFFLINE.md#online-scans-the-offline-fallback)) |
| NuGet packages ship no source | A C# dependency is often in `deps_skipped_list`, reason `no_reachability_data` | — |
| Unpinned Python requirement | `deps_skipped_list` reason `unpinned` | Pin it (lock file or `==`) |
| Go types come from the host | A Go call into a module missing from the module cache is `name_only`, so its findings read `unknown`; a Go dependency analysed without one of its modules is less typed until the next graph id | `go mod download` before the scan |
| Go build-tag variants are unioned | A function declared in several build-tag files carries the calls of all of them: a route only one platform builds reads `reachable` | — |
| Go composite literals and field stores | `tls.Config{...}`, `cfg.CipherSuites = ...` are not in the Go graph: no finding or route from them | — |
| Static analysis | `unknown` verdicts, `unresolved_reason` set | See [Why a verdict is unknown](#why-a-verdict-is-unknown) |
| Call chains are a sample | At most `--export-callgraph-max-chains` (default 8) chains per finding, depth 32 | Raise the flag; `--export-callgraph-entry-points` for the full reverse index |
| Maven lists a dependency once | A route through a second parent is missing from the stitched tree | — |
| Build tools run repository code | `mvn` / `gradle` execute plugins the project controls | Scan untrusted code in a sandbox |

## Unknown verdicts are common on dynamic code

Dependency verdicts are fail-closed: where the analysis cannot decide a
route, the verdict is `unknown`, never a guess. On Python and on
JavaScript/TypeScript, which dispatch on values more than on declared types,
a large share of dependency findings read `unknown`. Most often the reason is
`unresolved_dispatch`. Treat `unknown` as possibly reachable.

`reachable` can also be wrong when the application's own values switch the
cryptography off (an option never enabled, an algorithm table where the
application pins another entry): the analysis follows calls, not those
values.

## Why a verdict is unknown

Common causes:

| Cause | Example |
|---|---|
| Algorithm chosen at run time from a table | pyjwt and authlib pick the algorithm implementation from a table, keyed by a value the caller passes |
| Call on a value with no known type | A method called on a `str`, or on a parameter nothing annotates |
| Framework callbacks | Twisted calls application code through registered callbacks that no call expression names |

The reasons the export gives:

| `unresolved_reason` | Meaning |
|---|---|
| `unresolved_dispatch` | Every route to the finding crosses a call resolved by name only (no receiver type) |
| `ambiguous_dispatch` | The project reaches the finding only through an interface call with several implementations in the closure |
| `dependency_without_graph` | Every dependency path to the finding crosses a dependency with no graph |

The stitch is fail-closed: it does not follow a call resolved by name only,
so an uncertain route yields `unknown`, not `reachable` by guess.

## Static analysis in general

- Reflection, dynamic imports and calls through stored function values are
  not followed.
- Java interface and abstract-class calls fan out to same-name, same-arity
  implementations; the stitch keeps only unambiguous ones.
- Generated or runtime-created code is not seen.
- A finding is never a runtime trace or an approval decision.

## Related

- [DEPENDENCY_SCANNING.md](DEPENDENCY_SCANNING.md): the dependency pipeline.
- [CLIENT_SERVER.md](CLIENT_SERVER.md): what runs where.
- [ERROR_CODES.md](ERROR_CODES.md): failure codes such as `language_not_supported`.
