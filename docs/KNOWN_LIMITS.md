# Known limits

What crypto-finder 1.0 does not do, or does not decide, and how each limit
shows up in the output. Read this before treating a missing finding as "no
cryptography" or an `unknown` verdict as an error.

## Summary

| Limit | Shows up as | Workaround |
|---|---|---|
| Java, Python, Go, JavaScript, TypeScript, Rust and Ruby only | `language_not_supported` (exit 1) for a target only in other languages | crypto-finder 0.54.0 for those languages |
| Python verdicts often `unknown` | 138 of 221 labelled Python cases `unknown` (`unresolved_dispatch`, `ambiguous_dispatch`) | Treat `unknown` as possibly reachable |
| Dependency ecosystems: Java (Maven, Gradle), Python, Go, JavaScript/TypeScript (npm, yarn, pnpm locks), Rust (`Cargo.lock`, needs `cargo`) | Dependency phase `skipped`, reason `ecosystem_not_supported` or `manifest_absent` | — |
| npm package locked at several versions | Only the version the project loads (top-level `node_modules`, else declared directly, else most depended on, else highest semver; across a monorepo's locks, an installed version, else the highest semver) is requested; the others are in `deps_skipped_list`, reason `other_version_requested`, and a package only those require with reason `under_other_version` | A multi-version request in the API |
| npm lock file of lockfileVersion 1 (npm 6) | Its module root is skipped with a warning (other roots resolve); with every lock version 1, npm dependencies `skipped`, reason `unsupported_lockfile`; other ecosystems are unaffected | Regenerate the lock with npm 7 or later |
| Only mined dependency versions | Dependency counted in `deps_skipped_list`, reason `no_reachability_data` | `--offline` mines it locally ([OFFLINE.md](OFFLINE.md)) |
| Unpinned Python requirement | `deps_skipped_list` reason `unpinned` | Pin it (lock file or `==`) |
| Go types come from the host | A Go call into a module missing from the module cache is `name_only`, so its findings read `unknown`; a Go graph mined without a module is less typed until the next graph id | `go mod download` before the scan |
| Go build-tag variants are unioned | A function declared in several build-tag files carries the calls of all of them: a route only one platform builds reads `reachable` | — |
| Go composite literals and field stores | `tls.Config{...}`, `cfg.CipherSuites = ...` are not in the Go graph: no finding or route from them | — |
| Static analysis | `unknown` verdicts, `unresolved_reason` set | See [Why a verdict is unknown](#why-a-verdict-is-unknown) |
| Call chains are a sample | At most `--export-callgraph-max-chains` (default 8) chains per finding, depth 32 | Raise the flag; `--export-callgraph-entry-points` for the full reverse index |
| Maven lists a dependency once | A route through a second parent is missing from the stitched tree | — |
| Build tools run repository code | `mvn` / `gradle` execute plugins the project controls | Scan untrusted code in a sandbox |

## Python dependency reachability

Python dependency findings carry the stitch's verdict, online and
`--offline` alike (new in 1.0).

Measured on 221 labelled Python cases (PyGithub, synapse):

| Result | 1.0 | 0.53.1 approach |
|---|---|---|
| Correct | 75 | 161 |
| False reachable | 8 | not reported |
| False unreachable | 0 | 59 |
| Unknown | 138 (130 `unresolved_dispatch`, 8 `ambiguous_dispatch`) | not reported |

1.0 trades coverage for soundness: on this set it calls no reachable
finding unreachable, and says `unknown` where it cannot decide. 8 findings
are reported reachable that are not.

Wall-clock time against 0.53.1 on the same targets:

| Target | 1.0 | 0.53.1 |
|---|---|---|
| PyGithub, online | 4.6 s | 16.2 s |
| synapse, online | 13-15 s | 55.7 s |
| synapse, `--offline`, first run (fills the cache) | 68 s | not measured |
| synapse, `--offline`, later run | 13 s | not measured |

Java outputs were unchanged between 0.5x and 1.0 on the two Java validation
projects (client-encryption-java and an internal Java test project).

## JavaScript and TypeScript dependency reachability

npm dependency findings carry the stitch's verdict, online and `--offline`
alike (new in 1.0).

Measured on 1582 labelled npm dependency findings (parse-server 9.11.0,
uptime-kuma 2.5.12). The labels were drafted by review agents, and the
48 rows where the engine disagreed or confidence was low were re-checked
against the source:

| Result | 1.0 | 0.54.0 |
|---|---|---|
| Correct | 1345 | 669 |
| False reachable | 27 | 0 |
| False unreachable | 2 | 219 |
| Unknown | 189 (182 `unresolved_dispatch`, 6 `dependency_without_graph`, 1 `ambiguous_dispatch`) | 154 `not_applicable` |
| Not reported at that location | 19 (15 entry points now reported where the function is defined) | 540 |

Of the 189 unknown findings, 125 are reachable and 64 are not.

- **The 2 false unreachable:** the copy of `ws` that playwright-core bundles
  in an esbuild-minified file.
- **Most of the 27 false reachable** are crypto that the application's own
  values switch off, which the analysis does not track:
  - an SNMPv3 session created `noAuthNoPriv` (net-snmp);
  - a JWT algorithm table where the application pins RS256 (jwa);
  - Parse's encrypted current user, never enabled (crypto-js);
  - an ssh2 `hostVerifier` the application never passes.
- **Online and offline agree** finding for finding, except for:
  - optional packages `npm ci` did not install, which only the online
    answer covers;
  - a route through a package without JavaScript, which reads
    `dependency_without_graph` online and `unreachable` offline.

Wall-clock time against 0.54.0 on the same targets:

| Target | 1.0 | 0.54.0 |
|---|---|---|
| parse-server, online | 13 s | 1320 s |
| uptime-kuma, online | 11 s | 559 s |
| parse-server / uptime-kuma, `--offline`, first run (fills the cache) | 252 s / 154 s | not measured |
| parse-server / uptime-kuma, `--offline`, later run | 14 s / 11 s | not measured |

## Why a verdict is unknown

Causes seen in the validation:

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
