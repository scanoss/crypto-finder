# Output Formats

Crypto Finder supports two output formats: an interim JSON format for detailed analysis and CycloneDX CBOM format for standardized Bill of Materials reporting.

## Interim JSON Format

The default output format containing detailed cryptographic asset information optimized for the SCANOSS ecosystem.

The interim report is the primary findings artifact. It contains finding metadata such as `finding_id` and optional structural `occurrence_key`, but it does not embed the finding-centric reachability slices produced by `--export-callgraph`.

### Format Specification

```json
{
  "version": "1.5",
  "tool": {
    "name": "crypto-finder",
    "version": "0.1.0"
  },
  "findings": [
    {
      "file_path": "path/to/file",
      "language": "language_name",
      "cryptographic_assets": [
        {
          "start_line": 123,
          "end_line": 123,
          "match": "code snippet",
          "rules": [
            {
              "id": "rule.id",
              "message": "description",
              "severity": "INFO|WARNING|ERROR"
            }
          ],
          "status": "pending|identified|dismissed|reviewed",
          "metadata": {
            "assetType": "algorithm|certificate|protocol|related-crypto-material",
            "algorithmFamily": "algorithm_family",
            "algorithmPrimitive": "primitive_type",
            "algorithmMode": "mode_of_operation",
            "algorithmPadding": "padding_scheme"
          },
          "source": "direct|dependency",
          "dependency_info": {
            "module": "golang.org/x/crypto",
            "version": "v0.17.0",
            "purl": "pkg:golang/golang.org/x/crypto@v0.17.0"
          },
          "finding_id": "a1b2c3d4",
          "occurrence_key": "v1:0123456789abcdef"
        }
      ]
    }
  ]
}
```

> **Note:** Version 1.1 introduced the `rules` array field (replacing single `rule` field) to support per-line deduplication. Version 1.2 added `source` and `dependency_info` for dependency scanning attribution. Version 1.3 adds `finding_id` for cross-referencing with the callgraph export. Version 1.5 adds optional `occurrence_key` for canonical findings, using AST call evidence when available and a deterministic file/module-level fallback for valid top-level calls. Dependency-backed `file_path` values are dependency-root-relative; the package identity stays in `dependency_info`. Reachability slices such as `call_chains` are emitted by the dedicated call graph export, not by the interim report. See [Dependency Scanning](DEPENDENCY_SCANNING.md) for details.

### Field Descriptions

| Field | Description |
|-------|-------------|
| `version` | Format version (currently "1.5") |
| `tool.name` | Scanner used (crypto-finder) |
| `tool.version` | Scanner version |
| `findings` | Array of file-level findings |
| `file_path` | Relative path to scanned file |
| `language` | Detected programming language |
| `cryptographic_assets` | Array of crypto findings in the file |
| `start_line` | First line where the asset was detected |
| `end_line` | Last line where the asset was detected |
| `match` | Actual code snippet matched |
| `rules` | Array of detection rules that identified this asset |
| `rules[].id` | Unique rule identifier |
| `rules[].message` | Human-readable description |
| `rules[].severity` | Finding severity level |
| `status` | Finding status (pending, identified, dismissed, reviewed) |
| `metadata` | Key-value pairs with asset-specific metadata |
| `metadata.assetType` | Asset classification |
| `metadata.algorithmFamily` | Algorithm/protocol family name |
| `metadata.algorithmPrimitive` | Cryptographic primitive type |
| `metadata.algorithmMode` | Mode of operation (for block ciphers) |
| `metadata.algorithmPadding` | Padding scheme used |
| `source` | `"direct"` (user code) or `"dependency"` (v1.2+) |
| `dependency_info` | Attribution for dependency findings: `module`, `version`, and optional `purl` (v1.5+) |
| `purl` | Optional canonical package URL promoted from direct rule metadata; it stays versionless unless one unambiguous direct dependency version is available (v1.6+) |
| `finding_id` | Stable short hash used to join the interim report to the call graph export (v1.3+) |
| `occurrence_key` | Optional `v1:<16 lowercase hex>` structural identity. It excludes rules, source text, metadata, reachability, and severity; uses AST anchors when available and a deterministic file/module-level fallback for valid top-level calls (v1.5+). A per-value asset, one a rule's `parameterCondition` specialized to a resolved value such as `param[0]==SHA-256`, also hashes that value, so the values of one call have distinct keys and `finding_id`s; every other asset, native ones included, hashes exactly the structural identity above. Legacy records or scans without source enrichment may omit it. |
| `parameter_conditions` | Structured argument predicates parsed from the rule's `parameterCondition` metadata — which argument value/type selects this asset variant (v1.4+, omitted when the rule carries no predicate) |
| `file_path` | For dependency findings, path relative to the dependency root; use `dependency_info` for artifact identity |

### Public Go Contract

Go consumers can import `github.com/scanoss/crypto-finder/pkg/schema` to read or write the interim report without importing implementation packages. `InterimFormatVersion` is currently `"1.6"`.

The report always emits `version`, `tool`, and `findings`. `rules` is a value field and currently emits as `{}` when empty. Findings always emit `file_path`, `language`, and `cryptographic_assets`. Assets always emit `start_line`, `end_line`, `match`, `rules`, `status`, and `metadata`; `start_col`, `end_col`, `parameter_conditions`, `oid`, `finding_id`, `occurrence_key`, `source`, `dependency_info`, and direct `purl` are omitted when empty. Rules always emit `id`, `message`, and `severity`; `version` is omitted when empty. Dependency metadata always emits `module` and `version` when present.

The report preserves its JSON vocabulary: `severity` is `INFO`, `WARNING`, or `ERROR`; `status` is `pending`, `identified`, `dismissed`, or `reviewed`; and `source` is `direct` or `dependency`. Valid rule package URLs are promoted to top-level `purl` for direct findings. Dependency findings keep package identity in `dependency_info.purl`; unknown ecosystems omit it, and missing versions produce versionless package URLs. `CryptographicAsset` accepts the legacy singular `rule` input and migrates it to `rules` only when `rules` is absent or empty. When both are supplied, `rules` takes precedence. Internal terminal-column fields never serialize.

### Call Graph Export

When `--export-callgraph <file>` is passed, Crypto Finder also writes a separate finding-centric call graph JSON file to `<file>`. This export contains the reachability slices and value-flow details associated with findings from the interim report.

Schema note: local CLI callgraph exports default to interned **`6.17`**. Consumers must join identity through `functions[]` and `call_chain_indexes`; use `--export-callgraph-interned-frames=false` for inlined **`6.14`**. SDK/stitch zero-value options remain `6.14`. Version history:

- **`6.17`** (local CLI default; SDK opt-in) adds optional fields to the interned render. `finding_graphs[].dependency` names the dependency a dependency finding sits in and its route from the application in the resolved dependency graph, with `without_source` on a path step parsed without source. `finding_graphs[].analysis` gains `paths_total`, `paths_kept`, `route_evidence` and `no_callers_only`. The first frame of each live chain carries `root_kind` (`main`, `framework_entry`, `no_callers`, `depth_limit`). `unresolved_reason` gains three values for an attributed finding whose verdict is `unknown`: `traversal_truncated`, `unresolved_dispatch` and `dependency_without_source`; the stitched export now writes `unresolved_reason` too, with `unresolved_dispatch` only. Every new field is optional, so a `6.16` reader that ignores unknown properties keeps working; a reader that switches on `unresolved_reason` must treat an unknown value as unknown. Frame shape is the `6.15` interned shape.
- **`6.16`** (SDK opt-in; the CLI default before `6.17`) adds optional `scan_metadata.ecosystems` to the interned render. A target with first-party findings in more than one supported ecosystem, such as a Java service beside a TypeScript front end, gets one call graph per ecosystem, and each finding resolves against the graph of its own language. The list names every graph analyzed, the primary first, each with `ecosystem`, `root_module`, `function_count` and `edge_count`. `scan_metadata.ecosystem`, `root_module`, `function_count` and `edge_count` keep describing the primary graph, the one dependencies resolve for, so a consumer that reads only those fields is unaffected. The list is absent for a single-ecosystem export, which is otherwise unchanged, and from the inlined `6.14` compatibility render. Frame shape is the `6.15` interned shape.
- **`6.15`** (SDK opt-in; the CLI default before `6.16`) contracts `call_chains` frames: they no longer repeat catalog identity fields (`function_name`, `file_path`, `canonical_signature`, `dependency_info`, and the rest of the interned identity). Join through `functions[]` plus `finding_graphs[].call_chain_indexes`, and through `canonical_signature` on `crypto_entry_points` and catalog rows. Hop-specific fields (`entry_call`, `crypto_call`, `entry_resolution`) stay on the frames. Enable with `--export-callgraph-interned-frames` or `ScanMeta.InternedFrames`. Zero-value SDK/stitch stays on `6.14`; the CLI defaulted to `6.15` until `6.16`. Parsers that only read `call_chains[]` objects must gate on `schema_version` or call `HydrateChainIdentities`.
- **`6.14`** adds a top-level interned `functions[]` catalog and `finding_graphs[].call_chain_indexes` (0-based positions into that catalog) beside the existing inlined `call_chains`. The index lists reconstruct the same N-sample of routes. Inlined frames keep their previous field names and meaning. `crypto_entry_points` is still the complete reverse-reach set. Both surfaces can explicitly select this compatibility render.
- **`6.13`** adds `call_chains[].entry_resolution` and `entry_declared_type`, reporting how the call arriving at each frame was established.
- **`6.12`** adds the rule-vs-callgraph key-length conflict marker to `supporting_calls[].supporting_call.resolved_key_length`. When a detection rule declares a static `keyLength` and the callgraph resolves a different value for a finding referencing that evidence, the resolved `bits` stay primary, the rule value is retained as `rule_declared_bits`, and `rule_conflict` is `true`. Agreement, an unresolved key length, and a rule that declares no `keyLength` all leave both fields absent. The marker is computed during the scan, so consumers read it directly instead of re-deriving it from rule metadata.

- **`6.11`** adds optional `supporting_calls[].supporting_call.resolved_key_length` for structurally derived Java key-generation configuration calls referenced by `finding_graphs[].supporting_call_ids`. It contains raw integer `bits` only when static analysis resolves a literal or simple propagated constant, `provenance` (`constant` or `unknown`), and required `source_call` (`function_name`, `line`, `parameter_index`) for the contributing argument. It is preserved by live, graph-fragment, and stitched callgraph exports; terminal `crypto_call` records do not carry it, and it does not populate CBOM properties or express a security threshold.

- **`6.10`** carries an optional top-level `purl` for direct findings and an optional canonical `purl` inside dependency context. Live and stitched exports derive dependency URLs from the scan ecosystem and existing module/version fields, so cached graph fragments gain the field without a fragment schema change.

- **`6.10`** adds optional `occurrence_key` to canonical finding graphs; it is propagated from the interim report and graph fragments. AST anchors are preferred, with a deterministic file/module-level fallback for valid top-level calls. When present, `(finding_id, occurrence_key)` identifies the structural occurrence; legacy records without `occurrence_key` continue using `finding_id` alone.
- **`6.9`** makes `crypto_entry_points[]` a reverse-reachability answer rather than a projection of the exported `call_chains`: every function that reaches a finding is listed, so an entry point no longer depends on which chains survived collapsing or the per-finding chain budget. `chain_depth` is consequently the true minimum frame distance, and some depths are smaller than the same export previously reported. No field was added or removed. Live and stitched paths agree on both the index and the enumerated routes.
- **`6.8`** adds `finding_graphs[].reachability` (`reachable`/`unreachable`/`unknown`/`not_applicable`, where a self-chain fallback never counts and suppression or a depth limit that cut every route downgrades to `unknown`), `finding_graphs[].analysis` (`call_chains`/`parameters` completeness), and `crypto_entry_points[].root` — the explicit chain-root classification, the index itself staying deliberately broader. The legacy `reachable` bool is unchanged.
- **`6.7`** adds `reachable` to each finding graph when dependency scanning makes user-code reachability applicable; it is omitted for a standalone library scan.
- **`6.6`** adds deterministic `forward_calls.ambiguous_calls` groups for fail-closed interface dispatch: completeness state, stable group/candidate IDs, complete callable identities, and preserved call-site argument provenance — without promoting ambiguous candidates to resolved edges.
- **`6.5`** makes `role: operation` contract methods **supporting-call-only**: they are exported as categorized `supporting_calls` referenced by `supporting_call_ids` (including interface-authored contracts resolved to concrete implementations) and are no longer synthesized as operation-only `crypto_entry_points` in live, fragment, or stitched exports.
- **`6.4`** adds `method_role`, `role_provenance`, and `parameter_roles` — contracts-KB-derived method/parameter role classification (`factory`/`config`/`output`/`operation` on `method_role`; per-parameter `operation-determining`/`metadata-contributing`/`none` with a `contributes: {property, derivation}` block on `parameter_roles`). `method_role`/`role_provenance` appear on `crypto_entry_points`; `parameter_roles` appears on `crypto_entry_points` and on the supporting-call declaration, index-aligned with `parameter_types` — never on call-site parameter literals. These fields are populated on the live (`--export-callgraph`) and graph-fragment export paths and carried through the stitched/served path.
- **`6.3`** added the optional per-finding `forward_calls` block — the finding anchor's forward call closure (deduped nodes with `depth`/`crypto_relevant`/`supporting_category`, plus traversed edges whose `entry_call` carries the call-site argument data-flow), emitted only when the stitch runs with `StitchOptions.ForwardClosure`; caps (depth/nodes/edges) are surfaced via `max_depth` and an explicit `truncated` flag, never silently.
- **`6.2`** exposed `supporting_calls`, `crypto_entry_points`, and `graph_algo_version` end-to-end.
- **`6.0`** removed the legacy `entry_point_index` projection and made `crypto_entry_points[]` canonical.
- **`4.3`** added Java runtime provenance in `scan_metadata` for JDK-aware platform signature enrichment.

- Each top-level record preserves `finding_id`. When `occurrence_key` is present, the composite `(finding_id, occurrence_key)` identifies the structural occurrence and joins it back to the interim report. Legacy records without `occurrence_key` use `finding_id` alone.
- `call_chains` is the primary value-flow structure. Each chain is ordered from the first reachable caller to the function that contains the matched crypto call. The array is a capped sample, not the complete reverse-reach set. Local CLI defaults to 8 paths; `--export-callgraph-max-chains 128` opts in to a larger sample. SDK/stitch zero or omitted `StitchOptions.MaxChains` remains 128. The live export has no depth cap. The sample is spent on the strongest evidence first (see `analysis.route_evidence`): every route whose calls all resolved statically, then routes that need a dispatch edge, then routes that need a `name_only` edge. Within each of these, it goes to distinct routes first: one shortest route per chain root, recognized entry points before other roots, then further routes, and only then the same route at another call-site line, the most certain call site first. The route that justifies the verdict is therefore always among the kept chains. The stitched export orders its chains the same way by evidence, direct routes before dispatch routes.
- With user code known (dependency scanning, or `--export-callgraph-project-reachability`), a chain walks back through application code until it reaches an application function that no application code calls, instead of stopping at the first application frame. An application function follows only its application callers; library code follows every caller. The function holding the crypto follows every caller, so crypto in an application callback is reached through the library that calls it back. The first frame of each chain carries `root_kind`: `main` (a Java `static main(String[])`, or a free function named `main`), `framework_entry` (a Java method that is an `@Override` of a method of a type outside the application, such as `HttpHandler.handle` or `Runnable.run`, or one annotated with a Spring or JAX-RS request mapping, `@Scheduled`, `@EventListener`, or a Kafka, RabbitMQ, JMS or SQS listener imported from its framework), `no_callers` (any other application function nothing in the application calls; on a library scanned alone, a graph root), or `depth_limit` (where a depth limit stopped the walk, SDK callers only). A cycle of application functions nothing outside it calls is rooted at its first member. The function holding the crypto is itself a root only when it is recognized as `main` or `framework_entry` and no application code calls it: a handler doing crypto inline reads `reachable`, a helper nothing calls reads `unreachable`. `crypto_entry_points[].root` follows the same roots.
- Entry point rules beyond those above. Which frameworks count, and the names each declares, is data: the entry-point catalog, one YAML file per framework under `internal/callgraph/entrypoints/<language>/<framework>.yaml`, built into the binary. An entry names the packages the framework comes from (`from`, a subpackage matches too), the names it declares, the shape the parser recognizes, and the `root_kind` it gives. A name counts only when the file brings it into scope from that package, never by the bare name: a Java annotation resolves through the file's single-type import, else its on-demand imports, else its own package, or is written qualified; a TypeScript or JavaScript decorator through its import, and a router through the import or declaration its value comes from (`app = express()`, `require('fastify')()`, a parameter typed `Express`); a Python decorator, callee or base class through its import or the module-level assignment its object comes from (`app = Flask(__name__)`, a function `@click.group()` makes); a Go receiver through its import, the declaration in scope (`r := chi.NewRouter()`, a parameter typed `chi.Router`) or a struct field of the file, and a method value through its receiver's type. Shapes: `decorator` (an annotation or decorator on the function), `registration_call` (a call that passes the handler, inline or by name, directly or through one wrapper call; `path: required` asks for a path or method argument before it, or on the route it is chained to), `handler_field` (a field of a framework struct literal, `&cobra.Command{RunE: run}`), `supertype` (a method of a type that extends, implements or embeds a framework type, also through the application's own supertypes; a Python entry may add `directory` to count only files under a directory of that name, and name `<clinit>` for the class body: the body of a Django `Migration` under a `migrations` directory is an entry point, since the migration loader runs it and reaches the `RunPython` callbacks from there), `interface_method` (a Go method with the name and parameter types of a framework interface method, `ServeHTTP(http.ResponseWriter, *http.Request)`), `server_registration` (Go: a call of a generated `Register<Service>Server` or `Register<Service>HandlerServer` function, whose `names` are patterns; the methods of the value passed as its last argument that belong to the service become entries, found from the interface when the scanned tree declares it, else by gRPC signature) and `file_convention` (an export a framework finds by the file's location, counted only when the nearest `package.json` declares the framework). The catalog ships Java: Spring (MVC and WebFlux handler methods, `@Bean`, schedules, application events, STOMP, JMS, and its filter and servlet bases), Spring Kafka, Spring AMQP, Spring Cloud Stream and AWS SQS, Spring Integration, JAX-RS, Jakarta Annotations (`@PostConstruct`, `@PreDestroy`), Servlet, WebSocket, EJB timers, Micronaut, Quarkus and MicroProfile Reactive Messaging; TypeScript and JavaScript: Express, Koa (`koa`, `@koa/router`, `koa-router`), Fastify, Hono, NestJS and Next.js; Python: Flask, Flask-RESTful, FastAPI, Starlette, Sanic, Django (views, signal receivers, migrations), Django REST framework, Celery, click, typer, Dramatiq and RQ; Go: net/http, chi, gin, echo, gorilla/mux, cobra and gRPC. To add a framework, add its file and a fixture under `internal/scan/testdata/entry_rules/<language>/` with a case in `internal/scan/entry_rules_export_test.go`; the loader rejects an unknown field, a shape the language's parser does not recognize, a field the shape does not read, and a name two entries both claim for the same package. Language semantics that belong to no library stay in the parsers: TypeScript and JavaScript: the exports of the module the nearest `package.json` names in `main`, `module` or `exports` (`dist/`, `build/`, `lib/`, `out/`, `esm/`, `cjs/` and `es/` paths also match the same path under `src/` and at the package root), and `main` for the top level (`<module>`) of that module, of a module `bin` names, of a module a `package.json` script runs with `node`, `nodejs`, `tsx`, `ts-node`, `bun` or `deno` (`tsx scripts/seed.ts`, also after `&&`, `||`, `;` or `|`, with the same `dist/` to `src/` mapping), of a `.js`, `.mjs`, `.cjs`, `.ts`, `.mts` or `.cts` file whose first line is a shebang naming one of those runtimes, and of a module with `if (require.main === module)`; Python: `main` for the functions the nearest `pyproject.toml` (`[project.scripts]`, `[project.gui-scripts]`, `[tool.poetry.scripts]`), `setup.cfg` (`[options.entry_points]`) or `setup.py` names as `module:function`, and for the top level (`<module>`) of a module with `if __name__ == "__main__":`; Go: `main` for `init` functions and the synthetic `<varinit:…>` package variable initializers, which the runtime runs before `main`. Three kinds of call have no call expression and are now call edges: a JSX element with a capitalized name calls that component, a JSX attribute that names a function (`onClick={handleClick}`) calls it, and a function written inline as a call or `new` argument, or as a JSX attribute value, is called by the function that writes it, except a route handler, which is an entry point instead. These edges never serve as a finding's matched crypto call. Test code is never an entry point in any language: a method with a JUnit or TestNG annotation, or a function in a file under `test/`, `tests/` or `__tests__/` or named like a test (`*Test.java`, `*_test.go`, `test_*.py`, `*_test.py`, `conftest.py`, `*.test.*`, `*.spec.*`), keeps `no_callers`. Test sources are in the graph only under `--include-tests`.
- `analysis.paths_total` is the number of distinct routes, from a chain root to the finding, the graph holds, and `analysis.paths_kept` the number the finding's `call_chains` show; chains that differ only in a call-site line count once. `paths_total` saturates at the largest int64 and is then a lower bound. Both are present on live findings with a chain: reachable ones and `unresolved_dispatch` ones. `analysis.call_chains` is `partial` whenever routes were left out or a depth limit cut the walk. There is no path-count ceiling any more: a finding with millions of routes gets its sample of chains and reads `reachable`, not `unknown` with no chains. A depth limit that cuts every route before a root reads `unknown` with `unresolved_reason` `traversal_truncated`; that reason, unlike the others, comes without `finding_location`, since the finding is attributed. A finding whose every route crosses a `name_only` edge reads `unknown` with `unresolved_reason` `unresolved_dispatch`, also without `finding_location`: its chains are exported as evidence of how the crypto may run, and the legacy `reachable` flag is omitted. One route free of `name_only` edges keeps it `reachable`. `analysis.route_evidence` rates the finding's strongest route by its weakest call: `direct` (every call `exact` or statically resolved), `dispatch` (the best route needs at least one `interface_dispatch` or `python_subclass_dispatch` edge and no `name_only` edge; the finding stays `reachable`, and the dispatch hop is the frame whose `entry_resolution` names it), or `name_only` (every route needs a `name_only` edge; the verdict is `unknown` with `unresolved_dispatch`). A finding specialized by a `parameter_conditions` predicate that removed chains rates `route_evidence` and `no_callers_only` from its surviving chains only, so a condition that refutes the direct route cannot leave `direct` behind; with no chain left both are absent. The verdict follows the same chains: a specialized finding whose surviving chains all cross a `name_only` edge reads `unknown` with `unresolved_dispatch`, even when another value of the same function has an exact route. A value reached only from a caller nothing calls keeps the verdict any finding so reached has (`reachable`, flagged `no_callers_only`). It is present with `paths_total` on the live export, and on stitched findings that are `reachable` through a chain or `unresolved_dispatch`; a stitched finding proven only by a dependency's mine-time entry-point index has no frame-by-frame route and carries none. `analysis.no_callers_only` is `true` when every root of the routes that support the verdict has `root_kind` `no_callers`: the crypto is reached only from application code nothing in the application calls, not from a recognized `main` or framework entry. The supporting routes are those free of `name_only` edges, or every route when none is, and all of them count, not only the kept chains. It is omitted when false, and on the stitched export, whose chains carry no `root_kind`. The stitched export, which follows no `name_only` edge, reads such a finding `unknown` with `unresolved_reason` `unresolved_dispatch` and no chain, and a dependency's mine-time entry-point index does not upgrade it to `reachable`; it sets no other `unresolved_reason`. CLI omits the optional complete reverse-reach index unless `--export-callgraph-entry-points=true`; sample budgets do not filter that index. Policy: [ADR 0002](adr/0002-call-chains-sample-size.md).
- `functions[]` (schema `6.14`+) is the interned identity catalog for those emitted routes. `finding_graphs[].call_chain_indexes` lists the same walks as integer positions into that catalog. Schema `6.14` also inlines those fields on `call_chains` frames. Schemas `6.15`, `6.16` and `6.17` (local CLI default) join identity through the catalog alone.
- Each chain node carries hop-specific fields: optional `entry_call`, `entry_resolution`, and `crypto_call` on the last node. Compatibility schema `6.14` also inlines function identity (`function_name`, `file_path`, `canonical_signature`, `dependency_info`) on each frame. The interned render (`6.15`+) keeps that identity only in `functions[]`.
- `entry_call` describes how execution entered the current node from the previous step. Its `file_path` and `line` refer to the call site in the previous node's source file.
- `entry_resolution` says how the edge from the previous step was resolved: `exact` (the receiver's static type and the call's argument types identify the target, including a method inherited from the nearest declaring superclass, and a declared function handed to a known callback-invoking API such as `threading.Thread(target=fn)`, `sort.Slice(xs, fn)` or `setTimeout(fn, 1)`, reached from the function that registers it), `interface_dispatch` (an interface or abstract-class call expanded to a method of a real subtype of `entry_declared_type`, from the bytecode hierarchy or the parsed extends/implements clauses), `python_subclass_dispatch`, or `name_only` (a match by method name and arity with no type proof: a fluent-chain fallback, or a dispatch candidate whose class hierarchy is only partly known or names a type whose simple name several known types share, kept because nothing proves it is not a subtype; with dependencies scanned, such a candidate is kept only when its artifact is the declared type's, is the project, or depends on the declared type's artifact). A Java type name is treated as certain only when the source spells it fully qualified, or when the file declares no type parameter or local class of that name and at most one type of that simple name exists in the scanned source and indexed bytecode; Java's scoping rules are not modeled beyond that. The graph cannot see a subtype relation it has no record of, for example one through a member type inherited from a supertype in an unindexed jar when a graph type of the same simple name sits in the caller's package, so such a gap can still hide a path. The local CLI export and the stitched export both fill it; it is absent on a chain's first frame.
- The last node in each chain carries `crypto_call`, which is the matched crypto-relevant call for the finding.
- `entry_call.parameters[]` and `crypto_call.parameters[]` both use the same parameter model: `parameter_index` (always `0`-based), best-effort `type`, `argument_expression`, `resolved_value`, `variable_name` for simple identifiers only, and recursive `source_nodes`.
- `supporting_calls[].supporting_call.resolved_key_length` is optional evidence scoped to structurally derived key-generation configuration calls, currently the JCA set: `javax.crypto.KeyGenerator.init(int)`, `java.security.KeyPairGenerator.initialize(int[, SecureRandom])`, and the `RSAKeyGenParameterSpec`, `ECGenParameterSpec`, and `SecretKeySpec` constructors whose value reaches such a call. `source_call.function_name` names the call the size was read from, which is the spec constructor when the size travels through a parameter object. Join the supporting declaration to a finding through `finding_graphs[].supporting_call_ids`. It reports raw key bits when known and otherwise retains `provenance: "unknown"` plus `source_call`; consumers must not infer a key-size threshold from it. The terminal `crypto_call` remains the detected operation and does not carry this field.
- `supporting_calls[].supporting_call.resolved_key_length.rule_conflict` reports that a detection rule declared a static `keyLength` disagreeing with the resolved `bits`. The resolved value remains primary and the rule value is preserved in `rule_declared_bits`, so neither side is lost. Both fields are absent when the two agree, when no key length was resolved, or when no rule declared one. A supporting call is shared by every finding that reaches the same crypto object, so the marker is a property of that shared evidence: it means **at least one** referencing finding declared a different key length, not that every one did, and it does not identify which. When several referencing findings disagree, `rule_declared_bits` reports the smallest disagreeing value, which keeps the output stable regardless of rule ordering. Per-finding attribution is not recoverable from this field.
- For Java scans, `scan_metadata` may also include `java_requested_jdk_major`, `java_runtime_version`, `java_platform_signatures_used`, `java_platform_signature_source`, and `java_platform_signature_unavailable_reason` to show which JDK major was requested and whether JDK platform signatures contributed to type enrichment.
- `source_nodes` can span multiple wrapper hops. A local `PARAMETER` node may contain nested upstream provenance such as `PARAMETER -> PARAMETER -> VALUE`, and propagated nested nodes keep `location.file_path` plus `location.line` when known.
- Method-call provenance is preserved as `CALL_RESULT` nodes. When the parser can resolve the invoked method, the node also exports `call_target`, and any traceable receiver value is nested under that `CALL_RESULT` via `source_nodes` (for example `CALL_RESULT -> PARAMETER alg -> VALUE SignatureAlgorithm.HS256`).
- `finding_graphs[].reachability` is `not_applicable` for every finding of a scan that resolved no dependency set, because such a target is read as a library scanned on its own, where a function nothing calls is public API rather than dead code. `--export-callgraph-project-reachability` treats the target as an application instead: its own source packages become the user code, the same set a `--scan-dependencies` run uses for first-party findings, so first-party verdicts match that run. First-party code that only a dependency reaches, through a callback or an interface the dependency calls, reads `unreachable` here because the dependency's code is not in the graph; `--scan-dependencies` follows it. A scan that resolved dependencies ignores the flag, and `--export-graph-fragment` is unaffected.
- A finding whose rule carries `parameter_conditions` keeps only the chains whose matched call satisfies them, reading each argument as the chain's caller passes it. A chain is dropped when a resolved argument contradicts a condition; a chain whose arguments did not resolve is kept when no chain matched. When every route was examined and every one contradicts the condition, the finding reads `unreachable` (`reachable: false`, no `call_chains`): the crypto the rule describes runs on no known route, and the graph fragment's `crypto_entry_points` do not list it either. When the chain budget (`--export-callgraph-max-chains`) left a route or a call site unexamined, it reads `unknown` with `unresolved_reason: "traversal_truncated"` and `analysis.call_chains: "partial"`.
- A dependency finding carries `finding_graphs[].dependency`, on the live and stitched exports: the dependency it sits in (`module`, `version`, `purl`, the versioned package URL), `relationship` (`direct` when the application declares it, `transitive` otherwise) and `path`, its shortest route from the application in the resolved dependency graph, not in the call graph. `path` lists `module`, `version` and `purl` per dependency, a direct dependency first and the finding's own dependency last; the application itself is `scan_metadata.root_module` and is not listed. Where several routes exist, one through dependencies parsed with source is preferred over a shorter one that is not, and ties break on module name. A module the resolution picks at more than one version (npm can install one package twice) is told apart by version: with a versioned dependency graph each copy has the route it really has, so `lodash` 4.17.21 can be `direct` while the copy nested under another package is `transitive`, and each path step names its own `version`. Without one, `relationship` and `path` are absent for a finding in such a module, and for any dependency whose route crosses one, rather than reporting a route that may belong to the other copy; `purl` and `version` stay. `relationship` and `path` are absent when the dependency graph was not resolved (for example a Maven tree that timed out) or does not connect the dependency to the application. A first-party finding has no `dependency` block; its top-level `purl` keeps its meaning, the package URL of the rule's library, and stays empty on a dependency finding. The block is optional and new in interned schema `6.17`. The inlined `6.14` compatibility render carries it too, and `schemas/callgraph-schema.json` declares it there.
- A dependency that joins the call graph without source code (a Java dependency with no source JAR is indexed for its types only; in other ecosystems it is left out) holds no call edges, so no call chain crosses it. On the live export such a dependency on a finding's `path` carries `without_source: true`. When every route from the application to a finding's dependency crosses one and no chain reaches the finding, the finding reads `unknown` with `unresolved_reason: "dependency_without_source"` and `analysis.call_chains: "partial"`, instead of `unreachable`: the chain may run through the dependency whose calls are missing. The stitched export has no such case, because a stitch with a component fragment missing fails.
- Findings missing a containing function or crypto-call match are still exported with `finding_location` and `unresolved_reason`. `no_containing_function` means the finding's language was analyzed and no function encloses it; `no_crypto_call_match` means no call at the finding's position matched. `language_not_analyzed` means no call graph exists for the finding's language in this scan, because the language has no call graph parser (Kotlin, for example) or its graph failed to build; its `reachability` is `not_applicable` because nothing about it was examined.
- A target with first-party findings in several supported ecosystems resolves each finding against the call graph of its own language. Those graphs cover first-party source only: dependencies are resolved for the primary ecosystem alone, the dominant language by file count or `--dep-ecosystem`. The first-party findings of the other ecosystems are classified the way the primary ecosystem's are, against their own source packages when dependencies were resolved or `--export-callgraph-project-reachability` is set, and `not_applicable` otherwise.
- `crypto_entry_points[]` is the stitch/API index. Each entry carries `function_key`, canonical/display symbols, aliases, and `reachable_findings[]` / `reachable_supporting_calls[]`.
- `supporting_calls[]` carries config/lifecycle/context crypto-adjacent calls, such as builder options or parameter setup. These calls are not findings and do not inflate `finding_graphs[]`. As of `6.5`, `role: operation` contract methods (the calls where the cryptographic computation actually executes, e.g. block-processing/finalization methods) are also exported here with a category and referenced via `supporting_call_ids`.
- Constructor joins remain canonical (`<init>`), while display fields and aliases expose IBM-style names such as `com.acme.Factory.Factory`.
- `entry_point_index` is not emitted by schema `6.0`. Consumers should migrate to `crypto_entry_points[]`.

### Compatibility and consumer gating

The published JSON Schemas are [`schemas/interim-report-schema.json`](../schemas/interim-report-schema.json), [`schemas/callgraph-schema.json`](../schemas/callgraph-schema.json) (inlined `6.14`), [`schemas/callgraph-schema-6.15.json`](../schemas/callgraph-schema-6.15.json) (interned `6.15`), [`schemas/callgraph-schema-6.16.json`](../schemas/callgraph-schema-6.16.json) (interned `6.16`), and [`schemas/callgraph-schema-6.17.json`](../schemas/callgraph-schema-6.17.json) (interned `6.17`, the local CLI default). Validate against the exact emitted version; undeclared properties are contract failures. Consumers without catalog hydration must explicitly request `--export-callgraph-interned-frames=false`.

- Adding an optional field requires a schema-version bump, a schema update, and documentation. Consumers must validate an artifact against the published schema for its exact version; an artifact with no matching published schema must fail closed with a clear upgrade message.
- Removing or renaming a field, changing a field's JSON type or meaning, or making an optional field required is breaking and requires a schema-version bump plus a migration note in `CHANGELOG.md`.
- Consumers must gate parsing on the artifact's `version` (interim report) or `schema_version` (callgraph), then validate against the matching published schema before processing it.
- Schema changes and version bumps must update this document, the schema file, generated-export validation, and `CHANGELOG.md` in the same change.

Example (`--export-callgraph-interned-frames=false`, schema `6.14`; identity is inlined on frames and also in `functions[]`):

```json
{
  "functions": [
    {
      "function_name": "io.jsonwebtoken.jjwtfun.controller.SecretsController.traceToken",
      "file_path": "src/main/java/io/jsonwebtoken/jjwtfun/controller/SecretsController.java",
      "start_line": 33
    },
    {
      "function_name": "io.jsonwebtoken.jjwtfun.service.SecretService.issueTraceToken",
      "file_path": "src/main/java/io/jsonwebtoken/jjwtfun/service/SecretService.java",
      "start_line": 72
    },
    {
      "function_name": "org.springframework.security.core.token.Sha512DigestUtils.getSha512Digest",
      "file_path": "org/springframework/security/core/token/Sha512DigestUtils.java",
      "start_line": 43,
      "dependency_info": {
        "module": "org.springframework.security:spring-security-core",
        "version": "5.7.11"
      }
    }
  ],
  "finding_graphs": [
    {
      "finding_id": "69669f02",
      "call_chain_indexes": [[0, 1, 2]],
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
  ]
}
```

### Example Output

**Single Rule Detection:**
```json
{
  "version": "1.1",
  "tool": {
    "name": "crypto-finder",
    "version": "0.1.0"
  },
  "findings": [
    {
      "file_path": "src/crypto/Example.java",
      "language": "java",
      "cryptographic_assets": [
        {
          "start_line": 29,
          "end_line": 29,
          "match": "cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");",
          "rules": [
            {
              "id": "java.crypto.cipher-aes-cbc",
              "message": "AES cipher usage detected",
              "severity": "INFO"
            }
          ],
          "status": "pending",
          "metadata": {
            "assetType": "algorithm",
            "algorithmFamily": "AES",
            "algorithmPrimitive": "block-cipher",
            "algorithmMode": "CBC",
            "algorithmPadding": "PKCS5Padding"
          }
        }
      ],
    }
  ]
}
```

**Multiple Rules Detection (Deduplicated):**
```json
{
  "version": "1.1",
  "tool": {
    "name": "crypto-finder",
    "version": "0.1.0"
  },
  "findings": [
    {
      "file_path": "src/crypto/cipher.go",
      "language": "go",
      "cryptographic_assets": [
        {
          "start_line": 42,
          "end_line": 42,
          "match": "cipher.NewGCM(block)",
          "rules": [
            {
              "id": "go-crypto-aes-gcm",
              "message": "AES-GCM encryption detected",
              "severity": "INFO"
            },
            {
              "id": "go-crypto-authenticated-encryption",
              "message": "Authenticated encryption pattern detected",
              "severity": "INFO"
            }
          ],
          "status": "pending",
          "metadata": {
            "assetType": "algorithm",
            "algorithmFamily": "AES",
            "algorithmPrimitive": "ae",
            "algorithmParameterSetIdentifier": "256",
            "algorithmMode": "GCM"
          }
        }
      ],
    }
  ]
}
```

### Use Cases

- Integration with SCANOSS platform
- Custom analysis pipelines
- Detailed cryptographic asset tracking
- Security auditing and compliance

## Graph Fragment Export

When `--export-graph-fragment <file>` is enabled, Crypto Finder writes a
**reusable structural graph fragment** for the scanned component: its call
graph plus rules-versioned crypto annotations. Unlike the finding-centric call
graph export (above), a fragment is designed to be composed with other fragments
across a dependency tree to answer "what crypto is transitively reachable from
artifact X?" The pure model and the stitcher that composes fragments live in the
public package `github.com/scanoss/crypto-finder/pkg/graphfrag`, so downstream
consumers can use one contract instead of reimplementing schema knowledge.

Current schema version: **`graph-fragment-1.12`** (`pkg/graphfrag.SchemaVersion`).

Since `graph-fragment-1.3`, a fragment is **self-contained enough to reconstruct
the two artifacts a live `--scan-dependencies` run would produce** — see
*Rendered artifacts* below.

Fragment schema history (all changes are additive; older fragments decode with
the missing fields empty and are handled fail-closed):

| Version | Change |
|---------|--------|
| `1.1` | Per-edge resolution metadata (`resolution`, `declared_type`, `method_name`, `arity`). |
| `1.2` | Per-edge call-site data-flow (`entry_call`) and full crypto-call identity + asset metadata on `crypto_annotations`. |
| `1.3` | Customer-facing reachability projections: `crypto_entry_points`, `supporting_calls`, display aliases for constructor symbols. |
| `1.4` | Call-site object identity (`ReceiverVar`/`AssignedVar`/`ChainID`) and match columns on annotations/supporting calls, enabling cache-side object-lifecycle re-derivation. |
| `1.5` | `supporting_calls`, `crypto_entry_points`, `graph_algo_version` exposed end-to-end (paired with callgraph schema `6.2`). |
| `1.6` | Optional `resolved_receiver_type` on internal edges and external calls — lets the stitcher disambiguate interface-dispatch groups with more than one candidate in closure. |
| `1.7` | `internal_edges_compact` + `internal_edge_strings` — string/key-indexed compact edge encoding to keep large dependency fragments small. |
| `1.8` | `role: operation` contract methods exported as categorized supporting calls, no longer as operation-only entry points (paired with callgraph schema `6.5`). |
| `1.9` | Generic-erased function join signatures for Java source-type hierarchy stitching and optional direct-finding `purl` on crypto annotations, carried into rendered findings envelopes and finding graphs. |
| `1.10` | Optional `occurrence_key` on canonical `crypto_annotations`, propagated to stitched callgraph and findings-envelope outputs. |
| `1.11` | Optional `supporting_calls[].supporting_call.resolved_key_length` raw key-bit evidence for structurally derived configuration calls, including provenance and a source-call parameter reference, preserved to stitched callgraph output. |
| `1.12` | Optional `rule_declared_bits` and `rule_conflict` on that key-length evidence, marking a rule-declared key length that disagrees with the resolved value without overwriting either side. |

### Structure

| Field | Description |
|-------|-------------|
| `schema_version` | Fragment schema version (currently `graph-fragment-1.12`). |
| `scan_metadata` | Ecosystem, root module, tool/rules versions, `graph_algo_version` (callgraph-construction algorithm version; cache key for annotate-only re-annotation), and per-array counts. |
| `functions[]` | Callable nodes. `key` is the stable function identity (`pkg.(Type).name#arity`); also carries `file_path`, `package`, `type`, `name`, signature, etc. |
| `internal_edges[]` | Caller→callee edges **within** the component (both functions are in this fragment). Each edge may carry `entry_call` (1.2+, see below). |
| `internal_edges_compact[]` / `internal_edge_strings[]` | Compact (1.7+) encoding of internal edges: same fields as `internal_edges`, with repeated strings and function keys indexed into `internal_edge_strings` to keep large dependency fragments small. |
| `external_calls[]` | Calls whose target may live in **another** component; resolved at stitch time against the dependency tree. Each edge may carry `entry_call` (1.2+, see below). |
| `crypto_annotations[]` | Terminal crypto findings attached to a function. Beyond `function_key`/`finding_id`/optional `occurrence_key`/`rule_id`/`symbol`, a 1.2+ annotation carries the data-flow and metadata needed to reconstruct a findings entry (see *Crypto annotation fields (1.2+)* below). A component with no crypto still emits a fragment (zero `crypto_annotations`) so it can serve as a bridge in transitive chains. |
| `supporting_calls[]` | Non-finding config/lifecycle/context calls useful for explaining crypto behavior without increasing finding counts. |
| `crypto_entry_points[]` | Canonical reachability index: API functions plus display aliases and links to reachable findings/supporting calls. |

### Per-call data flow: `entry_call` (1.2+)

Every `internal_edges[]` and `external_calls[]` entry may carry an `entry_call`
describing the call-site argument data-flow for that edge — the same model the
finding-centric call graph export uses (see *Call Graph Export* above):
`entry_call.parameters[]` each have `parameter_index`, best-effort `type`,
`argument_expression`, `resolved_value`, `variable_name` (simple identifiers
only), and recursive `source_nodes` provenance. Carrying it **on the edge** is
what lets the stitcher rebuild full per-frame value flow when composing chains
across components, so a stitched chain matches a live run frame-for-frame.

### Crypto annotation fields (1.2+)

A `graph-fragment-1.2+` `crypto_annotations[]` entry carries enough to
reconstruct a full findings.json entry for the matched crypto call:

| Field | Description |
|-------|-------------|
| `crypto_call` | Identity and call-site argument data-flow of the matched crypto call (`function_name`, `line`, `parameters[]` — same parameter model as `entry_call`). |
| `oid` | Object Identifier for the cryptographic algorithm, when known. |
| `metadata` | Raw asset metadata block from the scanner. |
| `source` | How the finding was discovered: `direct` or `indirect`. |
| `matched_operation` | Kind / symbol / `expression` of the matched crypto operation. |
| `end_line` | Last source line of the crypto finding (often equal to its start line). |
| `match` / expression | The exact source expression that triggered the detection. |

### Rendered artifacts: `ToCallgraphExport` / `ToFindingsEnvelope`

Because a 1.3+ fragment carries per-call data flow, full crypto-annotation,
supporting-call, and entrypoint metadata, `pkg/graphfrag` can render a stitched
`Result` into the same two artifacts a live `--scan-dependencies` run produces:

- **`Result.ToCallgraphExport(root, meta)`** — renders the stitched result into
  a callgraph (zero-value meta stamps inlined `6.14`; `ScanMeta.InternedFrames` selects `6.17`). Align the render and sample budget explicitly when comparing with local CLI exports. Dep-component findings get
  `module@version/`-prefixed `finding_id`s, matching live output.
- **`ToFindingsEnvelope(root, deps, fragments, meta)`** — reconstructs the
  findings.json v1.6 envelope (asset metadata, including direct `purl`). Its `finding_id`s are computed
  with the **same inputs** as `ToCallgraphExport`, so the two agree: consumers
  join assets (envelope) to call chains (callgraph) by `(finding_id, occurrence_key)` when the key is present,
  or by `finding_id` for legacy records without `occurrence_key`.

`pkg/graphfrag/equiv` is a semantic diff tool that asserts a stitched callgraph
equals a live one minus the chains intentionally dropped by resolution
suppression (see below) — the equivalence guarantee these renderers rely on.

### Edge resolution metadata (v1.1+)

Every `internal_edges[]` and `external_calls[]` entry carries **resolution
metadata** describing *how confidently* the edge was resolved. This lets a
consumer distinguish exact typed calls from over-broad name/arity dispatch
guesses, and refuse to present the latter as typed reachability proof.

| Field | Description |
|-------|-------------|
| `resolution` | How the target was resolved: `exact`, `interface_dispatch`, or `name_only`. Absent ⇒ treat as unresolved/untrusted. |
| `declared_type` | The static/interface type at the call site (e.g. the interface whose method was dispatched). Present on dispatch edges. |
| `method_name` | The invoked method name, independent of the resolved target. |
| `arity` | The argument count of the call. |
| `resolved_receiver_type` | (1.6+) Concrete receiver type resolved by the producer's contracts-KB / return-type inference for an interface-dispatch call site, when available. Lets the stitcher disambiguate a dispatch group with more than one candidate; empty ⇒ fail-closed behavior unchanged. |

`resolution` values:

- **`exact`** — the receiver's static type was known and the method resolved to
  a unique declared target on that type (or an overload set on that exact type).
- **`interface_dispatch`** — the target was found by expanding an
  interface/abstract method to concrete implementations matching name + arity
  within a namespace root. Trustworthy only when exactly one implementation is
  present in the dependency closure; otherwise it is an ambiguous guess.
- **`name_only`** — the target was guessed by method name + arity (plus
  namespace heuristics) with no receiver-type anchor (e.g. fluent-chain
  fallback).

`method_name` + `arity` + the call-site line let a consumer **group sibling
candidates of one call site** so ambiguity can be detected across edges that
span the component boundary. The reference consumer (`pkg/graphfrag`'s stitcher)
applies a **tiered, fail-closed** policy: traverse `exact` edges and
`interface_dispatch` edges with exactly one implementation in the dependency
closure; **drop** ambiguous interface dispatch (>1 impl) and `name_only` edges,
recording them rather than emitting a chain. This is what prevents a DRBG's
`generate()` from name-colliding with `BCrypt.generate#3` (or
`provider.get(...)` fanning out to unrelated `get(...)` methods) from being
reported as reachable crypto.

> Fragments exported by older versions (without `resolution`) decode as
> unresolved and are treated as untrusted (fail-closed): under-report, never a
> false positive.

### Example

```json
{
  "schema_version": "graph-fragment-1.12",
  "scan_metadata": { "ecosystem": "java", "root_module": "org.bouncycastle:bcpkix-jdk18on", "graph_algo_version": "graph-algo-6", "function_count": 4000, "internal_edge_count": 6417, "external_call_count": 9469, "crypto_operation_count": 160, "supporting_call_count": 12, "crypto_entry_point_count": 42 },
  "functions": [
    { "key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1", "file_path": "org/bouncycastle/pkcs/PKCS8EncryptedPrivateKeyInfo.java" }
  ],
  "external_calls": [
    {
      "caller_key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1",
      "target_key": "org.bouncycastle.operator.(InputDecryptorProvider).get#1",
      "line": 90,
      "resolution": "exact",
      "method_name": "get",
      "arity": 1,
      "entry_call": {
        "file_path": "org/bouncycastle/pkcs/PKCS8EncryptedPrivateKeyInfo.java",
        "line": 90,
        "parameters": [
          { "parameter_index": 0, "type": "org.bouncycastle.operator.InputDecryptorProvider", "argument_expression": "inputDecryptorProvider" }
        ]
      }
    },
    {
      "caller_key": "org.bouncycastle.pkcs.(PKCS8EncryptedPrivateKeyInfo).decryptPrivateKeyInfo#1",
      "target_key": "org.bouncycastle.cms.(RecipientInformationStore).get#1",
      "line": 90,
      "resolution": "interface_dispatch",
      "declared_type": "org.bouncycastle.operator.InputDecryptorProvider",
      "method_name": "get",
      "arity": 1
    }
  ],
  "supporting_calls": [
    {
      "supporting_id": "cfg123",
      "function_key": "org.example.(Builder).configure#0",
      "category": "config",
      "matched_operation": { "kind": "call", "symbol": "org.example.Builder.withParameter" }
    }
  ],
  "crypto_entry_points": [
    {
      "function_key": "org.example.(Facade).encrypt#1",
      "function_name": "org.example.Facade.encrypt",
      "display_symbol": "org.example.Facade.encrypt",
      "reachable_findings": [{ "finding_id": "abc123", "chain_depth": 3, "finding_graph_ref": "abc123" }],
      "reachable_supporting_calls": [{ "supporting_id": "cfg123", "chain_depth": 2 }]
    }
  ],
  "crypto_annotations": [
    {
      "function_key": "org.bouncycastle.asn1.pkcs.(EncryptedPrivateKeyInfo).getEncryptedData#0",
      "finding_id": "abc123",
      "symbol": "getEncryptedData",
      "source": "direct",
      "end_line": 142,
      "match": "getEncryptedData()",
      "oid": "1.2.840.113549.1.5.13",
      "matched_operation": { "kind": "decrypt", "symbol": "getEncryptedData", "expression": "getEncryptedData()" },
      "crypto_call": {
        "function_name": "org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo.getEncryptedData",
        "line": 142,
        "parameters": []
      }
    }
  ]
}
```

In this slice, `decryptPrivateKeyInfo` has one **`exact`** edge to the real
`InputDecryptorProvider.get` and one over-broad **`interface_dispatch`** edge to
an unrelated `get#1` from the same call site (`line: 90`). A stitcher that sees
more than one implementation for that call site drops the ambiguous group.

## CycloneDX CBOM Format

CycloneDX 1.6 compatible Cryptography Bill of Materials format for standardized reporting.

### Features

- **Schema Validation**: Validates against CycloneDX 1.6 specification
- **Standardized Components**: Maps cryptographic assets to standardized component types
- **Rich Metadata**: Includes algorithm properties, evidence, and provenance
- **Industry Standard**: Compatible with CycloneDX ecosystem tools

### Supported Asset Types

| Type | Description |
|------|-------------|
| `algorithm` | Cryptographic algorithms (AES, RSA, SHA-256, etc.) |
| `certificate` | Digital certificates and certificate chains |
| `protocol` | Cryptographic protocols (TLS, SSH, etc.) |
| `related-crypto-material` | Keys, seeds, nonces, and other crypto material |

### Example Output

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-15T10:00:00Z",
    "tools": [
      {
        "vendor": "SCANOSS",
        "name": "crypto-finder",
        "version": "0.1.0"
      }
    ],
    "component": {
      "type": "application",
      "name": "scanned-project"
    }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "AES",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "block-cipher",
          "mode": "CBC",
          "padding": "PKCS5Padding"
        }
      },
      "evidence": {
        "occurrences": [
          {
            "location": "src/crypto/Example.java:29"
          }
        ]
      }
    }
  ]
}
```

### Converting Formats

Use the `convert` command to transform interim JSON to CycloneDX:

```bash
# Convert from file
crypto-finder convert results.json --output cbom.json

# Convert from stdin (pipe from scan)
crypto-finder scan /path/to/code | crypto-finder convert --output cbom.json

# Direct output during scan
crypto-finder scan --format cyclonedx --output cbom.json /path/to/code
```

### Integration

CycloneDX CBOM output can be consumed by:

- Dependency track systems
- Software Bill of Materials (SBOM) aggregators
- Security scanning platforms
- Compliance reporting tools
- Supply chain risk management systems

## Format Comparison

| Feature | Interim JSON | CycloneDX CBOM |
|---------|-------------|----------------|
| **Ecosystem** | SCANOSS-specific | Industry standard |
| **Detail Level** | High (findings metadata, code snippets) | Medium (structured metadata) |
| **File Size** | Larger | Smaller |
| **Best For** | Deep analysis, custom tooling | Compliance, integration, reporting |
| **Schema** | SCANOSS interim spec | CycloneDX 1.6 |
| **Validation** | SCANOSS tools | CycloneDX validators |

## Related Documentation

- [Main README](../README.md) - Usage and command reference
- [Dependency Scanning](DEPENDENCY_SCANNING.md) - How dependency scanning, call graph tracing, and attribution work
- [Docker Usage](DOCKER_USAGE.md) - Container-based scanning and format conversion
