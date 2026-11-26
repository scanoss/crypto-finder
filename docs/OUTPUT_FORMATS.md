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
| `metadata.algorithmSource` | On an asset whose algorithm stayed unresolved, the runtime inputs the algorithm argument is read from: `env:NAME` (an environment variable), `property:KEY` (a Java system or `java.util.Properties` property) or `argv:N` (a program argument, at the index the program reads), sorted and comma-joined, at most 16. Set only when the scan builds a call graph and a rule states a `parameterCondition` for the call; absent when the algorithm resolved or no input key is known. Not carried into the CBOM |
| `source` | `"direct"` (user code) or `"dependency"` (v1.2+) |
| `dependency_info` | Attribution for dependency findings: `module`, `version`, and optional `purl` (v1.5+) |
| `purl` | Optional canonical package URL promoted from direct rule metadata; it stays versionless unless one unambiguous direct dependency version is available (v1.6+) |
| `finding_id` | Stable short hash used to join the interim report to the call graph export (v1.3+) |
| `occurrence_key` | `v1:<16 lowercase hex>` structural identity, present on every asset whenever the scan built a call graph, so every asset that has a finding graph carries the key its graph carries. It excludes rules, source text, metadata, reachability, and severity. It uses the AST anchor of the matched call when there is one. A match with no call to anchor, such as a type usage (a cast or a declaration) or a library API declaration surfaced as an entry point, is keyed by the function that holds it; a valid top-level call uses a deterministic file/module-level fallback (v1.5+). A per-value asset, one a rule's `parameterCondition` specialized to a resolved value such as `param[0]==SHA-256`, also hashes that value, so the values of one call have distinct keys and `finding_id`s. A synthesized entry point (rule id `crypto-finder.api-entry-point`) that has several variants at one declaration, such as `PBKDF2` next to `PBKDF2-SHA-256` selected by an argument type (`param[0]:type==...`), or `ECDSA` next to `ECDSA-deterministic`, gives each variant except the base its own `finding_id` and `occurrence_key`, derived from the variant's `algorithmName`, `algorithmHashFunction` and `parameterCondition` (variants that share all three hash their whole metadata instead); the base keeps the identity a lone entry point has. Two calls of one API in a statement that spans lines get distinct keys; `finding_id` hashes file, start line and rule, so such a pair shares it and `(finding_id, occurrence_key)` is the unique pair. Every other asset hashes exactly the structural identity above. A report written without a call graph may omit it. |
| `parameter_conditions` | Structured argument predicates parsed from the rule's `parameterCondition` metadata — which argument value/type selects this asset variant (v1.4+, omitted when the rule carries no predicate) |
| `conditioned_value` | The resolved condition, such as `param[0]==HmacSHA256`, a per-value asset was specialized for. It is part of the asset's `finding_id` and `occurrence_key`, so a report read back by another scan, such as published dependency findings, keeps one identity per value (v1.7+, omitted on every other asset) |
| `terminal_start_col`, `terminal_end_col` | Columns of the call that encloses an asset matched on an argument span, such as `new KeyParameter(key)` inside `cipher.init(...)`. They locate the crypto call for the callgraph export and the `occurrence_key`, so a report read back by another scan finds the same call (v1.7+, omitted on every other asset) |
| `pqc` | Post-quantum classification of an asset that names an algorithm (v1.8+, omitted on every other asset): `status` (`vulnerable`, `safe`, `hybrid`, `not_applicable` or `unassessed`; new values may appear), `family` (omitted when `unassessed`), `deadline` (the earliest year any cited source sets: the worst case to plan against), `deadlines` (one entry per source: `source`, `deprecated_after`, `disallowed_after`, `migrate_by`, `citation`) and `dataset_version`. A CBOM carries the same classification as flat `scanoss:pqc*` properties |
| `file_path` | For dependency findings, path relative to the dependency root; use `dependency_info` for artifact identity |

### Related Material Followed From Random Draws

When the scan builds a call graph (`--export-callgraph`, `--export-graph-fragment` or `--scan-dependencies`), an asset whose rule reports a random draw (`algorithmPrimitive: drbg`) can be joined by a `related-crypto-material` asset at the same span, with the same rule, whose metadata holds only `assetType` and `materialType` (a CycloneDX relatedCryptoMaterial type such as `salt`, `nonce` or `initialization-vector`). The scan adds it when the drawn value, the variable the draw's result is bound to or the buffer a random-fill call (`rand.Read`, `nextBytes`, `fill_bytes`, `randomFillSync`, ...) writes, reaches an argument that the contract knowledge base declares as that material, also through up to three application functions it is passed to: `salt = os.urandom(16)` handed to a helper that calls `PBKDF2HMAC(salt=salt)` gives a `salt` asset at the `os.urandom` line. A value that may be rebound or overwritten before it is used, passed through a field, a collection or an interface call, or reaching contracts that disagree, adds nothing. A finding that already reports the same material at the draw is not given a second one. A plain scan without a call graph reports the draw alone.

### Public Go Contract

Go consumers can import `github.com/scanoss/crypto-finder/pkg/schema` to read or write the interim report without importing implementation packages. `InterimFormatVersion` is currently `"1.9"`.

The report always emits `version`, `tool`, and `findings`. `rules` is a value field and currently emits as `{}` when empty. The top-level `rules` block names the ruleset a scan used (`source`, `name`, `version`, `checksum_sha256`); for a remote ruleset, `checksum_sha256` is the lease's `payload_sha256` (never the hash of the per-tenant bundle) and the block also carries `lease` with `expires_at` and `signing_key_id` (v1.9+) (see [Remote Rulesets](REMOTE_RULESETS.md#leased-rulesets)); every other report omits `lease`. Findings always emit `file_path`, `language`, and `cryptographic_assets`. Assets always emit `start_line`, `end_line`, `match`, `rules`, `status`, and `metadata`; `start_col`, `end_col`, `parameter_conditions`, `conditioned_value`, `terminal_start_col`, `terminal_end_col`, `oid`, `finding_id`, `occurrence_key`, `source`, `dependency_info`, and direct `purl` are omitted when empty. Rules always emit `id`, `message`, and `severity`; `version` is omitted when empty. Dependency metadata always emits `module` and `version` when present.

The report preserves its JSON vocabulary: `severity` is `INFO`, `WARNING`, or `ERROR`; `status` is `pending`, `identified`, `dismissed`, or `reviewed`; and `source` is `direct` or `dependency`. Valid rule package URLs are promoted to top-level `purl` for direct findings. Dependency findings keep package identity in `dependency_info.purl`; unknown ecosystems omit it, and missing versions produce versionless package URLs. `CryptographicAsset` accepts the legacy singular `rule` input and migrates it to `rules` only when `rules` is absent or empty. When both are supplied, `rules` takes precedence. Internal terminal-column fields never serialize.

### Call Graph Export

When `--export-callgraph <file>` is passed, Crypto Finder also writes a separate finding-centric call graph JSON file to `<file>`. This export contains the reachability slices and value-flow details associated with findings from the interim report.

Schema note: local CLI callgraph exports default to interned **`6.18`**. Consumers must join identity through `functions[]` and `call_chain_indexes`; use `--export-callgraph-interned-frames=false` for inlined **`6.14`**. SDK/stitch zero-value options remain `6.14`. Version history:

- **`6.18`** (local CLI default; SDK opt-in) adds optional fields to chain frames, so a reader can check a route hop by hop without the source tree. `excerpt` is up to seven lines of the source the analysis read (`start_line`, `focus_line`, `lines`, `truncated`), centered on the line where the chain moves on from that frame; `excerpt_unavailable` (`no_source`, `unreadable`, `out_of_range`) says why a frame has none. The first frame of a chain carries `entry_rule`, the ID of the entry-point catalog entry that made it an entry point. `entry_call.call_site_column` is the column the call into the frame starts at. Every new field is optional; frame shape is otherwise the `6.17` shape.
- **`6.17`** (SDK opt-in; the CLI default before `6.18`) adds optional fields to the interned render. `finding_graphs[].dependency` names the dependency a dependency finding sits in and its route from the application in the resolved dependency graph, with `without_source` on a path step parsed without source. `finding_graphs[].analysis` gains `paths_total`, `paths_kept`, `route_evidence` and `no_callers_only`. The first frame of each live chain carries `root_kind` (`main`, `framework_entry`, `no_callers`, `depth_limit`). `unresolved_reason` gains three values for an attributed finding whose verdict is `unknown`: `traversal_truncated`, `unresolved_dispatch` and `dependency_without_source`; the stitched export now writes `unresolved_reason` too, with `unresolved_dispatch` only. Every new field is optional, so a `6.16` reader that ignores unknown properties keeps working; a reader that switches on `unresolved_reason` must treat an unknown value as unknown. Frame shape is the `6.15` interned shape. The stitched export now also writes `root_kind` and `no_callers_only`, when the fragments recorded entry kinds (`graph-fragment-1.14`).
- **`6.16`** (SDK opt-in; the CLI default before `6.17`) adds optional `scan_metadata.ecosystems` to the interned render. A target with first-party findings in more than one supported ecosystem, such as a Java service beside a TypeScript front end, gets one call graph per ecosystem, and each finding resolves against the graph of its own language. The list names every graph analyzed, the primary first, each with `ecosystem`, `root_module`, `function_count` and `edge_count`. `scan_metadata.ecosystem`, `root_module`, `function_count` and `edge_count` keep describing the primary graph, the one dependencies resolve for, so a consumer that reads only those fields is unaffected. The list is absent for a single-ecosystem export, which is otherwise unchanged, and from the inlined `6.14` compatibility render. Frame shape is the `6.15` interned shape.
- **`6.15`** (SDK opt-in; the CLI default before `6.16`) contracts `call_chains` frames: they no longer repeat catalog identity fields (`function_name`, `file_path`, `canonical_signature`, `dependency_info`, and the rest of the interned identity). Join through `functions[]` plus `finding_graphs[].call_chain_indexes`, and through `canonical_signature` on `crypto_entry_points` and catalog rows. Hop-specific fields (`entry_call`, `crypto_call`, `entry_resolution`) stay on the frames. Enable with `--export-callgraph-interned-frames` or `ScanMeta.InternedFrames`. Zero-value SDK/stitch stays on `6.14`; the CLI defaulted to `6.15` until `6.16`. Parsers that only read `call_chains[]` objects must gate on `schema_version` or call `HydrateChainIdentities`.
- **`6.14`** adds a top-level interned `functions[]` catalog and `finding_graphs[].call_chain_indexes` (0-based positions into that catalog) beside the existing inlined `call_chains`. The index lists reconstruct the same N-sample of routes. Inlined frames keep their previous field names and meaning. `crypto_entry_points` is still the complete reverse-reach set. Both surfaces can explicitly select this compatibility render.
- **`6.13`** adds `call_chains[].entry_resolution` and `entry_declared_type`, reporting how the call arriving at each frame was established.
- **`6.12`** adds the rule-vs-callgraph key-length conflict marker to `supporting_calls[].supporting_call.resolved_key_length`. When a detection rule declares a static `keyLength` and the callgraph resolves a different value for a finding referencing that evidence, the resolved `bits` stay primary, the rule value is retained as `rule_declared_bits`, and `rule_conflict` is `true`. Agreement, an unresolved key length, and a rule that declares no `keyLength` all leave both fields absent. The marker is computed during the scan, so consumers read it directly instead of re-deriving it from rule metadata.

- **`6.11`** adds optional `supporting_calls[].supporting_call.resolved_key_length` for structurally derived Java key-generation configuration calls referenced by `finding_graphs[].supporting_call_ids`. It contains raw integer `bits` only when static analysis resolves a literal or simple propagated constant, `provenance` (`constant` or `unknown`), and required `source_call` (`function_name`, `line`, `parameter_index`) for the contributing argument. It is preserved by live, graph-fragment, and stitched callgraph exports; terminal `crypto_call` records do not carry it, and it does not populate CBOM properties or express a security threshold.

- **`6.10`** carries an optional top-level `purl` for direct findings and an optional canonical `purl` inside dependency context. Live and stitched exports derive dependency URLs from the scan ecosystem and existing module/version fields, so cached graph fragments gain the field without a fragment schema change.

- **`6.10`** adds optional `occurrence_key` to canonical finding graphs; it is propagated from the interim report and graph fragments. AST anchors are preferred, with a deterministic file/module-level fallback for valid top-level calls. When present, `(finding_id, occurrence_key)` identifies the structural occurrence. Every finding graph of a current scan carries one, including synthesized entry points and matches with no call to anchor; only legacy records omit it and continue using `finding_id` alone.
- **`6.9`** makes `crypto_entry_points[]` a reverse-reachability answer rather than a projection of the exported `call_chains`: every function that reaches a finding is listed, so an entry point no longer depends on which chains survived collapsing or the per-finding chain budget. `chain_depth` is consequently the true minimum frame distance, and some depths are smaller than the same export previously reported. No field was added or removed. Live and stitched paths agree on both the index and the enumerated routes.
- **`6.8`** adds `finding_graphs[].reachability` (`reachable`/`unreachable`/`unknown`/`not_applicable`, where a self-chain fallback never counts and suppression or a depth limit that cut every route downgrades to `unknown`), `finding_graphs[].analysis` (`call_chains`/`parameters` completeness), and `crypto_entry_points[].root` — the explicit chain-root classification, the index itself staying deliberately broader. The legacy `reachable` bool is unchanged.
- **`6.7`** adds `reachable` to each finding graph when dependency scanning makes user-code reachability applicable; it is omitted for a standalone library scan.
- **`6.6`** adds deterministic `forward_calls.ambiguous_calls` groups for fail-closed interface dispatch: completeness state, stable group/candidate IDs, complete callable identities, and preserved call-site argument provenance — without promoting ambiguous candidates to resolved edges.
- **`6.5`** makes `role: operation` contract methods **supporting-call-only**: they are exported as categorized `supporting_calls` referenced by `supporting_call_ids` (including interface-authored contracts resolved to concrete implementations) and are no longer synthesized as operation-only `crypto_entry_points` in live, fragment, or stitched exports.
- **`6.4`** adds `method_role`, `role_provenance`, and `parameter_roles` — contracts-KB-derived method/parameter role classification (`factory`/`config`/`output`/`operation` on `method_role`; per-parameter `operation-determining`/`metadata-contributing`/`none` with a `contributes: {property, derivation}` block on `parameter_roles` (Node options-object roles add `argument_property`, the object property the derivation reads, an optional field of the same block)). `method_role`/`role_provenance` appear on `crypto_entry_points`; `parameter_roles` appears on `crypto_entry_points` and on the supporting-call declaration, index-aligned with `parameter_types` — never on call-site parameter literals. These fields are populated on the live (`--export-callgraph`) and graph-fragment export paths and carried through the stitched/served path.
- **`6.3`** added the optional per-finding `forward_calls` block — the finding anchor's forward call closure (deduped nodes with `depth`/`crypto_relevant`/`supporting_category`, plus traversed edges whose `entry_call` carries the call-site argument data-flow), emitted only when the stitch runs with `StitchOptions.ForwardClosure`; caps (depth/nodes/edges) are surfaced via `max_depth` and an explicit `truncated` flag, never silently.
- **`6.2`** exposed `supporting_calls`, `crypto_entry_points`, and `graph_algo_version` end-to-end.
- **`6.0`** removed the legacy `entry_point_index` projection and made `crypto_entry_points[]` canonical.
- **`4.3`** added Java runtime provenance in `scan_metadata` for JDK-aware platform signature enrichment.

- Each top-level record preserves `finding_id`. When `occurrence_key` is present, the composite `(finding_id, occurrence_key)` identifies the structural occurrence and joins it back to the interim report. Every finding graph of a current scan carries it, entry-point findings included; only legacy records without `occurrence_key` use `finding_id` alone.
- `call_chains` is the primary value-flow structure. Each chain is ordered from the first reachable caller to the function that contains the matched crypto call. The array is a capped sample, not the complete reverse-reach set. Local CLI defaults to 8 paths; `--export-callgraph-max-chains 128` opts in to a larger sample. SDK/stitch zero or omitted `StitchOptions.MaxChains` remains 128. The live export has no depth cap. The sample is spent on the strongest evidence first (see `analysis.route_evidence`): every route whose calls all resolved statically, then routes that need a dispatch edge, then routes that need a `name_only` edge. Within each of these, it goes to distinct routes first: one shortest route per chain root, recognized entry points before other roots, then further routes, and only then the same route at another call-site line, the most certain call site first. The route that justifies the verdict is therefore always among the kept chains. Where frames are attributed to dependencies, distinct routes of every tier come before variants of any tier: tier by tier, one route per chain root and one route through each library whose sequence of libraries no kept chain shows yet, and only then further routes. A small budget therefore shows the libraries a weaker tier reaches rather than more variants of a stronger tier's one path, and the first chain is still the strongest route. The stitched export orders its chains the same way by evidence, direct routes before dispatch routes.
- With user code known (dependency scanning, or `--export-callgraph-project-reachability`), a chain walks back through application code until it reaches an application function that no application code calls, instead of stopping at the first application frame. An application function follows only its application callers; library code follows every caller. The function holding the crypto follows every caller, so crypto in an application callback is reached through the library that calls it back. The first frame of each chain carries `root_kind`: `main` (a Java `static main(String[])`, or a free function named `main`), `framework_entry` (a Java method that is an `@Override` of a method of a type outside the application, such as `HttpHandler.handle` or `Runnable.run`, or one annotated with a Spring or JAX-RS request mapping, `@Scheduled`, `@EventListener`, or a Kafka, RabbitMQ, JMS or SQS listener imported from its framework), `no_callers` (any other application function nothing in the application calls; on a library scanned alone, a graph root), or `depth_limit` (where a depth limit stopped the walk, SDK callers only). An application function nothing calls is not a root at all, so what only it reaches reads `unreachable`, when its module has an entry point that shows it is a program: `main` (including a Python `__main__` guard, a console script, a `package.json` `main` or `bin` target and `require.main === module`, but not Go `init`, `<varinit:…>` or a static initializer, which libraries have too) or a `framework_entry` from the entry-point catalog (not the `@Override` and package-export heuristics). A module is the directory of the nearest `go.mod`, `package.json`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `Cargo.toml`, `pyproject.toml`, `setup.py` or `setup.cfg` above the function's file, so in a monorepo one application's entry point does not turn its sibling modules into dead code; a module without one keeps `no_callers` roots. Even in a module with an entry point, such a function stays a `no_callers` root when it is an instance method (an interface, trait or framework may call it without an edge in the graph) other than an instance method of a Java class that is not live. A Java class is live, and its uncalled instance methods stay roots, when any of these hold: it is an enum, interface or annotation type rather than a class or record; the application's Java source (every `.java` file under its modules, test sources included, outside hidden directories and the dependency and build directories at a module's top level, so a source package named `build` is read) creates it or names it: `new C(..)` with or without a class body, `C` anywhere in a created type (`new TypeReference<C>() {}`), `C::new`, `C.class`, or `C` as a word of any string literal (`Class.forName("app.C")`); `C` occurs as a word in a configuration file of an entry module (the extensions above, `.factories`, `.imports`, and the files under `META-INF/services/`); a class-level annotation other than `@Deprecated`, `@SuppressWarnings`, `@SafeVarargs` or `@Override` sits on it (`@Component`, `@RestController`, `@Path`, `@Named` and any unknown annotation count); it extends or implements, directly or through application supertypes, a type that resolves to no application class (a framework base, `Runnable`, `Serializable`, an unresolved name), since outside code may create or receive it and the method may override that type's method; or a subclass of it is live. Names are matched by simple name, so two classes sharing one make both live, a class two modules declare under the same fully qualified name is live, and when a Java source file cannot be read every class counts as live. Instance methods in Python, TypeScript and JavaScript, Go and Rust keep the old rule and stay roots. A Java instance method that passes is still subject to the reference and decorator rules below. Further, it stays a root when its name is referred to anywhere in the application's source besides its own declaration, or occurs as a word in a `.yaml`, `.yml`, `.xml`, `.json`, `.toml`, `.cfg`, `.ini`, `.properties` or `.conf` file of its module outside hidden, dependency and build directories (a function passed as a value: a router handler, a callback, a table entry, a handler a deployment file names), where a reference in source is an identifier the language parser reads in code: a name inside a comment, or inside a string literal that holds more than the name (`"/fingerprint?data=hello"`), is not one, a string literal that is exactly the name (`getattr(m, "fingerprint")`, `getMethod("fingerprint")`) is, and a qualified name (`liba.fingerprint`, `liba::fingerprint`, `Liba::fingerprint`) is not one when its qualifier is a name the file imports (in Rust, also a crate or module path written without an import) from a module, package or class whose last path segment is not the file stem, directory, package segment or type of any application function of that name (Go, Python, Java, JavaScript and TypeScript, Rust; C and C++ read strings and comments only; a file in another language is read word by word), when a decorator, attribute or annotation sits on it whose name is neither a test marker (`test`, a JUnit or TestNG annotation, `pytest.*`, `cfg(test)`; arguments are not read, so `@routes.post("/attest")` counts) nor an inert built-in: a Rust `allow`, `warn`, `deny`, `forbid`, `expect`, `inline`, `cold`, `track_caller`, `must_use`, `deprecated`, `doc`, `cfg`, `target_feature`, `rustfmt::*` or `clippy::*` attribute, or a `cfg_attr` that applies only such attributes (`#[no_mangle]`, `#[export_name]` and any other attribute still count); a Python `staticmethod`, `classmethod`, `functools.wraps`, `functools.cache`, `functools.lru_cache`, `contextlib.contextmanager`, `contextlib.asynccontextmanager`, `typing.overload`, `typing.override`, `typing.final`, `typing.no_type_check`, `abc.abstractmethod` or `deprecated` decorator, written qualified or bare; a Java `@Deprecated`, `@SuppressWarnings`, `@SafeVarargs` or `@Override` (every marker on a line is read, so `@SuppressWarnings("x") @Scheduled(..)` counts), or when its source cannot be read. The manifest lookup stops at the scanned project's root. Go `init` functions, `<varinit:…>`, Java `<clinit>` and Python and Node `<module>` bodies are always roots. Test code nothing calls is not a root in a module with an entry point. A cycle of application functions nothing outside it calls is rooted at its first member. The function holding the crypto is itself a root only when it is recognized as `main` or `framework_entry` and no application code calls it: a handler doing crypto inline reads `reachable`, a helper nothing calls reads `unreachable`. `crypto_entry_points[].root` follows the same roots.
- Entry point rules beyond those above. Which frameworks count, and the names each declares, is data: the entry-point catalog, one YAML file per framework under `reach/callgraph/entrypoints/<language>/<framework>.yaml`, built into the binary. An entry names the packages the framework comes from (`from`, a subpackage matches too), the names it declares, the shape the parser recognizes, and the `root_kind` it gives. A name counts only when the file brings it into scope from that package, never by the bare name: a Java annotation resolves through the file's single-type import, else its on-demand imports, else its own package, or is written qualified; a TypeScript or JavaScript decorator through its import, and a router through the import or declaration its value comes from (`app = express()`, `require('fastify')()`, a parameter typed `Express`); a Python decorator, callee or base class through its import or the module-level assignment its object comes from (`app = Flask(__name__)`, a function `@click.group()` makes); a Go receiver through its import, the declaration in scope (`r := chi.NewRouter()`, a parameter typed `chi.Router`) or a struct field of the file, and a method value through its receiver's type; a Rust attribute or callee through its `use` import (a glob import such as `use actix_web::*;` included) or its qualified path (`#[actix_web::get("/")]`, `axum::routing::get(h)`), and a bare attribute also through a crate a root of the package (`src/lib.rs`, `src/main.rs`, or the file's `src/bin` root) brings in with `#[macro_use] extern crate`; a Rust method call through the value it is called on, followed back through calls, method chains and the enclosing function's `let` bindings to the path it starts from (`Router::new()`, `web::get()`, `warp::path!(..)`). Shapes: `decorator` (an annotation or decorator on the function; in Rust an attribute on the function, or on an `impl` block, which makes every method of the block an entry), `registration_call` (a call that passes the handler, inline or by name, directly or through one wrapper call; in Python positionally after the path or as the `view_func=`, `endpoint=` or `route=` keyword argument; `path: required` asks for a path or method argument before it, or on the route it is chained to), `handler_field` (a field of a framework struct literal, `&cobra.Command{RunE: run}`), `supertype` (a method of a type that extends, implements or embeds a framework type, also through the application's own supertypes; a Python entry may add `directory` to count only files under a directory of that name, and name `<clinit>` for the class body: the body of a Django `Migration` under a `migrations` directory is an entry point, since the migration loader runs it and reaches the `RunPython` callbacks from there), `interface_method` (a Go method with the name and parameter types of a framework interface method, `ServeHTTP(http.ResponseWriter, *http.Request)`), `server_registration` (Go: a call of a generated `Register<Service>Server` or `Register<Service>HandlerServer` function, whose `names` are patterns; the methods of the value passed as its last argument that belong to the service become entries, found from the interface when the scanned tree declares it, else by gRPC signature) and `file_convention` (an export a framework finds by the file's location, counted only when the nearest `package.json` declares the framework). The catalog ships Java: Spring (MVC and WebFlux handler methods, `@Bean`, schedules, application events, STOMP, JMS, and its filter and servlet bases), Spring Kafka, Spring AMQP, Spring Cloud Stream and AWS SQS, Spring Integration, JAX-RS, Jakarta Annotations (`@PostConstruct`, `@PreDestroy`), Servlet, WebSocket, EJB timers, Micronaut, Quarkus and MicroProfile Reactive Messaging; TypeScript and JavaScript: Express, Koa (`koa`, `@koa/router`, `koa-router`), Fastify, Hono, NestJS and Next.js; Python: Flask (decorators, and views registered with `add_url_rule` on a `Flask` or `Blueprint`), Flask-RESTful, FastAPI (decorators, and `add_api_route`, `add_api_websocket_route`, `add_route` and `add_websocket_route` on a `FastAPI` or `APIRouter`), Starlette (decorators, and `add_route` and `add_websocket_route`), Sanic, Django (views, signal receivers, migrations), Django REST framework, Celery, click, typer, Dramatiq and RQ; Go: net/http, chi, gin, echo, gorilla/mux, cobra and gRPC; Rust: actix-web 4 (route attributes and `to()` handlers), axum 0.8 (method routers and `fallback`), Rocket 0.5 (route, catcher and `#[launch]` attributes), warp 0.4 (`map`, `then`, `and_then`, `or_else` and `recover` handlers), tonic 0.14 (`#[tonic::async_trait]` service impls), poem 3 (`#[handler]`) and poem-openapi 5 (`#[OpenApi]` impls), and `lambda_runtime`/`lambda_http` 1 (`service_fn`). A Rust `fn main`, including `#[tokio::main]` and `#[actix_web::main]` ones, is `main` by name. To add a framework, add its file and a fixture under `internal/scan/testdata/entry_rules/<language>/` with a case in `internal/scan/entry_rules_export_test.go`; the loader rejects an unknown field, a shape the language's parser does not recognize, a field the shape does not read, and a name two entries both claim for the same package. Language semantics that belong to no library stay in the parsers: TypeScript and JavaScript: the exports of the module the nearest `package.json` names in `main`, `module` or `exports` (`dist/`, `build/`, `lib/`, `out/`, `esm/`, `cjs/` and `es/` paths also match the same path under `src/` and at the package root), and `main` for the top level (`<module>`) of that module, of a module `bin` names, of a module a `package.json` script runs with `node`, `nodejs`, `tsx`, `ts-node`, `bun` or `deno` (`tsx scripts/seed.ts`, also after `&&`, `||`, `;` or `|`, with the same `dist/` to `src/` mapping), of a `.js`, `.mjs`, `.cjs`, `.ts`, `.mts` or `.cts` file whose first line is a shebang naming one of those runtimes, and of a module with `if (require.main === module)`; Python: `main` for the functions the nearest `pyproject.toml` (`[project.scripts]`, `[project.gui-scripts]`, `[tool.poetry.scripts]`), `setup.cfg` (`[options.entry_points]`) or `setup.py` names as `module:function`, and for the top level (`<module>`) of a module with `if __name__ == "__main__":`; Go: `main` for `init` functions and the synthetic `<varinit:…>` package variable initializers, which the runtime runs before `main`. Three kinds of call have no call expression and are now call edges: a JSX element with a capitalized name calls that component, a JSX attribute that names a function (`onClick={handleClick}`) calls it, and a function written inline as a call or `new` argument, or as a JSX attribute value, is called by the function that writes it, except a route handler, which is an entry point instead. These edges never serve as a finding's matched crypto call. In Rust (`graph-algo-rs-15`), a function passed as a value to a call (`alt((rsa_privkey, openssh_privkey))`, `map(f, ..)`) is called by the function that passes it, unless a framework registration makes it an entry point, and `s.parse::<T>()` calls `T::from_str`. Test code is never an entry point in any language: a method with a JUnit or TestNG annotation, or a function in a file under `test/`, `tests/` or `__tests__/` or named like a test (`*Test.java`, `*_test.go`, `test_*.py`, `*_test.py`, `conftest.py`, `*.test.*`, `*.spec.*`), keeps `no_callers`, and in a module with an entry point is no root. Test sources are in the graph only under `--include-tests`.
- `analysis.paths_total` is the number of distinct routes, from a chain root to the finding, the graph holds, and `analysis.paths_kept` the number the finding's `call_chains` show; chains that differ only in a call-site line count once. `paths_total` saturates at the largest int64 and is then a lower bound. Both are present on live findings with a chain: reachable ones and `unresolved_dispatch` ones. `analysis.call_chains` is `partial` whenever routes were left out or a depth limit cut the walk. There is no path-count ceiling any more: a finding with millions of routes gets its sample of chains and reads `reachable`, not `unknown` with no chains. A depth limit that cuts every route before a root reads `unknown` with `unresolved_reason` `traversal_truncated`; that reason, unlike the others, comes without `finding_location`, since the finding is attributed. A finding whose every route crosses a `name_only` edge reads `unknown` with `unresolved_reason` `unresolved_dispatch`, also without `finding_location`: its chains are exported as evidence of how the crypto may run, and the legacy `reachable` flag is omitted. One route free of `name_only` edges keeps it `reachable`. `analysis.route_evidence` rates the finding's strongest route by its weakest call: `direct` (every call `exact` or statically resolved), `dispatch` (the best route needs at least one `interface_dispatch` or `python_subclass_dispatch` edge and no `name_only` edge; the finding stays `reachable`, and the dispatch hop is the frame whose `entry_resolution` names it), or `name_only` (every route needs a `name_only` edge; the verdict is `unknown` with `unresolved_dispatch`). A finding specialized by a `parameter_conditions` predicate that removed chains rates `route_evidence` and `no_callers_only` from its surviving chains only, so a condition that refutes the direct route cannot leave `direct` behind; with no chain left both are absent. The verdict follows the same chains: a specialized finding whose surviving chains all cross a `name_only` edge reads `unknown` with `unresolved_dispatch`, even when another value of the same function has an exact route. A value reached only from a caller nothing calls keeps the verdict any finding so reached has (`reachable`, flagged `no_callers_only`). It is present with `paths_total` on the live export, and on stitched findings that are `reachable` through a chain or `unresolved_dispatch`; a stitched finding proven only by a dependency's mine-time entry-point index has no frame-by-frame route and carries none. `analysis.no_callers_only` is `true` when every root of the routes that support the verdict has `root_kind` `no_callers`: the crypto is reached only from application code nothing in the application calls, not from a recognized `main` or framework entry. The supporting routes are those free of `name_only` edges, or every route when none is, and all of them count, not only the kept chains. It is omitted when false. The stitched export sets it the same way, over every root that reaches the finding (not only the kept chains), but only when the root component's fragment recorded entry kinds (`graph-fragment-1.14`): a root of an older fragment could be a framework entry the scan could not mark, so such a finding never claims it, and its chains carry no `root_kind`. On the stitched export a root reads `main` or `framework_entry` from the fragment's `entry_kind`, and `no_callers` when it has none and nothing in the stitched graph calls it; `depth_limit` never appears there. A finding proven only through a dependency's entry-point index has no route and does not claim it. The stitched export, which follows no `name_only` edge, reads such a finding `unknown` with `unresolved_reason` `unresolved_dispatch` and no chain, and a dependency's mine-time entry-point index does not upgrade it to `reachable`; it sets no other `unresolved_reason`. CLI omits the optional complete reverse-reach index unless `--export-callgraph-entry-points=true`; sample budgets do not filter that index. Policy: [ADR 0002](adr/0002-call-chains-sample-size.md).
- `functions[]` (schema `6.14`+) is the interned identity catalog for those emitted routes. `finding_graphs[].call_chain_indexes` lists the same walks as integer positions into that catalog. Schema `6.14` also inlines those fields on `call_chains` frames. Schemas `6.15` to `6.18` (`6.18` is the local CLI default) join identity through the catalog alone.
- Each chain node carries hop-specific fields: optional `entry_call`, `entry_resolution`, and `crypto_call` on the last node. Compatibility schema `6.14` also inlines function identity (`function_name`, `file_path`, `canonical_signature`, `dependency_info`) on each frame. The interned render (`6.15`+) keeps that identity only in `functions[]`.
- `entry_call` describes how execution entered the current node from the previous step. Its `file_path` and `line` refer to the call site in the previous node's source file, and `call_site_column` (`6.18`+, live export only, when the parser recorded it) to the 1-based column the call expression starts at.
- `excerpt` (`6.18`+) is the source around a frame's focus line, so a reader can verify each hop, dependency frames included, without the source tree. The focus line is where the chain moves on: on every frame but the last, the call into the next frame (that frame's `entry_call.line`); on the last frame, the matched crypto call (`crypto_call.line`); the function's `start_line` when neither is known. The window is the focus line and three lines either side, clipped to the file: `start_line` is the number of `lines[0]`, `focus_line` the focus line, `lines` the verbatim lines without line endings, each cut to 240 characters, with `truncated: true` when one was cut. The live export reads only files under the scanned target or a dependency source directory the scan resolved (an extracted source jar, the Go module cache, a Cargo registry source, `node_modules`, `site-packages`), after resolving symlinks, and reads each file once while the files it holds fit in 64 MiB. A frame without an excerpt carries `excerpt_unavailable`: `no_source` (its file is outside those directories, for example a dependency joined for its types only, or the export is stitched from graph fragments, which carry no source; the stitched export writes it on every frame), `unreadable` (reading the file failed) or `out_of_range` (the focus line is not a line of the file).
- `entry_rule` (`6.18`+) is on a chain's first frame when its `root_kind` is `main` or `framework_entry` and an entry-point catalog entry recognized it. It reads `<language>/<framework>:<shape>[:<directory>]:<first name>`, the entry's first declared name standing for the whole entry: `java/spring:decorator:RequestMapping` for any Spring request-mapping annotation, `node/nextjs:file_convention:app:default`. Each catalog entry has a distinct ID. It is absent when language semantics made the frame an entry point (a `main` function, an `init` function, a Java `@Override` of an external type) and on the stitched export.
- `entry_resolution` says how the edge from the previous step was resolved: `exact` (the receiver's static type and the call's argument types identify the target, including a method inherited from the nearest declaring superclass, and a declared function handed to a known callback-invoking API such as `threading.Thread(target=fn)`, `sort.Slice(xs, fn)` or `setTimeout(fn, 1)`, reached from the function that registers it), `interface_dispatch` (an interface or abstract-class call expanded to a method of a real subtype of `entry_declared_type`, from the bytecode hierarchy or the parsed extends/implements clauses), `python_subclass_dispatch`, or `name_only` (a match by method name and arity with no type proof: a fluent-chain fallback, or a dispatch candidate whose class hierarchy is only partly known or names a type whose simple name several known types share, kept because nothing proves it is not a subtype; with dependencies scanned, such a candidate is kept only when its artifact is the declared type's, is the project, or depends on the declared type's artifact). A Java type name is treated as certain only when the source spells it fully qualified, or when the file declares no type parameter or local class of that name and at most one type of that simple name exists in the scanned source and indexed bytecode; Java's scoping rules are not modeled beyond that. The graph cannot see a subtype relation it has no record of, for example one through a member type inherited from a supertype in an unindexed jar when a graph type of the same simple name sits in the caller's package, so such a gap can still hide a path. The local CLI export and the stitched export both fill it; it is absent on a chain's first frame.
- The last node in each chain carries `crypto_call`, which is the matched crypto-relevant call for the finding.
- `entry_call.parameters[]` and `crypto_call.parameters[]` both use the same parameter model: `parameter_index` (always `0`-based), best-effort `type`, `argument_expression`, `resolved_value`, `variable_name` for simple identifiers only, and recursive `source_nodes`.
- `supporting_calls[].supporting_call.resolved_key_length` is optional evidence scoped to key-generation configuration calls, either structurally derived siblings of the finding's call or, when the call the rule matched fixes the key size itself, the finding's own call emitted as a supporting-call entry (Python `rsa.generate_private_key(key_size=...)`, Go `rsa.GenerateKey`, C `RSA_generate_key_ex` and `EVP_PKEY_CTX_set_rsa_keygen_bits`, Java `KeyPairGenerator.initialize(int)` and the `RSAKeyGenParameterSpec` constructor). A matched call that contributes no key size is not echoed as a supporting call. Go and C contracts without `parameter_types` resolve a literal key-size argument positionally; each Go, C and C++ `keySize` argument is classified as bits or bytes against the library's own documentation, and a byte count is reported as bits (`wc_AesSetKey(aes, key, 16, ...)` is 128). Where the unit is unclear, no key length is reported. The Java set is: `javax.crypto.KeyGenerator.init(int)`, `java.security.KeyPairGenerator.initialize(int[, SecureRandom])`, and the `RSAKeyGenParameterSpec`, `ECGenParameterSpec`, and `SecretKeySpec` constructors whose value reaches such a call. `source_call.function_name` names the call the size was read from, which is the spec constructor when the size travels through a parameter object. Join the supporting declaration to a finding through `finding_graphs[].supporting_call_ids`. It reports raw key bits when known and otherwise retains `provenance: "unknown"` plus `source_call`; consumers must not infer a key-size threshold from it. The terminal `crypto_call` remains the detected operation and does not carry this field; its key size is read from the supporting-call entry above. Elliptic-curve and DSA sizes are looked up from the argument rather than read from it: a curve name or constructor (`ECGenParameterSpec("secp256r1")`, Python `ec.SECP384R1()`, Go `elliptic.P256()`) yields the curve's field size, and a Go `dsa.L2048N256` constant yields its modulus size L. The Bouncy Castle `RSAKeyGenerationParameters` and `DSAParameterGenerationParameters` constructors and the DSA, DH and ElGamal `*ParametersGenerator.init(size, certainty, random)` calls carry their strength in bits, which reaches a generator's `init(params)` through the argument source. A curve or parameter set the tables do not list stays unresolved, and so does a curve held in a variable the parser does not trace. Node.js `crypto.generateKeyPair`, `generateKeyPairSync`, `generateKey` and `generateKeySync` read the size from a property of the options object literal that the key type selects (`modulusLength` for `rsa`, `rsa-pss` and `dsa`, `primeLength` for `dh`, `length` for `aes` and `hmac`, all bits, and `namedCurve` for `ec`, looked up); `source_call.parameter_index` is the options argument. An options object that is a variable, a spread or computed key, a non-literal size, or a key type that is not a string literal reports no size. Bouncy Castle EC lookups (`ECNamedCurveTable.getByName`, `SECNamedCurves`, `NISTNamedCurves`, `TeleTrusTNamedCurves`, `CustomNamedCurves`, `ECNamedCurveTable.getParameterSpec`, `ECNamedCurveGenParameterSpec`) yield the curve's field size from a literal name, which reaches `ECKeyPairGenerator.init(params)` and `KeyPairGenerator.initialize(spec)` through the argument sources; when producers behind one argument name different curves, no key length is reported.
- A size or curve fixed in another method than the finding's call still resolves. An argument that is a parameter of the enclosing method (`kpg.initialize(size)`, `new ECGenParameterSpec(curve)`) takes the value its call sites pass, only when every call site passes the same literal or constant, through at most four call sites; call sites that pass different values leave `provenance: "unknown"` with no `bits`. When the method returns the finding's object (`return KeyPairGenerator.getInstance("RSA")`, or a variable bound to it), the calls each caller makes on the returned object (`kpg = newKpg(); kpg.initialize(2048)`) are supporting calls of the finding, each with its own `resolved_key_length`, through at most three returning methods. `annotate` re-derives the same caller-side calls from a `graph-fragment-1.15` fragment, which records the calls each function returns in `functions[].returns_calls`; from an older fragment it does not include them.
- A Go `crypto/ecdh` call takes its key size from the curve it is invoked on: `ecdh.P256().GenerateKey(rand.Reader)`, `ecdh.P384().NewPrivateKey(b)`, or the same call on a local variable bound once by `c := ecdh.P521()` yield 256, 384 and 521 bits. The finding's own call carries `resolved_key_length`, and `source_call` names the curve constructor (`crypto/ecdh.P256`) at its line with `parameter_index` 0, since the constructor takes no argument. A curve parameter, a variable bound more than once, a variable whose address is taken, a curve held in a struct field, and `ecdh.X25519()` report no key length.
- `supporting_calls[].supporting_call.resolved_key_length.rule_conflict` reports that a detection rule declared a static `keyLength` disagreeing with the resolved `bits`. The resolved value remains primary and the rule value is preserved in `rule_declared_bits`, so neither side is lost. Both fields are absent when the two agree, when no key length was resolved, or when no rule declared one. A supporting call is shared by every finding that reaches the same crypto object, so the marker is a property of that shared evidence: it means **at least one** referencing finding declared a different key length, not that every one did, and it does not identify which. When several referencing findings disagree, `rule_declared_bits` reports the smallest disagreeing value, which keeps the output stable regardless of rule ordering. Per-finding attribution is not recoverable from this field.
- For Java scans, `scan_metadata` may also include `java_requested_jdk_major`, `java_runtime_version`, `java_platform_signatures_used`, `java_platform_signature_source`, and `java_platform_signature_unavailable_reason` to show which JDK major was requested and whether JDK platform signatures contributed to type enrichment.
- For Java, a local or parameter that its method writes again after the declaration (assignment, compound assignment, `++`/`--`, in any branch, loop or block) exports a variable node with no nested `source_nodes`: it has no single source, so neither the declaration's value nor a caller's propagated value is attached. Java traces a call's arguments up to six nested levels deep.
- `source_nodes` can span multiple wrapper hops. A local `PARAMETER` node may contain nested upstream provenance such as `PARAMETER -> PARAMETER -> VALUE`, and propagated nested nodes keep `location.file_path` plus `location.line` when known.
- Method-call provenance is preserved as `CALL_RESULT` nodes. When the parser can resolve the invoked method, the node also exports `call_target`, and any traceable receiver value is nested under that `CALL_RESULT` via `source_nodes` (for example `CALL_RESULT -> PARAMETER alg -> VALUE SignatureAlgorithm.HS256`).
- `finding_graphs[].reachability` is `not_applicable` for every finding of a scan that resolved no dependency set, because such a target is read as a library scanned on its own, where a function nothing calls is public API rather than dead code. `--export-callgraph-project-reachability` treats the target as an application instead: its own source packages become the user code, the same set a `--scan-dependencies` run uses for first-party findings, so first-party verdicts match that run. First-party code that only a dependency reaches, through a callback or an interface the dependency calls, reads `unreachable` here because the dependency's code is not in the graph; `--scan-dependencies` follows it. A scan that resolved dependencies ignores the flag, and `--export-graph-fragment` is unaffected.
- A finding whose rule carries `parameter_conditions` keeps only the chains whose matched call satisfies them, reading each argument as the chain's caller passes it. A chain is dropped when a resolved argument contradicts a condition; a chain whose arguments did not resolve is kept when no chain matched. When every route was examined and every one contradicts the condition, the finding reads `unreachable` (`reachable: false`, no `call_chains`): the crypto the rule describes runs on no known route, and the graph fragment's `crypto_entry_points` do not list it either. When the chain budget (`--export-callgraph-max-chains`) left a route or a call site unexamined, it reads `unknown` with `unresolved_reason: "traversal_truncated"` and `analysis.call_chains: "partial"`.
- A dependency finding carries `finding_graphs[].dependency`, on the live and stitched exports: the dependency it sits in (`module`, `version`, `purl`, the versioned package URL), `relationship` (`direct` when the application declares it, `transitive` otherwise) and `path`, its shortest route from the application in the resolved dependency graph, not in the call graph. That graph comes from scanoss.go's dependency resolver (`pkg/dependencies/resolve`): the project's lockfile for npm, Cargo, Poetry and uv, and the `go` and `mvn` tools for Go and Maven. A Go module `go.mod` marks `// indirect` is `transitive`, and each module of a Maven reactor declares its own `direct` dependencies. A module that resolver does not know, for example in a pip environment without a lockfile or a Gradle build, takes its route from crypto-finder's own resolution instead; a module it knows but does not connect to the application, such as a lockfile entry nothing depends on, has no `relationship`. `path` lists `module`, `version` and `purl` per dependency, a direct dependency first and the finding's own dependency last; the application itself is `scan_metadata.root_module` and is not listed. Where several routes exist, one through dependencies parsed with source is preferred over a shorter one that is not, and ties break on module name. A module the resolution picks at more than one version (npm can install one package twice) is told apart by version: with a versioned dependency graph each copy has the route it really has, so `lodash` 4.17.21 can be `direct` while the copy nested under another package is `transitive`, and each path step names its own `version`. Without one, `relationship` and `path` are absent for a finding in such a module, and for any dependency whose route crosses one, rather than reporting a route that may belong to the other copy; `purl` and `version` stay. `relationship` and `path` are absent when the dependency graph was not resolved (for example a Maven tree that timed out) or does not connect the dependency to the application. A first-party finding has no `dependency` block; its top-level `purl` keeps its meaning, the package URL of the rule's library, and stays empty on a dependency finding. The block is optional and new in interned schema `6.17`. The inlined `6.14` compatibility render carries it too, and `schemas/callgraph-schema.json` declares it there.
- A dependency finding's verdict comes from the SCANOSS API, which stitches the project's call sites into every mined dependency graph of the pinned closure (`--scan-dependencies`, see [Dependency Scanning](DEPENDENCY_SCANNING.md)). The call sites are those of the project functions the roots above reach, so a dependency finding reached only from a function that reads as dead code is `unreachable`. `unresolved_reason` names why an `unknown` verdict could not be decided (for example `ambiguous_dispatch` or `dependency_without_graph`), and up to `--dependency-reachability-max-chains` chains come back per finding.
- Findings missing a containing function or crypto-call match are still exported with `finding_location` and `unresolved_reason`. `no_containing_function` means the finding's language was analyzed and no function encloses it; `no_crypto_call_match` means no call at the finding's position matched. `language_not_analyzed` means no call graph exists for the finding's language in this scan, because the language has no call graph parser (Kotlin, for example) or its graph failed to build; its `reachability` is `not_applicable` because nothing about it was examined.
- A target with first-party findings in several supported ecosystems resolves each finding against the call graph of its own language. The graph of an ecosystem other than the primary covers first-party source only, and its first-party findings are classified the way the primary ecosystem's are, against their own source packages when dependencies were resolved or `--export-callgraph-project-reachability` is set, and `not_applicable` otherwise. The export's fields and schema version are unchanged. The graph fragment (`--export-graph-fragment`) covers the primary ecosystem only.
- `crypto_entry_points[]` is the stitch/API index. Each entry carries `function_key`, canonical/display symbols, aliases, and `reachable_findings[]` / `reachable_supporting_calls[]`.
- `supporting_calls[]` carries config/lifecycle/context crypto-adjacent calls, such as builder options or parameter setup. These calls are not findings and do not inflate `finding_graphs[]`. As of `6.5`, `role: operation` contract methods (the calls where the cryptographic computation actually executes, e.g. block-processing/finalization methods) are also exported here with a category and referenced via `supporting_call_ids`.
- Constructor joins remain canonical (`<init>`), while display fields and aliases expose IBM-style names such as `com.acme.Factory.Factory`.
- `entry_point_index` is not emitted by schema `6.0`. Consumers should migrate to `crypto_entry_points[]`.

### Compatibility and consumer gating

The published JSON Schemas are [`schemas/interim-report-schema.json`](../schemas/interim-report-schema.json), [`schemas/callgraph-schema.json`](../schemas/callgraph-schema.json) (inlined `6.14`), [`schemas/callgraph-schema-6.15.json`](../schemas/callgraph-schema-6.15.json) (interned `6.15`), [`schemas/callgraph-schema-6.16.json`](../schemas/callgraph-schema-6.16.json) (interned `6.16`), [`schemas/callgraph-schema-6.17.json`](../schemas/callgraph-schema-6.17.json) (interned `6.17`), and [`schemas/callgraph-schema-6.18.json`](../schemas/callgraph-schema-6.18.json) (interned `6.18`, the local CLI default). Validate against the exact emitted version; undeclared properties are contract failures. Consumers without catalog hydration must explicitly request `--export-callgraph-interned-frames=false`.

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
public package `github.com/scanoss/reach/graphfrag`, so downstream
consumers can use one contract instead of reimplementing schema knowledge.

Current schema version: **`graph-fragment-1.39`** (`reach/graphfrag.SchemaVersion`).

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
| `1.14` | Optional `functions[].entry_kind` (`main` or `framework_entry`) on a function the producing scan recognized as an entry point, and `scan_metadata.entry_kinds`, which says the scan recorded entry kinds at all. The stitched callgraph export reads them to write `root_kind` and `analysis.no_callers_only`. A fragment without `scan_metadata.entry_kinds` (`1.13` and older) still loads; its roots get no `root_kind` and its findings never claim `no_callers_only`. |
| `1.15` | Optional `functions[].returns_calls`, the sorted callee keys of the calls whose result the function returns (`return f()`, or a variable bound to `f()` and returned), each a callee the function calls exactly once. `annotate` reads it to follow a crypto object a helper returns into the callers that keep it, so the callers' configuration calls on it (`kpg = newKpg(); kpg.initialize(2048)`) are supporting calls of the finding, as in a scan. A fragment without it (`1.14` and older) still loads, and `annotate` follows no returned object for it. |
| `1.22` | Writes once what earlier versions repeated; `scan_metadata` names each elision and `reach/graphfrag` restores it (`GraphFragmentExport.RestoreElided` after decoding, which `ToFragment` and `DecodeFragment` run), so a reader sees the `1.21` form. `shared_entry_calls`: an edge with no `entry_call` takes the one the last edge at its call site (caller, `line`, `start_col`, `end_col`, `arity`; internal edges first, then external calls) wrote, and `"entry_call": {}` stands for none. `implicit_source_files`: a source location with a `line` and no `file_path` is in the file of the function it belongs to (an edge's caller, a call anchor's or constant reference's function, the function a `return_sources` entry is of); `no_file: true` marks one that has no file. `derived_function_names`: a function without `package`, `type` and `name` takes them from its key, one without `function_name` takes `package.Type.name` (no `#arity`), one without `display_symbol` takes its `function_name`, and one without `erased_signature` its `canonical_signature`. `derived_target_names`: an external call without `target_function_name` takes it from `target_key` (a method key's `package.Type.name`, or a bare `name#arity` without the arity). Crypto sections are never elided. The `1.21` call data (`call_anchors` callee, text, arguments and argument provenance, `functions[].parameter_names` and `return_sources`, `external_signatures`) is written for Java fragments and, without a schema bump, for Python ones (`graph-algo-py-26` and later), the languages `annotate --scanner cards` reads without source. |
| `1.23` | `rebind_lines` and `scan_metadata.rebind_lines` (Java fragments; Python ones from `graph-algo-py-26`, no schema bump): for each variable a function passes to a call as a bare argument, the lines of its body, from its first line to its last call, that may give it another value or overwrite its buffer, as positional arrays `[function, name, line, ...]`; `[function]` alone marks a function whose source the producer could not read. The related-material pass reads them without the source, so `annotate` follows a buffer `random.nextBytes(iv)` fills to its use over lines `source_lines` does not hold, as a scan does. A `1.22` fragment still loads; without the source the pass then follows such a buffer only to a use on the next line. |
| `1.24` | `abstract` on a function declared without a body (a Java interface method that is not `default` or `static`, an `abstract` method) and `scan_metadata.abstract_methods` (Java fragments; Python ones from `graph-algo-py-25`, no schema bump), which says every such function is marked. The stitch then reads an unmarked method as a body a call on its type may run: an override of it is one more dispatch candidate, so a route only through the override is served `unknown` (`ambiguous_dispatch`) unless the receiver's resolved type picks it. A `1.23` fragment still loads, and the stitch reads its methods as before. |
| `1.25` | `service_providers` (Java fragments only): the classes the component registers for `java.util.ServiceLoader`, read from every `META-INF/services/<service type>` file under the scanned sources (comments and blank lines dropped, test resources skipped with the test sources), as an object from the service type's binary name to the registered classes' binary names in file order (`{"org.apache.tika.parser.Parser": ["org.apache.tika.parser.pdf.PDFParser", ...]}`). The application reachability stitch reads each registered class's implementation of a service type method (its own or inherited body, matched by name and parameters) as an implementation of that method: a call on the service type (tika-core `CompositeParser.parse` calling `Parser.parse`) dispatches to the registered implementations the dependency closure declares, under the standard dispatch policy (several candidates: `unknown`, `ambiguous_dispatch`). An unregistered subtype never joins this way. The project's own registrations travel in the request's call sites. A `1.24` fragment still loads with no registrations. |
| `1.26` | Rust scope facts (Rust fragments, `graph-algo-rs-4` and later; a Rust graph now carries its own graph algorithm id). `imports` lists each file's `use` and `extern crate` bindings as written, paths unresolved, one binding per leaf of a grouped use, each with its declaration's span (`start_col`, `end_col` 1-based, end exclusive, `end_line` only when it spans lines) and use tree (`text`). `items` lists, by file, the items a file declares at any depth (`mod`, `fn`, `impl`, `trait`, `const`, `static`, `struct`, `extern_crate`; from `graph-algo-rs-12` also `block`, a block of a function body other than the body that declares a `use` or `extern crate` of its own, with no name) as positional arrays `[line, start_col, end_col, kind, name, end_line?]`, so a reader places a call or a use in the items that enclose it. `constant_refs` and `declarations` are also filled for Rust. A `1.25` fragment still loads, without imports or items. |
| `1.30` | Rust fragments (`graph-algo-rs-7`). `binary_exprs` lists, by file, every binary expression of each file's function bodies (`s * base`, `&s * &p`, `a == b`), nested ones and those in a macro's arguments included, as positional arrays `[line, start_col, end_col, op, left, right, left_end_col, right_start_col, function, end_line?, left_end_line?, right_line?]`: the operator and both operands as written, the columns where the left operand ends and the right one starts, and the key of the function that holds the expression. A `fn` item of `items` gains a trailing field, its parameters in order, each `[line, start_col, end_col, pattern, type, end_line?, self?]`: the pattern and the type as written (`mut key`, `&acme::Key`), `self` true for a receiver. A `1.29` fragment still loads, without either. |
| `1.32` | Go fragments (`graph-algo-go-12`; `1.31` is reserved for Node). `imports` lists, by file, each spec of each Go file's import declarations as written: `module` the import path, `alias` the name written before it (absent for none, `.` for a dot import, `_` for a blank one), with the spec's span (`start_col`, `end_col` 1-based, end exclusive, `end_line` only when it spans lines). A rule's `import $P "p"` binds only an aliased import of `p`, and the cards engine reads the alias here. A `1.30` Go fragment still loads, without imports; such a rule then also matches unaliased imports. |
| `1.33` | Rust fragments (`graph-algo-rs-9`). `constant_refs` also list a one-segment path a function body reads as a value whose name starts with an upper-case letter (`&X25519` after `use ring::agreement::X25519`, `SysRng`; not `None`, `Some`, `Ok`, `Err` or `Self`), wherever it is read but in a pattern, a longer path, a callee or a macro's name, and the path of every struct literal, of one segment or more, with the position kind `struct` (`acme::Key { bits: 1 }`). The arrays keep their layout; an older fragment still loads, without them. |
| `1.34` | Go fragments (`graph-algo-go-13`). `go_values` lists, by file, each Go file's composite literals (`tls.Config{MinVersion: v}`, `&rsa.PSSOptions{...}`, nested ones included), `new(T)` expressions and field stores (`cfg.CipherSuites = v`): `kind` (`composite`, `new`, `store`), the span (a literal's leading `&` at `addr_col`), the type as written and qualified (`type_text`, `package`, `type`), a store's `receiver`, the `fields` (name, value as written, value span) and the holding `function`. The cards engine matches Go rules written as such expressions against them. A `1.32` Go fragment still loads, without them; such rules then match nothing. |
| `1.35` | Rust fragments (`graph-algo-rs-10`). `constant_refs` also list each path written as a whole type (a field, a parameter, a return type, a `let` annotation, a cast, a type alias, an impl's self type, a const or static item's type, a generic argument, a reference's referent, a tuple or array element, a `dyn` or `impl` trait), as written (`SysRng`, `acme::Key`), with the new position kind `type`; one-segment names follow the rule of `1.33`. A generic type's head (`Key<u8>`), a trait bound or where predicate, an impl's trait and a qualified path are left out. A reference in a fn's signature belongs to that fn; one outside any fn belongs to the file's `<varinit:<file>>` function. The arrays keep their layout; a `1.34` fragment still loads, without them. |
| `1.36` | Go fragments (`graph-algo-go-15`). `go_blocks` lists, by file, the extent of every block of each Go function body (the body, if/else and for bodies, bare blocks, function-literal bodies, and each `case`/`default` clause), with the holding `function`. `go_values` gains the kind `assign`: an assignment to plain names, with `names` (every left-hand name), `op` (`:=`, `=` or `var`), `value` (the one right-hand expression as written) and, for a typed `var`, `type_text`. A Go function returning a composite literal lists it as an `EXPRESSION` return source. The cards engine reads a producer `pattern-inside` within its block, and follows an object through a local copy, a struct field and a same-file factory. A `1.34` Go fragment still loads; the engine then reads the block from the source lines' indentation and follows none of the three. |
| `1.38` | Node fragments (`graph-algo-node-9`): each function carries `start_col` and `end_col` (1-based, end exclusive) beside `start_line`/`end_line`, so annotating a stored fragment places a crypto call written on the line where a callback argument starts in the function that writes it, as a scan does. Other ecosystems write no function columns. A `1.37` fragment (C and C++ facts) is read unchanged. |
| `1.39` | Java fragments (`graph-algo-40`): a function carries `constructs`, the one class every return of it builds as a plain `new T(...)`, as `package.(Type)` (`"org.acme.liba.(Standard)"`). It is written only when every return that yields an object builds that class: a return of `null` is passed over, and any other returned value (a call result, a field, an anonymous class, another class, an expression the parser cannot read) leaves it out. An external call of an application reachability request may carry `receiver_producer`, the key of the dependency function whose result the call's receiver holds (a local bound once, by that one call); a stored fragment never carries it. The stitch types such a receiver with the class its producer constructs and dispatches the call to that class's method only. A `1.38` Java fragment still loads, without `constructs`; a call on its factories' results keeps every candidate. |

### Structure

| Field | Description |
|-------|-------------|
| `schema_version` | Fragment schema version (currently `graph-fragment-1.39`). |
| `scan_metadata` | Ecosystem, root module, tool/rules versions, `graph_algo_version` (callgraph-construction algorithm version; cache key for annotate-only re-annotation), and per-array counts. |
| `functions[]` | Callable nodes. `key` is the stable function identity (`pkg.(Type).name#arity`); also carries `file_path`, `package`, `type`, `name`, signature, etc., and (1.14+) `entry_kind` when the scan recognized the function as an entry point, and (1.15+) `returns_calls`, the callee keys of the calls whose result it returns, and (1.39+, Java) `constructs`, the one class every return of it builds with `new`. |
| `internal_edges[]` | Caller→callee edges **within** the component (both functions are in this fragment). Each edge may carry `entry_call` (1.2+, see below). A Node call on a merged module object (`H = Object.assign({}, require(a), require(b)); H.f()`, or a chain it heads) carries `candidate_modules` (1.29+): the modules the object combines, sorted; its `target_key` stays caller-local. |
| `internal_edges_compact[]` / `internal_edge_strings[]` | Compact (1.7+) encoding of internal edges: same fields as `internal_edges`, with repeated strings and function keys indexed into `internal_edge_strings` to keep large dependency fragments small. |
| `external_calls[]` | Calls whose target may live in **another** component; resolved at stitch time against the dependency tree. Each edge may carry `entry_call` (1.2+, see below). A Node call on a merged module object (`H = Object.assign({}, require(a), require(b)); H.f()`, or a chain it heads) carries `candidate_modules` (1.29+): the modules the object combines, sorted; its `target_key` stays caller-local. |
| `crypto_annotations[]` | Terminal crypto findings attached to a function. Beyond `function_key`/`finding_id`/optional `occurrence_key`/`rule_id`/`symbol`, a 1.2+ annotation carries the data-flow and metadata needed to reconstruct a findings entry (see *Crypto annotation fields (1.2+)* below). A component with no crypto still emits a fragment (zero `crypto_annotations`) so it can serve as a bridge in transitive chains. |
| `supporting_calls[]` | Non-finding config/lifecycle/context calls useful for explaining crypto behavior without increasing finding counts. |
| `crypto_entry_points[]` | Canonical reachability index: API functions plus display aliases and links to reachable findings/supporting calls. |
| `imports` | Python, optional (no schema bump): by `file_path`, the bindings of each scanned file's import statements in source order, `{line, module, name, alias, local}`: `import a.b` (`module`), `import a.b as z` (`alias`), `from m import n as a` (`module`, `name`, `alias`), `from m import *` (`name: "*"`). A relative module is resolved against the file's package; `local` marks an import inside a function or class body. Node (1.26+): every `import`, `require`, dynamic `import()` and `export ... from` of each scanned file, `{line, module, name, alias, kind, local}`: `module` is the specifier as written (`node:crypto`, `./util`); `name` is the export taken (`default`, `*` for a namespace or star form, a dotted path for `require('m').a.b`), empty when the module itself is bound; `alias` is the local name when it differs; `kind` is empty for an ES import, or `type` (TypeScript `import type`), `require`, `dynamic` or `export`. |
| `object_literals` | Node (1.28+): by `file_path`, every outermost non-empty object expression of each scanned file, wherever it stands (a call argument, an initializer, a return value, an array element), in source order, `{line, start_col, end_line, end_col, text, caller_key, assigned_var, assign_start_col, assign_line}`: columns are 1-based with the end exclusive, `end_line` is set only when the object spans lines, `text` is its exact source and `caller_key` the key of the function that holds it (`<package>.<module>` at module level). Objects nested in one are part of its `text` and are not listed again. An object assigned to a variable (1.29+) also carries `assigned_var`, `assign_start_col` and `assign_line` (set only when the declarator starts on another line); destructuring patterns and TypeScript object types are not objects. |
| `property_reads` | Node (1.29+): by `file_path`, every outermost member read of each scanned file (`ns.enums.hash.md5`, `c.fingerprint`), not a callee, assignment target or type, `{caller_key, target_key, method_name, raw, line, start_col, end_line, end_col, receiver_var, assigned_var, candidate_modules}`, keyed exactly as a call of that property would be. Reads are not calls: they change no function, call or edge. |
| `exports` | Python, optional (no schema bump): each public dotted name of the component that names a declaration made elsewhere in it, mapped to that declaration: a function key, or a class as `pkg.(Type)` (`"jwt.encode": "jwt.api_jwt.(PyJWT).encode"`, `"jwt.PyJWT": "jwt.api_jwt.(PyJWT)"`). Re-exports, star imports, `__all__` and module-level aliases of a function, a method or a bound method of a module-level instance give such names; a name without an underscore, or one `__all__` lists, is public. The stitch joins a client's call of a public name through it. Node (`graph-algo-node-7` and later, no schema bump): each key a caller spells through one of the package's specifiers, mapped to the function the package declares under another key (`"acme-sign.sign": "acme-sign/index.sign"`, `"@acme/sign.sign"`, `"acme/sub.f"`, `"acme.default"`, members of an exported object such as `"notp.hotp.gen": "notp/index.(hotp).gen"`), from package.json `exports`, `main` or the index file, directory indexes and re-exporting files; an application's `require("acme-sign").sign()` call stitches into the package through it. Rust (`graph-algo-rs-14` and later, no schema bump): each public path a crate gives a function, type or module, in function-key form, mapped to its declaration. `pub use` items (renames, globs and re-exported modules included) and `pub type` aliases give such paths (`"jsonwebtoken.decode": "jsonwebtoken::decoding.decode"`, `"jsonwebtoken.DecodingKey": "jsonwebtoken::decoding.(DecodingKey)"`, `"ml_kem.MlKem768": "ml_kem::kem.(Kem)"`), and every module is public at its own path (`"ring.hmac": "ring::hmac"`), which joins a call through an imported module (`use ring::hmac; hmac::sign(..)` is keyed `ring.(hmac).sign`). A re-export of another crate's item names it as that crate keys it (`"rand::rngs.OsRng": "rand_core.(OsRng)"`), and the stitch follows it into that crate. An application's `jsonwebtoken::decode(..)` call stitches into the crate through it. From `graph-algo-rs-15`, a call a crate makes to its own item through such a path also reaches the declaration inside the fragment (`crate::ssh::Identity::from_buffer(..)` under `pub use identity::Identity;` is an internal edge to `age::ssh::identity.(Identity).from_buffer`), and keeps the call as written. |
| `constant_refs` (Python) | The 1.17 positional references, also written for Python without a schema bump (`graph_algo_version` `graph-algo-py-23` and later): an attribute chain rooted in an import (`ssl.PROTOCOL_TLSv1_1`, `hashes.SHA256`, `hashlib.sha256` passed as a value), a from-imported name used as a value (written `module.name`: `from ssl import CERT_NONE as N` then `N` is `ssl.CERT_NONE`) and a dotted `case` pattern, outside a call target, a written target, a decorator and a type annotation. The context is one of Java's (`compare` for `==`, `!=`, `is`, `is not`; `case`; `return`; `assign`; `init` for a module or class body assignment or an annotated one; `array` for a list, tuple or set element; `arg`; `other`) or `in` (an operand of `in` / `not in`, or an element of the container one tests) or `dict` (a dict display key or value) or `type_check` (the class argument of `isinstance` / `issubclass`, or an element of its tuple of classes, `graph-algo-py-36` and later). `compare`, `in` and `case` carry the operand compared with, `dict` on a value its key. A compared field of the object (`self.mode == ssl.CERT_REQUIRED`, `graph-algo-py-31` and later) is a `FIELD` source holding as `VALUE` nodes the fixed values its class assigns to it (`mode = X` in the class body, `self.mode = X` / `cls.mode = X` in a method), as a Java compared field does since `graph-algo-31`. A module or class body with references and no call gets its `<module>` / `<clinit>` function. |
| `attribute_stores` | Python, optional (no schema bump; `graph-algo-py-24` and later): each assignment to an attribute of an object, positional `[function, line, start_col, end_col, receiver, attribute, operator, end_line, value]`: the span is the whole assignment (columns 1-based, end exclusive), `receiver` the object written (`ctx`, `self._ctx`) and `attribute` the name assigned, without whitespace, `operator` `=` or the augmented operator (`\|=`), `end_line` 0 on one line, and `value` the value assigned (the last right side of a chained assignment) as a call argument's parameter object: its text, resolved value and provenance (`True` / `False` / `None` are a `VALUE`). A `self.f = g(..)` / `cls.f = g(..)` store is left out (`graph-algo-py-27` and later): the call's `assigned_var` (`self.f`) names the field. A rule naming a store (`$CTX.mode = lib.EXAMPLE_FLAG`) reads it without the source. A module or class body with a store and no call gets its `<module>` / `<clinit>` function. |
| `local_bindings` | Python, optional (no schema bump; `graph-algo-py-35` and later): for each local a function (or module or class body) binds more than once with a call among the values (a parameter counts as one, the value its callers pass), the statements that bind it, positional `[function, name, line, col, effect_line, effect_col, block_end_line, block_end_col, loop_line, loop_col]` (columns 1-based). `line`/`col` start the statement (assignment, with item, for or except clause, `del`, import, nested `def`/`class`); a call written from there up to the effect point is the value it binds. `effect_line`/`effect_col` are where the name holds the new value (the end of the statement; the start of a for loop's or except clause's body). `block_end_*` end (exclusive) the innermost block that runs the binding whenever it runs, so a later use inside it reads the new value; `loop_*` start the outermost loop around the binding, whose next iteration a use written before it may read (0 for none). Names a `global` or `nonlocal` statement names get none; an augmented assignment, an assignment expression and a match capture count toward "more than once" but are not listed. Every name of a tuple or list pattern assigned a call (`pub, priv = rsa.newkeys(..)`, also a name bound once) is listed with three more fields, `[..., element, value_line, value_col]`: its position in the pattern (from 0), the element of the call's value it holds, and where that call starts (its site's `line` and `start_col`); a name after a starred target or in a nested pattern is not. The cards matcher reads them to follow only the assignment of a local that reaches its use (reaching definitions; a site with no binding of its own reaches every use), and a card's `from: {call: .., element: i}` to tie a name to the call it unpacks. |
| `declarations`, `casts`, `abstract` (Python) | The 1.18 and 1.24 data, also written for Python without a schema bump (`graph-algo-py-25` and later). A declaration is an annotated assignment (`k: rsa.RSAPrivateKey = ...`, `self.pub: T = ...`, a class body's `key: T`), its span the assignment, `name` the target as written, `init` `call`, `cast` (a `typing.cast`), `null` (`None`), `literal`, `other` or none; builtin scalars, `str`, `bytes`, `object` and `Any` are not recorded. A cast is `typing.cast(T, f(..))` (also `cast` imported from typing) around a call, its span the cast call, `type` the first argument as written. `abstract` marks a method decorated `@abstractmethod` (or abc's `abstractproperty`, `abstractclassmethod`, `abstractstaticmethod`), a stub (docstring, `...`, `pass`) of a `Protocol` class and a method whose body only raises `NotImplementedError`; `scan_metadata.abstract_methods` is set, so the stitch reads every other Python method as a body a call may run (graph-fragment-1.24). |
| `constant_refs`, `declarations`, `call_anchors`, `rebind_lines` (Go) | Also written for Go without a schema bump: `constant_refs` from `graph-algo-go-5` (a value read through an import, text `<import path>.<name>`), `declarations` from `graph-algo-go-6` (a `var` of an imported type, written with its import path), and the call data from `graph-algo-go-7`. From `graph-algo-go-3` a Go call nothing typed is a `name_only` external call; from `graph-algo-go-9` so is a call on an interface value of a package outside the scan, with that interface in `declared_type`, and from `graph-algo-go-11` a call on a type of a module missing from the module cache. |
| `call_anchors`, `rebind_lines` (Node) | Also written for Node without a schema bump: the 1.21 call data (`call_anchors` callee, text, arguments and argument provenance, `functions[].parameter_names` and `return_sources`, `external_signatures`) and `rebind_lines`. `annotate` rebuilds the calls from them, so a call with no edge (a chain link such as `.digest()` that resolves to a function of the module itself) keeps its place, and a chain's terminal call is the one the scan picked. A Node fragment without them is rebuilt from its edges, as before. |
| `call_anchors`, `rebind_lines` (C) | Also written for C without a schema bump (`graph-algo-c-3`): the 1.21 call data (`call_anchors` callee, text, arguments and argument provenance, `functions[].return_sources`, `external_signatures`) and `rebind_lines`. `annotate` rebuilds the calls from them, with the linkage the C parser gave each callee (a call written as a bare name is externally linked unless its key names the caller's own file, a `static` function), so a supporting call keeps its `matched_operation.expression`, and the `category` and `parameter_roles` the C KB gives a call of an externally linked function. A C fragment without them is rebuilt from its edges, as before. |
| `call_anchors`, `rebind_lines` (C++) | Also written for C++ without a schema bump (`graph-algo-cpp-4`): the 1.21 call data (`call_anchors` callee, text, arguments and argument provenance, `functions[].parameter_names` and `return_sources`, `external_signatures`) and `rebind_lines`. `annotate` rebuilds the calls from them and links a call of a type or method the project declares internally, as the scan's graph does (a type counts as declared when a function of the fragment is one of its members), so a supporting call the graph resolved to a project function keeps its `matched_operation.expression`, and a call of a project type the C++ KB also describes takes no KB `category`. A C++ fragment without them is rebuilt from its edges, as before. |
| `source_lines` (C and C++ files) | Beside the lines of the call sites, string literals and directives, the preprocessor conditionals (`#if`, `#ifdef`, `#ifndef`, `#elif`, `#else`, `#endif`) written inside each statically false `#if` block (`#if 0`, `#if (0)`, `#if 0x0`, `#if !1`, `#if 0 && ...`, up to its `#endif`, `#else` or `#elif`), no schema bump (`graph-algo-c-3`). A scan drops the findings inside such a block, reading the file; `annotate` finds the blocks from these lines and drops the same findings. A fragment without them keeps them on annotate. |
| `supertypes` | Each declared type, fully qualified, to the supertypes its `extends`/`implements` clauses name (an unresolved base keeps its candidates joined by a vertical bar). Rust (`graph-algo-rs-15` and later, no schema bump): the crate's trait hierarchy in function-key owner form. `impl Trait for Type` makes the trait a supertype of the type (`"chacha20poly1305.ChaChaPoly1305": ["aead.AeadInPlace", ..]`), `trait A: B` makes B one of A, and a blanket `impl<G: Bound> Trait for G`, whose methods are keyed under the parameter (`aead.(Alg).encrypt`), makes the parameter's owner a supertype of the bound (`"aead.AeadInPlace": ["aead.AeadCore", "aead.Alg"]`). A trait's required method is a function marked `abstract`, and `scan_metadata.abstract_methods` is set. The stitch reads a Rust type's method as an implementation of the same method of its supertypes, so a call through a trait's default method dispatches to the implementations: one is followed, several serve `unknown` (`ambiguous_dispatch`). |
| `service_providers` | (1.25+, Java) Each service type to the classes the component registers for it in `META-INF/services` (see the history above). |

### Per-call data flow: `entry_call` (1.2+)

Every `internal_edges[]` and `external_calls[]` entry may carry an `entry_call`
describing the call-site argument data-flow for that edge — the same model the
finding-centric call graph export uses (see *Call Graph Export* above):
`entry_call.parameters[]` each have `parameter_index`, best-effort `type`,
`argument_expression`, `resolved_value`, `variable_name` (simple identifiers
only), and recursive `source_nodes` provenance. A Python keyword argument
(`algorithm="HS256"`) also has `keyword`; its `parameter_index` is then its
place in the call, not a position of the callee's parameters, and
`argument_expression` is the value alone. A Python `PARAMETER` source node's `parameter_index` is
the position a caller writes the argument at: a method's parameters count from the one after
`self` / `cls` (`graph-algo-py-29` and later; earlier graphs trace no method parameter), and a
keyword-only parameter has `-1`, since a caller passes it by its `name` alone. A Python local or module name written more than once
(`graph-algo-py-24` and later) is a `VARIABLE` source node with
`may_values`, the string literals its writes assign, and
`may_values_exhaustive` when every write is one, as Java's since 1.16. A Python local or module
name bound once to a dotted name rooted in an import or a class of the module (`variant = Type.ID`,
`graph-algo-py-32` and later) is a `VARIABLE` whose source is the `VALUE` `Type.ID`, as written
(`resolved_value` `Type.ID`), as one bound to a literal already was. Inside a Python branch
that fixes a variable (`graph-algo-py-28` and later: the body of `if v == X:`, also as an `and`
conjunct, of `if v in (X, Y):` and of `case X:` / `case X | Y:` of `match v:`, where X is a plain
string or integer literal or a dotted name rooted in an import) the variable is a `VARIABLE` whose
source is the `VALUE` X, or whose exhaustive `may_values` are the strings X and Y, as Java's
branches since 1.19. A Python subscript of a dispatch table (`graph-algo-py-30` and later: a dict
display with literal keys, written in place or bound once to a function or module name whose items
the file never writes and, `graph-algo-py-34` and later, never hands to other code: passes as an
argument, aliases, returns or puts in a display) whose key resolves (`TABLE["HS512"]`, `TABLE[alg]` with `alg` traced to
literals) is a `VARIABLE` named as the subscript is written, whose source is the value of the entry
the key selects (`resolved_value` `hashlib.sha512`), or of each entry its keys select. With a key
that does not resolve, a table the function itself writes or binds (`graph-algo-py-33` and later:
`names = {"a": "sha256", "b": "sha512"}` then `names[alg]`, or the display in place) is a
`VARIABLE` whose `may_values` are the fixed values of its entries, not exhaustive; a module's table
has no source then. A local bound once to a table read (`name = names[alg]`) traces to the read. A
Python name bound once to a list or tuple display of plain string and integer literals
(`graph-algo-py-35` and later: `algs = ["HS256"]`, `ALGS = ("HS256", "HS384")`) is a `VARIABLE`
whose source is the `VALUE` display, written `[e1, e2]` / `(e1, e2)` / `(e1,)` with its elements as
written (`resolved_value` the same); a list only when it is a function local used as a bare call
argument and nothing else (one the function changes, or a module list, has no source). Carrying it **on the edge** is
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
supporting-call, and entrypoint metadata, `reach/graphfrag` (the callgraph) and
`pkg/appreach` (the findings envelope) can render a stitched `Result` into
the same two artifacts a live `--scan-dependencies` run produces:

- **`Result.ToCallgraphExport(root, meta)`** — renders the stitched result into
  a callgraph (zero-value meta stamps inlined `6.14`; `ScanMeta.InternedFrames` selects `6.18`). Align the render and sample budget explicitly when comparing with local CLI exports. Dep-component findings get
  `module@version/`-prefixed `finding_id`s, matching live output.
- **`appreach.ToFindingsEnvelope(root, deps, fragments, meta)`** — reconstructs the
  findings.json v1.7 envelope (asset metadata, including direct `purl`). Its `finding_id`s are computed
  with the **same inputs** as `ToCallgraphExport`, so the two agree: consumers
  join assets (envelope) to call chains (callgraph) by `(finding_id, occurrence_key)` when the key is present,
  or by `finding_id` for legacy records without `occurrence_key`.

`reach/graphfrag/equiv` is a semantic diff tool that asserts a stitched callgraph
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
span the component boundary. The reference consumer (`reach/graphfrag`'s stitcher)
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

#### Python stitching

A Python component (a fragment stamped `graph-algo-py-*`, or a `pkg:pypi`
purl) is stitched with what Python imports, not with what a build declares
(`StitchOptions.EnvironmentTargets`, which application reachability sets to
`python`):

- **Environment targets.** A typed call its `requires` leave without a target
  resolves against every other component of the pinned closure: a module
  imports whatever is installed, and an optional import, a dependency an extra
  pulls in, or a lock without edges (`Pipfile.lock`) is attributed to no
  requirement. Declared dependencies are tried first. Java components keep
  their classpath targets.
- **Module id.** A PyPI component's module is its PEP 503 distribution name
  (`pkg:pypi/PyJWT` serves its findings under `pyjwt@2.10.1/jwt/...`), the name
  the Python dependency resolver gives it; the import name (`jwt`) never is.
  Calls join by function key, whose path is the import path, so the two need
  not match.
- **Hierarchy across components.** With `HierarchyFromSupertypes`, a base a
  class names by a dependency's public path (`class GithubRetry(urllib3.Retry)`)
  is the class that path exports (`urllib3.util.retry.Retry`), so a method the
  class only inherits, and its `__init__`, resolve into the dependency. A
  call of a class that declares no `__init__` of its own runs the one it
  inherits, also for the caller's own classes, whose instantiation the
  producer could not link when that `__init__` is a dependency's.
- **Unresolved calls into a dependency read unknown.** A typed call whose
  target names a module (or package) of another Python component of the
  closure but no declaration the lookups above find (a method of a
  module-level instance, a class attribute's value, a class one dependency
  re-exports from another) runs code of that dependency the fragments do not
  name. It is read as a `name_only` call: its candidates are that component's
  functions of the called name and the `__init__` of its classes of that
  name (else of a class of that name elsewhere in the closure), so a finding
  it may reach is `unknown` (`unresolved_dispatch`), never `unreachable`. A
  target in a module of the caller's own (an instantiation the producer also
  links internally) or of no component (the standard library) is no call
  into a dependency.
- **`name_only` candidates.** A Python `name_only` call (a receiver whose type
  nothing named) has as candidates the functions of its name in its own
  component (the producer links an untyped call to nothing, not even to the
  component's own methods: pyjwt's `self._jws.encode(..)` runs `PyJWS.encode`)
  and in the environment (a value of unknown type may come from any installed
  package; the declared dependencies only, without environment targets). A
  method name of a builtin value type (`get`, `items`, `update`, `encode`,
  `decode`, `copy`, ...: the methods of `str`, `bytes`, `dict`, `list`, `set`,
  `tuple`, `int`, `float`) has candidates in other components only when the
  receiver is a dependency value: a local the caller assigns from a call into a
  dependency's module, a field of the caller's class assigned so, or the
  result of such a call earlier in the same chain. Such names were 85%
  (PyGithub) and 80% (matrix-synapse) of the client calls with a candidate, and
  each one read was a dict, str or bytes value. The edges stay `name_only`:
  never traversed, they only make a finding `unknown`.
- **Import-time edges** (`graph-algo-py-37` and later). Importing a module
  runs its top level and that of the packages on its path; a class body runs
  with its `class` statement. The producer writes these as exact calls: a
  module's `<module>` (written for a module that only imports or defines
  classes too) calls the `<module>` of each module it imports
  (`import a.b` names `a.<module>` and `a.b.<module>`; `from a import b` also
  `a.b.<module>`, for `b` may be a submodule), a function each module it
  imports in its body, and `<module>` the `<clinit>` of each class it defines
  (unless an entry rule made the class body a root, a Django migration's).
  An import under `if TYPE_CHECKING:`, one in a stub (`.pyi`) and one of the
  standard library get none, nor does one the component itself answers without
  top-level code. Into a dependency, such a call that names no declaration (a
  module without top-level code, a from-imported name that is no module) runs
  nothing: it has no `name_only` reading. Module-level code of a module the
  client imports, directly or through its dependencies, is thus reachable.
- **Class values** (`graph-algo-py-38` and later). A class handed around as a
  value (`{"RSA": RSAKey}`, `register(Handler)`, `return modes.CBC`,
  `raise Error`, `cls = Algorithm`; not one only tested with `isinstance`,
  caught, annotated, a base or in a decorator) may be instantiated, or have
  its class methods called, by whatever holds it. The producer writes a
  `name_only` call from the function reading it to `pkg.(K).<class>`, the
  class object (no function bears that name, so the cards matcher and the
  tracers never read it as a call of `K`). The stitch reads it as the
  `__init__` a call of `K` runs (`K`'s own or inherited, else a class of that
  name in the component the target names): a finding in it is `unknown`, not
  `unreachable`, and no other class's `__init__` is a candidate.
- **Live classes.** With environment targets, a Python `name_only` candidate
  that is a method of class `K` stays only when code the client reaches
  instantiates `K` or a subclass (`K(..)`), calls through `K` (a typed call
  naming it), or hands `K` around as a value (a `<class>` edge), computed to a
  fixpoint over the traversed, ambiguous and kept `name_only` edges. Calling
  a method needs an object of the class or the class itself, so a candidate
  of a class nothing reached can hold is dropped and a finding only it would
  reach is `unreachable`. Classes match by simple name (a namesake keeps
  them), and every class of a component none of whose modules the client
  imports, even over `name_only` edges, stays (a plugin loaded by name from
  configuration). Objects made natively, unpickled or built with `type(..)`
  are outside this model.

### Example

```json
{
  "schema_version": "graph-fragment-1.15",
  "scan_metadata": { "ecosystem": "java", "root_module": "org.bouncycastle:bcpkix-jdk18on", "graph_algo_version": "graph-algo-25", "function_count": 4000, "internal_edge_count": 6417, "external_call_count": 9469, "crypto_operation_count": 160, "supporting_call_count": 12, "crypto_entry_point_count": 42 },
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

CycloneDX 1.7 compatible Cryptography Bill of Materials format for standardized reporting.

### Features

- **Schema Validation**: Validates against CycloneDX 1.7 specification
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
  "specVersion": "1.7",
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
| **Schema** | SCANOSS interim spec | CycloneDX 1.7 |
| **Validation** | SCANOSS tools | CycloneDX validators |

## Related Documentation

- [Main README](../README.md) - Usage and command reference
- [Dependency Scanning](DEPENDENCY_SCANNING.md) - How dependency scanning, call graph tracing, and attribution work
- [Docker Usage](DOCKER_USAGE.md) - Container-based scanning and format conversion
