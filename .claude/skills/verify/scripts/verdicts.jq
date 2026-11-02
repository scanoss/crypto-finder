# Join a findings report ($f) and a call graph export ($g) into one row per
# finding graph: where the finding is (module, file base name, line), what the
# findings report says (source), and what the call graph says (reachability,
# dependency relationship and path, each sampled call chain as the module of
# every frame). Application code is module "app".
#
# Usage: jq -n --slurpfile f findings.json --slurpfile g callgraph.json -f verdicts.jq
($f[0].findings
  | map(. as $x | $x.cryptographic_assets[]
      | {key: .finding_id, value: {file: ($x.file_path | split("/") | last), line: .start_line, source}})
  | from_entries) as $loc
| $g[0].functions as $fn
| [ $g[0].finding_graphs[]
    | $loc[.finding_id] as $l
    | { finding_id,
        module: (.dependency.module // "app"),
        file: $l.file,
        line: $l.line,
        source: $l.source,
        reachability,
        relationship: (.dependency.relationship // null),
        path: [(.dependency.path // [])[].module],
        chains: [(.call_chain_indexes // [])[] | map($fn[.].dependency_info.module // "app")] } ]
| sort_by(.module, .file, .line)
