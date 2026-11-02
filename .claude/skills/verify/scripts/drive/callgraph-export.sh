# shellcheck shell=bash disable=SC2016 # sourced by run.sh; jq filters stay single-quoted
# Driver for features/callgraph-export.md. Sourced by run.sh.
#
# Fixture: testdata/projects/transitive_reachability/go with
# --scan-dependencies, so chains cross app -> liba -> libb.

drive() {
	copy_fixture "$FIXTURES/transitive_reachability/go"
	local base=(--error-format json scan --scanner opengrep --no-remote-rules --findings-cache none --languages go
		--rules "$RULES_DIR/transitive-reachability.yaml" --scan-dependencies)
	local app="$BOX/work/fixture/app" cg="$EVID/callgraph.json" frag="$EVID/graph-fragment.json"

	# 1. Default export (interned frames) plus the graph fragment, one scan.
	cf export "${base[@]}" --output "$EVID/findings.json" --export-callgraph "$cg" --export-graph-fragment "$frag" "$app"
	expect "scan with both exports exit code" "$CF_EXIT" 0
	expect "callgraph schema_version (default, interned frames)" "$(jq -r .schema_version "$cg" 2>/dev/null)" 6.18
	expect_jq "scan_metadata names the tool, ecosystem and root module" "$cg" \
		'.scan_metadata | .tool_name == "crypto-finder" and .ecosystem == "go" and .root_module == "example.com/transapp"'
	# function_count counts the whole crypto-scoped graph; functions[] holds
	# only the frames chains reference, so the two differ by design.
	expect_jq "scan_metadata counts functions and edges" "$cg" '.scan_metadata.function_count > 0 and .scan_metadata.edge_count > 0 and (.functions | length) > 0'
	expect_jq "6.18 frames carry no inline identity (hydrated from functions[])" "$cg" \
		'[.finding_graphs[].call_chains[]?[]] | length > 0 and all(has("function_name") | not)'
	expect "finding_graphs cover every finding_id in the report" \
		"$(jq -r -n --slurpfile f "$EVID/findings.json" --slurpfile g "$cg" \
			'([$f[0].findings[].cryptographic_assets[].finding_id] | sort) == ([$g[0].finding_graphs[].finding_id] | sort)')" true
	expect_jq "every reachable graph has a chain, all indexes inside functions[]" "$cg" \
		'(.functions | length) as $n | [.finding_graphs[] | select(.reachability == "reachable")]
		 | length > 0 and all(.call_chain_indexes | length > 0 and all(.[]; all(.[]; . >= 0 and . < $n)))'
	expect_jq "the libb chain starts at app main and ends in libb" "$cg" \
		'.functions as $fn | [.finding_graphs[] | select(.dependency.module == "example.com/translibb" and .reachability == "reachable")
		 | .call_chain_indexes[] | [$fn[.[0]].function_name, $fn[.[-1]].dependency_info.module]]
		 | any(. == ["example.com/transapp.main", "example.com/translibb"])'
	expect_jq "no crypto_entry_points index unless asked" "$cg" 'has("crypto_entry_points") | not'

	expect "graph fragment schema_version" "$(jq -r .schema_version "$frag" 2>/dev/null)" graph-fragment-1.14
	expect_jq "graph fragment has functions, edges and crypto annotations" "$frag" \
		'(.functions | length) > 0 and (.internal_edges_compact != null or .internal_edge_strings != null) and (.crypto_annotations | length) > 0'

	# 2. Legacy inlined frames (schema 6.14), entry-point index, one chain per finding.
	cf export-legacy "${base[@]}" --output "$EVID/findings-legacy.json" --export-callgraph "$EVID/callgraph-6.14.json" \
		--export-callgraph-interned-frames=false --export-callgraph-entry-points --export-callgraph-max-chains 1 "$app"
	expect "scan with legacy export exit code" "$CF_EXIT" 0
	expect "callgraph schema_version (interned frames off)" "$(jq -r .schema_version "$EVID/callgraph-6.14.json" 2>/dev/null)" 6.14
	expect_jq "6.14 reachable graphs inline each frame's identity" "$EVID/callgraph-6.14.json" \
		'[.finding_graphs[] | select(.reachability == "reachable")] | length > 0 and all(.call_chains | length > 0 and all(.[]; all(.[]; .function_name != null)))'
	expect_jq "--export-callgraph-max-chains 1 caps every finding at one chain" "$EVID/callgraph-6.14.json" \
		'all(.finding_graphs[]; ((.call_chains // []) | length) <= 1)'
	expect_jq "--export-callgraph-entry-points adds crypto_entry_points" "$EVID/callgraph-6.14.json" 'has("crypto_entry_points")'
}
