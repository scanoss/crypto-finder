# shellcheck shell=bash disable=SC2016 # sourced by run.sh; jq filters stay single-quoted
# Driver for features/callgraph-export.md. Sourced by run.sh.
#
# Fixtures: testdata/projects/transitive_reachability/go with
# --scan-dependencies, so chains cross app -> liba -> libb; and
# testdata/projects/key_params_across_methods/java, whose key sizes and curves
# are fixed in a different method from the KeyPairGenerator the rule matches.

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

	expect "graph fragment schema_version" "$(jq -r .schema_version "$frag" 2>/dev/null)" graph-fragment-1.15
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

	# 3. Key size and curve resolved across methods (Java, no dependencies).
	# Each finding's size is read the way consumers read it: finding_graphs[]
	# .supporting_call_ids joined to supporting_calls[].supporting_call
	# .resolved_key_length. "none" means no supporting call carries bits.
	cp -R "$FIXTURES/key_params_across_methods/java" "$BOX/work/keyparams"
	local keys="$EVID/callgraph-key-params.json" keysfrag="$EVID/graph-fragment-key-params.json"
	local want_bits="14:3072,21:4096,28:2048,33:none,40:3072,47:384"
	cf export-key-params --error-format json scan --scanner opengrep --no-remote-rules --findings-cache none --languages java \
		--rules "$RULES_DIR/key-params-across-methods.yaml" --output "$EVID/findings-key-params.json" --export-callgraph "$keys" \
		--export-graph-fragment "$keysfrag" "$BOX/work/keyparams"
	expect "key-params scan exit code" "$CF_EXIT" 0
	expect "resolved key bits per KeyPairGenerator finding (line:bits)" \
		"$(jq -r -n --slurpfile f "$EVID/findings-key-params.json" --slurpfile g "$keys" '
			($g[0].supporting_calls // [] | map({key: .supporting_id, value: .supporting_call.resolved_key_length.bits}) | from_entries) as $bits
			| [$f[0].findings[].cryptographic_assets[] | .finding_id as $id
			   | ([$g[0].finding_graphs[] | select(.finding_id == $id) | .supporting_call_ids[]? | $bits[.] // empty] | unique) as $b
			   | "\(.start_line):\(if ($b | length) == 1 then $b[0] else "none" end)"]
			| sort_by(split(":")[0] | tonumber) | join(",")' 2>/dev/null)" \
		"$want_bits"

	# 4. annotate re-derives the same sizes from the cached fragment, the
	# returned generator (line 28) included.
	cf annotate-key-params --error-format json annotate --scanner opengrep --no-remote-rules --languages java \
		--rules "$RULES_DIR/key-params-across-methods.yaml" --import-fragment "$keysfrag" --source "$BOX/work/keyparams" \
		--output "$EVID/annotate-key-params.json"
	expect "key-params annotate exit code" "$CF_EXIT" 0
	expect "annotate resolved key bits per KeyPairGenerator finding (line:bits)" \
		"$(jq -r '
			(.supporting_calls // [] | map({key: .supporting_id, value: .supporting_call.resolved_key_length.bits}) | from_entries) as $bits
			| [.crypto_annotations[] | ([.supporting_call_ids[]? | $bits[.] // empty] | unique) as $b
			   | "\(.start_line):\(if ($b | length) == 1 then $b[0] else "none" end)"]
			| sort_by(split(":")[0] | tonumber) | join(",")' "$EVID/annotate-key-params.json" 2>/dev/null)" \
		"$want_bits"
}
