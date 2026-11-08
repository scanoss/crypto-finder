# shellcheck shell=bash disable=SC2016,SC2034 # sourced by run.sh; jq filters stay single-quoted
# Driver for features/related-material.md. Sourced by run.sh.
#
# Fixture: testdata/projects/related_material/<lang>/app. One function draws a
# salt and an iv (or nonce) and hands them to helpers that pass them to a KDF
# and a cipher; another draws a value and overwrites it before handing it on.
# The synthetic rules report only the draws.
LANGS="go python rust node"
DEFAULT_LANG=python

# want LANG: "<line>:<materialType>" of every related-crypto-material asset,
# sorted, followed by the line of the overwritten draw (which gets none).
want() {
	case $1 in
	go) echo "31:salt,39:nonce 48" ;;
	python) echo "19:salt,21:initialization-vector 27" ;;
	rust) echo "17:salt,21:initialization-vector 27" ;;
	node) echo "13:salt,15:initialization-vector 20" ;;
	esac
}

drive() {
	local lang=$1 materials overwritten
	read -r materials overwritten <<<"$(want "$lang")"
	copy_fixture "$FIXTURES/related_material/$lang"
	local base=(--error-format json scan --scanner opengrep --no-remote-rules --findings-cache none
		--languages "$(scanner_language "$lang")" --rules "$RULES_DIR/related-material.yaml")

	# 1. With a call graph, a draw whose value reaches a material parameter in a
	#    helper carries that material at the draw line.
	cf with-callgraph "${base[@]}" --output "$EVID/findings.json" --export-callgraph "$EVID/callgraph.json" "$BOX/work/fixture/app"
	expect "scan with --export-callgraph exit code" "$CF_EXIT" 0
	expect "related material at the draws (line:materialType)" \
		"$(jq -r '[.findings[].cryptographic_assets[] | select(.metadata.assetType == "related-crypto-material") | "\(.start_line):\(.metadata.materialType)"] | sort_by(split(":")[0] | tonumber) | join(",")' "$EVID/findings.json" 2>/dev/null)" \
		"$materials"
	expect_jq "every material asset keeps the draw's rule and span" "$EVID/findings.json" '
		[.findings[].cryptographic_assets] | map(
			(map(select(.metadata.algorithmPrimitive == "drbg")) | map({key: "\(.start_line):\(.start_col)", value: .rules[0].id}) | from_entries) as $draws
			| .[] | select(.metadata.assetType == "related-crypto-material")
			| $draws["\(.start_line):\(.start_col)"] == .rules[0].id) | length > 0 and all'
	expect_jq "material assets carry only CycloneDX related-material metadata" "$EVID/findings.json" '
		[.findings[].cryptographic_assets[] | select(.metadata.assetType == "related-crypto-material") | .metadata | keys] | all(. == ["assetType", "materialType"])'
	expect "the overwritten draw at line $overwritten gets no material" \
		"$(jq -r --argjson l "$overwritten" '[.findings[].cryptographic_assets[] | select(.start_line == $l) | .metadata.assetType] | sort | join(",")' "$EVID/findings.json" 2>/dev/null)" \
		algorithm
	expect_jq "material assets get finding ids" "$EVID/findings.json" '
		[.findings[].cryptographic_assets[] | select(.metadata.assetType == "related-crypto-material") | .finding_id] | all(type == "string" and length > 0)'

	# 2. Without a call graph the scan reports the draws alone.
	cf without-callgraph "${base[@]}" --output "$EVID/findings-plain.json" "$BOX/work/fixture/app"
	expect "plain scan exit code" "$CF_EXIT" 0
	expect "plain scan reports no related material" \
		"$(jq '[.findings[].cryptographic_assets[] | select(.metadata.assetType == "related-crypto-material")] | length' "$EVID/findings-plain.json" 2>/dev/null)" 0

	# 3. The CBOM carries the material as relatedCryptoMaterial components.
	cf cbom "${base[@]}" --format cyclonedx --output "$EVID/cbom.json" --export-callgraph "$EVID/callgraph-cbom.json" "$BOX/work/fixture/app"
	expect "scan --format cyclonedx exit code" "$CF_EXIT" 0
	expect "CBOM related material types" \
		"$(jq -r '[.components[] | select(.cryptoProperties.assetType == "related-crypto-material") | .cryptoProperties.relatedCryptoMaterialProperties.type] | unique | join(",")' "$EVID/cbom.json" 2>/dev/null)" \
		"$(tr ',' '\n' <<<"$materials" | cut -d: -f2 | sort -u | paste -sd, -)"
}
