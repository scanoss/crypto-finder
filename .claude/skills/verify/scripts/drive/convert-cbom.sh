# shellcheck shell=bash disable=SC2016 # sourced by run.sh; jq filters stay single-quoted
# Driver for features/convert-cbom.md. Sourced by run.sh.
#
# Fixture: testdata/projects/transitive_reachability/go app/ (SHA-256 at
# main.go:18, MD5 at main.go:22). convert validates every CBOM against the
# embedded CycloneDX 1.7 schema before writing it, so exit 0 means the schema
# accepted it.

# cbom_checks LABEL FILE: shape checks shared by every CBOM this drive makes.
cbom_checks() {
	expect_jq "$1: bomFormat CycloneDX, specVersion 1.7" "$2" '.bomFormat == "CycloneDX" and .specVersion == "1.7"'
	expect "$1: algorithm components" \
		"$(jq -r '[.components[]? | select(.type == "cryptographic-asset" and .cryptoProperties.assetType == "algorithm") | .name] | sort | join(",")' "$2" 2>/dev/null)" \
		"MD5,SHA-256"
	expect_jq "$1: every crypto component records where it was found" "$2" \
		'[.components[]? | select(.type == "cryptographic-asset")] | length > 0 and all(.evidence.occurrences | length > 0)'
}

drive() {
	copy_fixture "$FIXTURES/transitive_reachability/go"
	local app="$BOX/work/fixture/app"
	local base=(--error-format json scan --scanner opengrep --no-remote-rules --findings-cache none --languages go --rules "$RULES_DIR/transitive-reachability.yaml")

	cf scan "${base[@]}" --output "$EVID/findings.json" "$app"
	expect "scan exit code" "$CF_EXIT" 0

	# 1. convert FILE --output.
	cf convert-file --error-format json convert "$EVID/findings.json" --output "$EVID/cbom.json"
	expect "convert --output exit code" "$CF_EXIT" 0
	cbom_checks "convert --output" "$EVID/cbom.json"

	# 2. convert from stdin to stdout.
	CF_STDIN="$EVID/findings.json" cf convert-stdin --error-format json convert
	expect "convert stdin->stdout exit code" "$CF_EXIT" 0
	cbom_checks "convert stdin" "$EVID/convert-stdin.stdout"

	# 3. scan --format cyclonedx goes straight to a CBOM.
	cf scan-cyclonedx "${base[@]}" --format cyclonedx --output "$EVID/scan-cbom.json" "$app"
	expect "scan --format cyclonedx exit code" "$CF_EXIT" 0
	cbom_checks "scan --format cyclonedx" "$EVID/scan-cbom.json"

	# 4. Input that is not an interim report is refused with a typed error.
	echo '{"not":"a report"' >"$BOX/work/broken.json"
	cf convert-broken --error-format json convert "$BOX/work/broken.json" --output "$EVID/cbom-broken.json"
	expect "convert of broken JSON exit code" "$CF_EXIT" 1
	# Malformed input is a typed failure: invalid_arguments (#811).
	local code
	code=$(error_code "$EVID/convert-broken.stderr")
	if [[ $code == "invalid_arguments" ]]; then
		pass "convert of broken JSON reports invalid_arguments"
	else
		fail "convert of broken JSON: error code '$code', want invalid_arguments"
	fi
	if [[ -e $EVID/cbom-broken.json ]]; then
		fail "convert of broken JSON still wrote $EVID/cbom-broken.json"
	else
		pass "convert of broken JSON wrote no CBOM"
	fi
}
