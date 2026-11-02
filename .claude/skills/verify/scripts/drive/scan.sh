# shellcheck shell=bash disable=SC2016 # sourced by run.sh; jq filters stay single-quoted
# Driver for features/scan.md. Sourced by run.sh.
#
# Fixture: testdata/projects/transitive_reachability/go. app/ has two hashing
# calls (main.go:18 SHA-256, main.go:22 MD5); liba/ has none.

drive() {
	copy_fixture "$FIXTURES/transitive_reachability/go"
	local app="$BOX/work/fixture/app" rules="$RULES_DIR/transitive-reachability.yaml"
	local base=(--error-format json scan --scanner opengrep --no-remote-rules --findings-cache none --languages go --rules "$rules")

	# 1. Findings report written with --output.
	cf scan-output "${base[@]}" --output "$EVID/findings.json" "$app"
	expect "scan --output exit code" "$CF_EXIT" 0
	expect_jq "report names the tool and its interim format version" "$EVID/findings.json" '.tool.name == "crypto-finder" and (.version | type == "string")'
	expect "findings in app/main.go (line:rule)" \
		"$(jq -r '[.findings[] | select(.file_path == "main.go") | .cryptographic_assets[] | "\(.start_line):\(.rules[0].id)"] | sort | join(",")' "$EVID/findings.json" 2>/dev/null)" \
		"18:go.transitive-reachability.sha256,22:go.transitive-reachability.md5"
	expect_jq "every asset is application code (source direct)" "$EVID/findings.json" '[.findings[].cryptographic_assets[]] | length > 0 and all(.source == "direct")'
	expect_jq "SHA-256 asset metadata comes from the rule" "$EVID/findings.json" '[.findings[].cryptographic_assets[] | select(.start_line == 18)][0].metadata | .algorithmName == "SHA-256" and .assetType == "algorithm"'

	# 2. Same report on stdout when --output is omitted.
	cf scan-stdout "${base[@]}" "$app"
	expect "scan to stdout exit code" "$CF_EXIT" 0
	expect "stdout report finding count" "$(jq '[.findings[].cryptographic_assets[]] | length' "$EVID/scan-stdout.stdout" 2>/dev/null)" 2

	# 3. --fail-on-findings with findings: exit 1, typed JSON error, report still written.
	cf fail-on-findings "${base[@]}" --fail-on-findings --output "$EVID/findings-fail.json" "$app"
	expect "--fail-on-findings with findings exit code" "$CF_EXIT" 1
	expect "--fail-on-findings error code on stderr" "$(error_code "$EVID/fail-on-findings.stderr")" findings_detected
	expect "--fail-on-findings still writes the report (finding count)" "$(jq '[.findings[].cryptographic_assets[]] | length' "$EVID/findings-fail.json" 2>/dev/null)" 2

	# 4. --fail-on-findings without findings: liba has no crypto.
	cf fail-on-findings-clean "${base[@]}" --fail-on-findings --output "$EVID/findings-clean.json" "$BOX/work/fixture/liba"
	expect "--fail-on-findings without findings exit code" "$CF_EXIT" 0
	expect "clean target finding count" "$(jq '[.findings[]?.cryptographic_assets[]] | length' "$EVID/findings-clean.json" 2>/dev/null)" 0

	# 5. A bad target is a typed failure, not an empty report.
	cf missing-target "${base[@]}" --output "$EVID/findings-missing.json" "$BOX/work/does-not-exist"
	expect "missing target exit code" "$CF_EXIT" 1
	expect "missing target error code on stderr" "$(error_code "$EVID/missing-target.stderr")" invalid_arguments
}
