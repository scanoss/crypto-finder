# shellcheck shell=bash disable=SC2016 # sourced by run.sh; jq filters stay single-quoted
# Driver for features/cbom-from-sbom.md. Sourced by run.sh.
#
# `cbom` scans nothing: it asks the SCANOSS API for each SBOM component's
# mined findings. The drive never talks to the real API. It starts
# scripts/api-stub.py on 127.0.0.1 and points --api-url at it (guard_args
# refuses any other URL), with a dummy key. The stub serves synthetic
# findings for node-forge, an empty finding list for left-pad, and
# COMPONENT_NOT_FOUND for anything else.

start_stub() {
	# exec, so $! is the python process itself and killing it stops the stub.
	(
		sandbox_env "$BOX"
		exec "${SANDBOX_ENV[@]}" python3 "$VERIFY_SCRIPTS/api-stub.py" "$BOX/stub.port" "$EVID/api-requests.jsonl"
	) &
	echo $! >"$BOX/stub.pid"
	trap 'kill "$(cat "$BOX/stub.pid")" 2>/dev/null || true; rmdir "$LOCK" 2>/dev/null || true' EXIT
	for _ in $(seq 50); do
		[[ -s $BOX/stub.port ]] && break
		sleep 0.1
	done
	[[ -s $BOX/stub.port ]] || die "API stub did not start"
	STUB_URL="http://127.0.0.1:$(cat "$BOX/stub.port")"
	echo "# API stub $STUB_URL pid $(cat "$BOX/stub.pid")" >>"$TRANSCRIPT"
}

drive() {
	start_stub
	: >"$EVID/api-requests.jsonl"
	local api=(--api-url "$STUB_URL" --api-key verify-stub-key)

	# 1. CycloneDX SBOM: one crypto component, one without crypto, one not
	#    mined, one without a version (never looked up).
	cat >"$BOX/work/sbom.cdx.json" <<-'EOF'
		{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"verify-app","version":"0.1.0"}},
		 "components":[
		  {"name":"node-forge","version":"1.3.1","purl":"pkg:npm/node-forge@1.3.1"},
		  {"name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
		  {"name":"unmined","version":"9.9.9","purl":"pkg:npm/unmined@9.9.9"},
		  {"name":"no-version","purl":"pkg:npm/no-version"}]}
	EOF
	cp "$BOX/work/sbom.cdx.json" "$EVID/sbom.cdx.json"
	cf cbom --error-format json cbom "$BOX/work/sbom.cdx.json" --output "$EVID/cbom.json" "${api[@]}"
	expect "cbom exit code" "$CF_EXIT" 0
	expect_jq "CBOM is CycloneDX 1.7" "$EVID/cbom.json" '.bomFormat == "CycloneDX" and .specVersion == "1.7"'
	expect "CBOM library dependencies (refs)" "$(jq -r '[.dependencies[]?.ref] | sort | join(",")' "$EVID/cbom.json" 2>/dev/null)" "pkg:npm/node-forge@1.3.1"
	expect_jq "node-forge depends on an AES algorithm asset" "$EVID/cbom.json" \
		'(.dependencies[] | select(.ref == "pkg:npm/node-forge@1.3.1") | .dependsOn) as $deps
		 | [.components[] | select(.["bom-ref"] as $r | $deps | index($r)) | .name] | index("AES") != null'
	expect_jq "CBOM metadata names the SBOM subject" "$EVID/cbom.json" '.metadata.component.name == "verify-app"'
	expect "API lookups the stub received (purl)" \
		"$(jq -r -s '[.[].purl] | sort | join(",")' "$EVID/api-requests.jsonl")" \
		"pkg:npm/left-pad,pkg:npm/node-forge,pkg:npm/unmined"
	expect_jq "every lookup hit the component endpoint with a key" "$EVID/api-requests.jsonl" \
		'.path == "/v3/cryptography/reachability/component" and .api_key_header'
	expect "stderr summary of component statuses" \
		"$(grep -o 'crypto [0-9]*, no crypto.*' "$EVID/cbom.stderr")" \
		"crypto 1, no crypto 1, not mined 1, unsupported 1, failed 0"

	# 2. SPDX tag-value from stdin.
	printf 'SPDXVersion: SPDX-2.3\nPackageName: node-forge\nPackageVersion: 1.3.1\nExternalRef: PACKAGE-MANAGER purl pkg:npm/node-forge@1.3.1\n' >"$EVID/sbom.spdx"
	CF_STDIN="$EVID/sbom.spdx" cf cbom-stdin --error-format json cbom - "${api[@]}"
	expect "cbom - (SPDX tag-value on stdin) exit code" "$CF_EXIT" 0
	expect "cbom - CBOM dependencies" "$(jq -r '[.dependencies[]?.ref] | join(",")' "$EVID/cbom-stdin.stdout" 2>/dev/null)" "pkg:npm/node-forge@1.3.1"

	# 3. Not an SBOM: refused before any lookup.
	echo '{"name":"package.json"}' >"$BOX/work/not-sbom.json"
	local before
	before=$(wc -l <"$EVID/api-requests.jsonl")
	cf cbom-not-sbom --error-format json cbom "$BOX/work/not-sbom.json" --output "$EVID/cbom-not-sbom.json" "${api[@]}"
	expect "cbom of a non-SBOM exit code" "$CF_EXIT" 1
	expect "cbom of a non-SBOM error code" "$(error_code "$EVID/cbom-not-sbom.stderr")" invalid_arguments
	expect "cbom of a non-SBOM made no API request" "$(wc -l <"$EVID/api-requests.jsonl")" "$before"
}
