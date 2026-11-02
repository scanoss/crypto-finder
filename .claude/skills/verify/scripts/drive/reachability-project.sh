# shellcheck shell=bash disable=SC2016,SC2034 # sourced by run.sh; jq filters stay single-quoted
# Driver for features/reachability-project.md. Sourced by run.sh.
#
# Fixture: testdata/projects/project_reachability/<lang>, app/ the target.
# Mirrors TestProjectReachabilityMatchesDependencyScan in
# internal/cli/project_reachability_equivalence_integration_test.go: a
# --export-callgraph-project-reachability pass (no dependency resolution) must
# give every first-party finding the verdict a --scan-dependencies pass gives
# it, except the declared divergences.
LANGS="go python"
DEFAULT_LANG=go

prepare() {
	copy_fixture "$FIXTURES/project_reachability/$1"
	case $1 in
	go) ;; # app/go.mod replaces example.com/reachlib with ../lib.
	python)
		# A venv outside the target with one package that hashes on its own.
		new_venv
		mkdir -p "$BOX/pkg/reachlib"
		printf 'import hashlib\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n' >"$BOX/pkg/reachlib/__init__.py"
		install_venv_package reachlib "$BOX/pkg/reachlib"
		;;
	esac
}

# want LANG: first-party verdicts of the project-only pass. main.go:29 (a
# callback handed to reachlib.Visit) is left to the equivalence check: both
# passes read it unreachable today and no test pins that as the contract.
want() {
	case $1 in
	go) jq -n '[
		{module: "app", file: "main.go", line: 21, reachability: "reachable", chain: ["app"]},
		{module: "app", file: "main.go", line: 25, reachability: "unreachable"},
		{module: "app", file: "main.go", line: 35, reachability: "unreachable"}]' ;;
	python) jq -n '[
		{module: "app", file: "main.py", line: 7, reachability: "reachable", chain: ["app"]},
		{module: "app", file: "main.py", line: 11, reachability: "unreachable"}]' ;;
	esac
}

# divergences LANG: "file:line" of first-party findings whose verdict may
# differ between the passes. hasher.Hash (main.go:35) is reached only through
# the dependency's Hasher interface, so only the dependency scan sees it.
divergences() {
	case $1 in
	go) echo '["main.go:35"]' ;;
	*) echo '[]' ;;
	esac
}

pass_args() { # OUTDIR EXTRA...
	local out=$1
	shift
	echo --error-format json scan --scanner opengrep --no-remote-rules --findings-cache none \
		--languages "$LANG_ARG" --rules "$RULES_DIR/project-reachability.yaml" \
		--output "$out/findings.json" --export-callgraph "$out/callgraph.json" "$@" "$BOX/work/fixture/app"
}

drive() {
	local lang=$1
	LANG_ARG=$(scanner_language "$lang")
	prepare "$lang"
	local p
	for p in project deps plain; do mkdir -p "$EVID/$p"; done

	# shellcheck disable=SC2046 # pass_args prints paths without spaces.
	cf project $(pass_args "$EVID/project" --export-callgraph-project-reachability)
	expect "project-only pass exit code" "$CF_EXIT" 0
	# shellcheck disable=SC2046
	cf deps $(pass_args "$EVID/deps" --scan-dependencies)
	expect "--scan-dependencies pass exit code" "$CF_EXIT" 0
	# shellcheck disable=SC2046
	cf plain $(pass_args "$EVID/plain")
	expect "pass without either flag exit code" "$CF_EXIT" 0
	for p in project deps plain; do
		[[ -s $EVID/$p/callgraph.json ]] || {
			fail "$p pass wrote no callgraph.json (see $p.stderr)"
			return
		}
		verdicts "$EVID/$p/findings.json" "$EVID/$p/callgraph.json" "$EVID/$p/verdicts.json"
	done

	want "$lang" >"$EVID/want.json"
	check_findings "$EVID/project/verdicts.json" "$(cat "$EVID/want.json")"
	expect_jq "dependency pass resolved the dependency (has dependency findings)" "$EVID/deps/verdicts.json" 'any(.[]; .module != "app")'
	expect_jq "project pass has no dependency findings" "$EVID/project/verdicts.json" 'all(.[]; .module == "app")'

	# Equivalence: same verdict per first-party finding_id, except divergences.
	jq -r -n --slurpfile p "$EVID/project/verdicts.json" --slurpfile d "$EVID/deps/verdicts.json" \
		--argjson div "$(divergences "$lang")" '
		($d[0] | map({key: .finding_id, value: .reachability}) | from_entries) as $dep
		| $p[0][] | "\(.file):\(.line)" as $k
		| if ($div | index($k)) then
			"PASS \($k): declared divergence, project-only \(.reachability), dependency scan \($dep[.finding_id])"
		  elif $dep[.finding_id] == .reachability then "PASS \($k): both passes read \(.reachability)"
		  else "FAIL \($k): project-only \(.reachability), dependency scan \($dep[.finding_id] // "absent")" end' >>"$VERDICT.tmp"
	# Without either flag there is no user-package universe to classify against.
	expect "verdicts without either flag" \
		"$(jq -r '[.[].reachability] | unique | join(",")' "$EVID/plain/verdicts.json")" not_applicable
}
