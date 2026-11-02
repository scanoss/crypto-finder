# shellcheck shell=bash disable=SC2016,SC2034 # sourced by run.sh; jq filters stay single-quoted
# Driver for features/reachability-dependencies.md. Sourced by run.sh.
#
# Fixture: testdata/projects/transitive_reachability/<lang>: app/ (the target)
# depends on liba/ (no crypto), which depends on libb/ (crypto). Expectations
# mirror TestTransitiveReachability in
# internal/cli/transitive_reachability_integration_test.go.
LANGS="go python node rust"
DEFAULT_LANG=go

# prepare LANG: copy the fixture and wire its dependencies the way the test does.
prepare() {
	copy_fixture "$FIXTURES/transitive_reachability/$1"
	local fx="$BOX/work/fixture"
	case $1 in
	go) ;; # app/go.mod replaces both modules with ../liba and ../libb.
	python)
		# A venv outside the target holding liba (requiring libb) and libb.
		new_venv
		install_venv_package translibb "$fx/libb/translibb"
		install_venv_package transliba "$fx/liba/transliba" translibb
		;;
	node)
		# The hoisted tree npm installs for app/package-lock.json.
		mkdir -p "$fx/app/node_modules"
		cp -R "$fx/liba" "$fx/app/node_modules/transliba"
		cp -R "$fx/libb" "$fx/app/node_modules/translibb"
		;;
	rust) ;; # Path dependencies; cargo metadata runs offline with RUSTUP_HOME kept.
	esac
}

# want LANG: the expected verdicts as JSON for check-findings.jq.
want() {
	local liba=transliba libb=translibb app_file app_used app_dead lib_file lib_used lib_dead
	case $1 in
	go) liba=example.com/transliba libb=example.com/translibb app_file=main.go app_used=18 app_dead=22 lib_file=libb.go lib_used=11 lib_dead=17 ;;
	python) app_file=main.py app_used=7 app_dead=11 lib_file=__init__.py lib_used=7 lib_dead=11 ;;
	node) app_file=index.js app_used=5 app_dead=9 lib_file=index.js lib_used=5 lib_dead=9 ;;
	rust) app_file=main.rs app_used=4 app_dead=9 lib_file=lib.rs lib_used=7 lib_dead=12 ;;
	esac
	jq -n --arg a "$liba" --arg b "$libb" --arg af "$app_file" --arg lf "$lib_file" \
		--argjson au "$app_used" --argjson ad "$app_dead" --argjson lu "$lib_used" --argjson ld "$lib_dead" '[
		{module: "app", file: $af, line: $au, reachability: "reachable", source: "direct", chain: ["app"]},
		{module: "app", file: $af, line: $ad, reachability: "unreachable", source: "direct"},
		{module: $b, file: $lf, line: $lu, reachability: "reachable", source: "dependency",
		 relationship: "transitive", path: [$a, $b], chain: ["app", $a, $b]},
		{module: $b, file: $lf, line: $ld, reachability: "unreachable", source: "dependency",
		 relationship: "transitive", path: [$a, $b]}
	]'
}

drive() {
	local lang=$1
	prepare "$lang"
	cf scan --error-format json scan --scanner opengrep --no-remote-rules --findings-cache none \
		--languages "$(scanner_language "$lang")" --rules "$RULES_DIR/transitive-reachability.yaml" \
		--output "$EVID/findings.json" --export-callgraph "$EVID/callgraph.json" \
		--scan-dependencies "$BOX/work/fixture/app"
	expect "scan --scan-dependencies exit code" "$CF_EXIT" 0
	[[ -s $EVID/findings.json && -s $EVID/callgraph.json ]] || {
		fail "scan wrote no findings.json/callgraph.json (see scan.stderr)"
		return
	}
	verdicts "$EVID/findings.json" "$EVID/callgraph.json" "$EVID/verdicts.json"
	want "$lang" >"$EVID/want.json"
	check_findings "$EVID/verdicts.json" "$(cat "$EVID/want.json")"
}
