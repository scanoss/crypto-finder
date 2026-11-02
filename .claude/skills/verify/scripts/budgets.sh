#!/usr/bin/env bash
# Measure what a change can make worse and hold it to budgets.json. Prints one
# PASS or FAIL line per metric ("FAIL <key> <value> over its budget <limit>")
# and exits 1 on any breach, 2 when it refused to run.
#
# Usage: .claude/skills/verify/scripts/budgets.sh [all|size|startup|scan]...
#   size     binary size of a build with the release ldflags (deterministic)
#   startup  median wall time of `--help` and `version` over 11 runs (noisy)
#   scan     median wall time and peak RSS of two fixed scans over 5 runs,
#            after one warm-up run (noisy)
# size needs only go; startup and scan need build.sh's binary, and scan
# needs opengrep, jq, go and GNU time at /usr/bin/time. Evidence lands in
# bin/verify/evidence/budgets/: measured.tsv, samples.tsv, transcript.txt and
# verdict.txt.
#
# scripts/budgetcheck keeps budgets.json and METRICS below in step: run
# `go run ./scripts/budgetcheck` after editing either.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

# Every key this script can measure. Each must have a budget, and record
# refuses any other key.
METRICS=(binary_size_bytes startup_help_ms startup_version_ms scan_deps_go_wall_ms scan_deps_go_peak_rss_kb scan_polyglot_wall_ms scan_polyglot_peak_rss_kb)
BUDGETS="$VERIFY_SCRIPTS/../budgets.json"
STARTUP_RUNS=11
SCAN_RUNS=5

groups=("$@")
((${#groups[@]})) || groups=(all)
for g in "${groups[@]}"; do
	case $g in
	all) groups=(size startup scan) && break ;;
	size | startup | scan) ;;
	*) die "unknown group '$g'; usage: budgets.sh [all|size|startup|scan]..." ;;
	esac
done
[[ -f $BUDGETS ]] || die "no budget file at $BUDGETS"
command -v jq >/dev/null || die "jq not on PATH"
if [[ " ${groups[*]} " == *" scan "* ]]; then
	[[ -x /usr/bin/time ]] || die "scan needs GNU time at /usr/bin/time (apt-get install time)"
	command -v opengrep >/dev/null || die "scan needs opengrep on PATH"
fi

# record KEY VALUE: compare one measured value with its budget.
record() {
	local key=$1 value=$2 limit
	[[ " ${METRICS[*]} " == *" $key "* ]] || die "record: $key is not in METRICS"
	printf '%s\t%s\n' "$key" "$value" >>"$EVID/measured.tsv"
	limit=$(jq -r --arg k "$key" '.budgets[$k].limit // empty' "$BUDGETS")
	if [[ -z $limit ]]; then
		fail "$key $value has no budget in budgets.json"
	elif ((value > limit)); then
		fail "$key $value over its budget $limit"
	else
		pass "$key $value within its budget $limit"
	fi
}

# median N...: the middle value (runs are odd in number).
median() { printf '%s\n' "$@" | sort -n | sed -n "$((($# + 1) / 2))p"; }
maximum() { printf '%s\n' "$@" | sort -n | tail -1; }

# sample STEP ARGS...: run the binary once in the sandbox, guarded as cf runs
# it, and set SAMPLE_MS (wall time) and SAMPLE_KB (peak RSS that GNU time
# reports for the process tree, so a scanner child counts when it is larger;
# 0 without GNU time, which only the startup group allows).
sample() {
	local step=$1 start end
	shift
	guard_args "$@"
	sandbox_env "$BOX"
	printf '$ crypto-finder %s\n' "$*" >>"$TRANSCRIPT"
	echo 0 >"$BOX/rss"
	local timer=()
	[[ -x /usr/bin/time ]] && timer=(/usr/bin/time -f %M -o "$BOX/rss")
	start=$(date +%s%N)
	set +e
	(cd "$BOX/work" && "${timer[@]}" "${SANDBOX_ENV[@]}" "$BIN" "$@") </dev/null >"$EVID/$step.stdout" 2>"$EVID/$step.stderr"
	CF_EXIT=$?
	set -e
	end=$(date +%s%N)
	SAMPLE_MS=$(((end - start) / 1000000))
	SAMPLE_KB=$(tail -1 "$BOX/rss")
	printf '%s\t%s\t%s\t%s\n' "$step" "$CF_EXIT" "$SAMPLE_MS" "$SAMPLE_KB" >>"$EVID/samples.tsv"
	echo "  -> exit $CF_EXIT, $SAMPLE_MS ms, $SAMPLE_KB KB ($step)" >>"$TRANSCRIPT"
	! holds_remote_rules "$BOX" || die "a remote ruleset landed in the sandbox HOME; isolation broken"
}

# measure_size: build cmd/crypto-finder as the Makefile and .goreleaser.yml do
# (-s -w plus the version -X flags, no -trimpath) and record its size. The
# version strings are fixed so two builds of one tree match byte for byte.
measure_size() {
	local pkg=github.com/scanoss/crypto-finder/internal/version out="$BOX/crypto-finder-release" size
	(cd "$REPO" && go build -o "$out" \
		-ldflags "-s -w -X $pkg.Version=v0.0.0-budget -X $pkg.GitCommit=$(git rev-parse HEAD) -X $pkg.BuildDate=1970-01-01T00:00:00Z" \
		./cmd/crypto-finder)
	size=$(stat -c %s "$out")
	echo "# size: $(go version), CGO_ENABLED=$(go env CGO_ENABLED), $size bytes" >>"$TRANSCRIPT"
	record binary_size_bytes "$size"
}

# measure_startup KEY ARGS...: median wall time of STARTUP_RUNS runs.
measure_startup() {
	local key=$1 i ms=()
	shift
	for ((i = 1; i <= STARTUP_RUNS; i++)); do
		sample "$key-$i" "$@"
		((CF_EXIT == 0)) || {
			fail "$key: crypto-finder $* exited $CF_EXIT (see $key-$i.stderr)"
			return
		}
		ms+=("$SAMPLE_MS")
	done
	record "$key" "$(median "${ms[@]}")"
}

# measure_scan NAME ARGS...: one warm-up run (it fills the sandbox's Go build
# cache), then SCAN_RUNS runs; median wall time, highest peak RSS.
measure_scan() {
	local name=$1 i ms=() kb=()
	shift
	for ((i = 0; i <= SCAN_RUNS; i++)); do
		sample "scan_$name-$i" "$@"
		((CF_EXIT == 0)) || {
			fail "scan_$name: scan exited $CF_EXIT (see scan_$name-$i.stderr)"
			return
		}
		((i == 0)) && continue
		ms+=("$SAMPLE_MS")
		kb+=("$SAMPLE_KB")
	done
	record "scan_${name}_wall_ms" "$(median "${ms[@]}")"
	record "scan_${name}_peak_rss_kb" "$(maximum "${kb[@]}")"
}

# measure_scans: the reachability-dependencies go fixture wired as its driver
# wires it, and the polyglot (Java, Kotlin, TypeScript) project-reachability
# fixture of TestPolyglotScanResolvesEachFindingInItsOwnEcosystem.
measure_scans() {
	# shellcheck source=drive/reachability-dependencies.sh
	source "$VERIFY_SCRIPTS/drive/reachability-dependencies.sh"
	prepare go
	cp -R "$FIXTURES/polyglot_reachability" "$BOX/work/polyglot"
	measure_scan deps_go --error-format json scan --scanner opengrep --no-remote-rules --findings-cache none \
		--languages go --rules "$RULES_DIR/transitive-reachability.yaml" \
		--output "$BOX/deps-findings.json" --export-callgraph "$BOX/deps-callgraph.json" \
		--scan-dependencies "$BOX/work/fixture/app"
	measure_scan polyglot --error-format json scan --scanner opengrep --no-remote-rules --findings-cache none \
		--rules "$RULES_DIR/polyglot-reachability.yaml" \
		--output "$BOX/polyglot-findings.json" --export-callgraph "$BOX/polyglot-callgraph.json" \
		--export-callgraph-project-reachability "$BOX/work/polyglot"
}

begin_drive budgets
{
	echo "# groups: ${groups[*]}"
	echo "# machine: $(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1), $(nproc) cores, $(uname -sm)"
} >>"$TRANSCRIPT"
: >"$EVID/measured.tsv"
: >"$EVID/samples.tsv"
for g in "${groups[@]}"; do
	case $g in
	size) measure_size ;;
	startup)
		measure_startup startup_help_ms --help
		measure_startup startup_version_ms version
		;;
	scan) measure_scans ;;
	esac
done
end_drive
