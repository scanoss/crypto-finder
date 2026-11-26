#!/usr/bin/env bash
# Measure what a change can make worse and hold it to budgets.json. Prints one
# PASS or FAIL line per metric ("FAIL <key> <value> over its budget <limit>")
# and exits 1 on any breach, 2 when it refused to run.
#
# Usage: .claude/skills/verify/scripts/budgets.sh [all|size|startup]...
#   size     binary size of a build with the release ldflags (deterministic)
#   startup  median wall time of `--help` and `version` over 11 runs (noisy)
# size needs only go; startup needs build.sh's binary. Evidence lands in
# bin/verify/evidence/budgets/: measured.tsv, samples.tsv, transcript.txt and
# verdict.txt.
#
# scripts/budgetcheck keeps budgets.json and METRICS below in step: run
# `go run ./scripts/budgetcheck` after editing either.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

# Every key this script can measure. Each must have a budget, and record
# refuses any other key.
METRICS=(binary_size_bytes startup_help_ms startup_version_ms)
BUDGETS="$VERIFY_SCRIPTS/../budgets.json"
STARTUP_RUNS=11

groups=("$@")
((${#groups[@]})) || groups=(all)
for g in "${groups[@]}"; do
	case $g in
	all) groups=(size startup) && break ;;
	size | startup) ;;
	*) die "unknown group '$g'; usage: budgets.sh [all|size|startup]..." ;;
	esac
done
[[ -f $BUDGETS ]] || die "no budget file at $BUDGETS"
command -v jq >/dev/null || die "jq not on PATH"

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

# sample STEP ARGS...: run the binary once in the sandbox, guarded as cf runs
# it, and set SAMPLE_MS (wall time).
sample() {
	local step=$1 start end
	shift
	guard_args "$@"
	sandbox_env "$BOX"
	printf '$ crypto-finder %s\n' "$*" >>"$TRANSCRIPT"
	start=$(date +%s%N)
	set +e
	(cd "$BOX/work" && "${SANDBOX_ENV[@]}" "$BIN" "$@") </dev/null >"$EVID/$step.stdout" 2>"$EVID/$step.stderr"
	CF_EXIT=$?
	set -e
	end=$(date +%s%N)
	SAMPLE_MS=$(((end - start) / 1000000))
	printf '%s\t%s\t%s\n' "$step" "$CF_EXIT" "$SAMPLE_MS" >>"$EVID/samples.tsv"
	echo "  -> exit $CF_EXIT, $SAMPLE_MS ms ($step)" >>"$TRANSCRIPT"
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
	esac
done
end_drive
