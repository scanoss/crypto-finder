#!/usr/bin/env bash
# Shared by build.sh, doctor.sh, run.sh and cleanup.sh. Source it; do not run it.
#
# Everything lives under bin/verify/ in this checkout, so two checkouts never
# collide:
#   bin/verify/crypto-finder        the binary build.sh made
#   bin/verify/state.env            what build.sh recorded about it
#   bin/verify/sandbox/<drive>/     one isolated HOME, venv and fixture copy per drive
#   bin/verify/evidence/<feature>/  proof; cleanup.sh never touches it

set -euo pipefail

VERIFY_SCRIPTS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$VERIFY_SCRIPTS/../../../.." && pwd)
RUN_DIR="$REPO/bin/verify"
BIN="$RUN_DIR/crypto-finder"
# shellcheck disable=SC2034 # read by build.sh and doctor.sh
STATE="$RUN_DIR/state.env"
SANDBOX_ROOT="$RUN_DIR/sandbox"
EVIDENCE_ROOT="$RUN_DIR/evidence"
RULES_DIR="$REPO/testdata/rules"
# VERIFY_FIXTURES swaps testdata/projects for another tree with the same
# layout, e.g. a temp copy with a fixture deliberately broken.
FIXTURES="${VERIFY_FIXTURES:-$REPO/testdata/projects}"
HOST_HOME="$HOME"

# remove_tree DIR: rm -rf that also clears read-only module cache entries.
remove_tree() {
	if [[ -e $1 ]]; then
		chmod -R u+w "$1"
		rm -rf "$1"
	fi
}

die() {
	echo "verify: $*" >&2
	exit 2
}

# source_fingerprint hashes the committed Go source trees plus any uncommitted
# change to them, so doctor.sh can tell whether the binary still matches the
# checkout. Commits that touch only docs or this skill keep it unchanged.
source_fingerprint() {
	(
		cd "$REPO"
		git rev-parse HEAD:cmd HEAD:internal HEAD:pkg HEAD:go.mod HEAD:go.sum
		git diff HEAD --binary -- cmd internal pkg go.mod go.sum
		git ls-files --others --exclude-standard -z -- cmd internal pkg | xargs -0 -r sha256sum
	) | sha256sum | cut -c1-16
}

# sandbox_env fills SANDBOX_ENV with an `env -i` prefix for a drive whose
# sandbox is $1. Nothing from the caller's environment leaks in except PATH,
# LANG and the rustup toolchain directory: no SCANOSS_*/SC_* variable (so no
# API key and no API URL), no VIRTUAL_ENV, no real HOME or XDG directory.
# GOPROXY=off, GOTOOLCHAIN=local and CARGO_NET_OFFLINE keep the toolchains off
# the network (the fixtures resolve through local paths only); -modcacherw
# keeps the sandbox removable. XDG_CONFIG_HOME must exist before opengrep
# runs, or `opengrep --version` dies and the scan reports
# scanner_initialization_failed; begin_drive creates it.
sandbox_env() {
	local box=$1
	SANDBOX_ENV=(env -i
		"PATH=$PATH"
		"LANG=${LANG:-C.UTF-8}"
		"TERM=dumb"
		"HOME=$box/home"
		"XDG_CACHE_HOME=$box/home/.cache"
		"XDG_CONFIG_HOME=$box/home/.config"
		"XDG_DATA_HOME=$box/home/.local/share"
		"TMPDIR=$box/tmp"
		"GOPROXY=off"
		"GOTOOLCHAIN=local"
		"GOFLAGS=-modcacherw"
		"CARGO_NET_OFFLINE=true")
	local rustup="${RUSTUP_HOME:-$HOST_HOME/.rustup}"
	if [[ -d $rustup ]]; then
		SANDBOX_ENV+=("RUSTUP_HOME=$rustup")
	fi
	SANDBOX_ENV+=("${EXTRA_ENV[@]}")
}

# holds_remote_rules BOX: true when the ruleset cache in BOX's HOME has any
# entry. The binary creates that directory empty on every scan; only a scan
# without --no-remote-rules fills it with the downloaded ruleset.
holds_remote_rules() {
	local dir="$1/home/.scanoss/crypto-finder/cache/rulesets"
	[[ -d $dir && -n $(find "$dir" -mindepth 1 -print -quit) ]]
}

# guard_args refuses any invocation that could reach the real rules or the
# SCANOSS API.
guard_args() {
	local sub="" prev="" arg
	for arg in "$@"; do
		case $arg in
		scan | convert | cbom | annotate | version) [[ -z $sub ]] && sub=$arg ;;
		configure) die "refusing 'configure': it writes API credentials" ;;
		esac
	done
	case $sub in
	scan)
		local has_no_remote=0 rules=0
		for arg in "$@"; do
			case $arg in
			--no-remote-rules) has_no_remote=1 ;;
			--api-key* | --api-url* | --rules-dir* | --no-cache)
				die "refusing scan with $arg: drives use only testdata/rules via --rules"
				;;
			esac
			if [[ $prev == --rules || $prev == -r ]]; then
				rules=$((rules + 1))
				case $(realpath -m "$arg") in
				"$RULES_DIR"/*) ;;
				*) die "refusing --rules $arg: rules must come from $RULES_DIR" ;;
				esac
			fi
			prev=$arg
		done
		((has_no_remote)) || die "refusing scan without --no-remote-rules"
		((rules > 0)) || die "refusing scan without a --rules file from $RULES_DIR"
		;;
	cbom)
		local url=""
		for arg in "$@"; do
			[[ $prev == --api-url ]] && url=$arg
			[[ $arg == --api-url=* ]] && url=${arg#--api-url=}
			prev=$arg
		done
		[[ $url =~ ^http://127\.0\.0\.1:[0-9]+$ ]] || die "refusing cbom without --api-url http://127.0.0.1:<port> (the local stub)"
		;;
	esac
}

# begin_drive FEATURE [LANG] sets BOX (the sandbox) and EVID (the evidence
# directory), starts both fresh, and takes a lock so the same drive cannot run
# twice at once in this checkout.
begin_drive() {
	local feature=$1 lang=${2:-}
	local name=$feature${lang:+-$lang}
	[[ -x $BIN ]] || die "no binary at $BIN; run build.sh"
	mkdir -p "$SANDBOX_ROOT"
	LOCK="$SANDBOX_ROOT/$name.lock"
	mkdir "$LOCK" 2>/dev/null || die "$LOCK exists: another drive of $name is running, or one was killed (run cleanup.sh)"
	trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT
	BOX="$SANDBOX_ROOT/$name"
	EVID="$EVIDENCE_ROOT/$feature${lang:+/$lang}"
	remove_tree "$BOX"
	remove_tree "$EVID"
	mkdir -p "$BOX/home/.cache" "$BOX/home/.config" "$BOX/home/.local/share" "$BOX/tmp" "$BOX/work" "$EVID"
	EXTRA_ENV=()
	TRANSCRIPT="$EVID/transcript.txt"
	VERDICT="$EVID/verdict.txt"
	: >"$VERDICT.tmp"
	{
		echo "# feature=$feature lang=${lang:--} started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "# binary: $("$BIN" version | head -1); head=$(git -C "$REPO" rev-parse --short HEAD)"
		echo "# fixtures: $FIXTURES"
		echo "# sandbox: $BOX"
	} >"$TRANSCRIPT"
}

# cf STEP ARGS... runs the binary in the sandbox from $BOX/work. stdout and
# stderr land in $EVID/STEP.stdout and STEP.stderr; the command and its exit
# code go to the transcript; the exit code is left in CF_EXIT. stdin is
# /dev/null unless CF_STDIN names a file.
cf() {
	local step=$1
	shift
	guard_args "$@"
	sandbox_env "$BOX"
	printf '$ crypto-finder %s%s\n' "$*" "${CF_STDIN:+ < $CF_STDIN}" >>"$TRANSCRIPT"
	set +e
	(cd "$BOX/work" && "${SANDBOX_ENV[@]}" "$BIN" "$@") <"${CF_STDIN:-/dev/null}" >"$EVID/$step.stdout" 2>"$EVID/$step.stderr"
	CF_EXIT=$?
	set -e
	echo "  -> exit $CF_EXIT ($step)" >>"$TRANSCRIPT"
	! holds_remote_rules "$BOX" || die "a remote ruleset landed in the sandbox HOME; isolation broken"
}

# sandboxed CMD... runs a helper tool (python3, cp, ...) with the sandbox env.
sandboxed() {
	sandbox_env "$BOX"
	"${SANDBOX_ENV[@]}" "$@"
}

pass() { echo "PASS $*" >>"$VERDICT.tmp"; }
fail() { echo "FAIL $*" >>"$VERDICT.tmp"; }

# expect DESCRIPTION ACTUAL WANTED
expect() {
	if [[ $2 == "$3" ]]; then pass "$1: $2"; else fail "$1: got '$2', want '$3'"; fi
}

# expect_jq DESCRIPTION FILE FILTER: passes when `jq -e FILTER FILE` is true.
expect_jq() {
	if jq -e "$3" "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1 ($3 on $(basename "$2"))"; fi
}

# error_code STDERR_FILE: the code of the --error-format json error, the last
# line of stderr that is a JSON object (log lines precede it).
error_code() {
	grep '^{' "$1" | tail -1 | jq -r '.code // empty' 2>/dev/null || true
}

# end_drive writes verdict.txt (first line VERDICT: PASS|FAIL) and exits
# non-zero when any check failed.
end_drive() {
	local status=PASS
	if grep -q '^FAIL' "$VERDICT.tmp" || ! grep -q '^PASS' "$VERDICT.tmp"; then status=FAIL; fi
	{
		echo "VERDICT: $status ($(grep -c '^PASS' "$VERDICT.tmp") passed, $(grep -c '^FAIL' "$VERDICT.tmp" || true) failed)"
		cat "$VERDICT.tmp"
	} >"$VERDICT"
	rm -f "$VERDICT.tmp"
	cat "$VERDICT"
	echo "evidence: $EVID"
	[[ $status == PASS ]]
}

# --- fixture preparation, mirroring internal/cli/*_reachability_*_test.go ---

# copy_fixture SRC: copy a fixture tree into $BOX/work/fixture. The whole tree
# is copied so relative wiring (Go replace, Cargo path deps) survives.
#
# $BOX/work is made a git repository of its own first. The primary scan honours
# the .gitignore of the repository a target sits in, and this checkout ignores
# bin/, so without it every application file in the copy would be skipped and
# only dependency findings would come back.
copy_fixture() {
	[[ -d $1 ]] || die "fixture $1 not found"
	sandboxed git init -q "$BOX/work"
	cp -R "$1" "$BOX/work/fixture"
	echo "# fixture copied from $1 into its own git repository $BOX/work" >>"$TRANSCRIPT"
}

# new_venv: an empty venv outside the scan target, named "venv" as the tests
# name it. Sets SITE_PACKAGES and adds VIRTUAL_ENV to the drive's env.
new_venv() {
	sandboxed python3 -m venv "$BOX/venv"
	SITE_PACKAGES=$(sandboxed "$BOX/venv/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
	EXTRA_ENV+=("VIRTUAL_ENV=$BOX/venv")
}

# install_venv_package NAME SRCDIR [REQUIRES...]: lay NAME out in the venv the
# way pip leaves it (package files plus a dist-info whose METADATA lists
# REQUIRES as Requires-Dist), without pip or a network.
install_venv_package() {
	local name=$1 src=$2
	shift 2
	local dist="$SITE_PACKAGES/$name-1.0.0.dist-info"
	mkdir -p "$SITE_PACKAGES/$name" "$dist"
	cp -R "$src/." "$SITE_PACKAGES/$name/"
	{
		printf 'Metadata-Version: 2.1\nName: %s\nVersion: 1.0.0\n' "$name"
		local req
		for req in "$@"; do printf 'Requires-Dist: %s\n' "$req"; done
	} >"$dist/METADATA"
	{
		(cd "$SITE_PACKAGES" && find "$name" -type f | sort | sed 's/$/,,/')
		printf '%s\n' "$name-1.0.0.dist-info/METADATA,," "$name-1.0.0.dist-info/RECORD,,"
	} >"$dist/RECORD"
	echo "$name" >"$dist/top_level.txt"
	echo pip >"$dist/INSTALLER"
	echo "# venv: installed $name${1:+ (requires $*)}" >>"$TRANSCRIPT"
}

# lang_needs / lang_ready: the toolchain a language's fixture needs.
lang_needs() {
	case $1 in
	go) echo go ;;
	python) echo "python3 with venv" ;;
	rust) echo "cargo and a rustup toolchain dir" ;;
	node) echo nothing ;;
	*) echo unknown ;;
	esac
}
lang_ready() {
	case $1 in
	go) command -v go ;;
	python) command -v python3 && python3 -c 'import venv, ensurepip' ;;
	rust) command -v cargo && [[ -d ${RUSTUP_HOME:-$HOST_HOME/.rustup} ]] ;;
	node) true ;;
	*) false ;;
	esac >/dev/null 2>&1
}

# scanner_language maps a fixture language to the --languages value.
scanner_language() {
	case $1 in
	node) echo javascript ;;
	*) echo "$1" ;;
	esac
}

# verdicts FINDINGS CALLGRAPH OUT: join the findings report and the call graph
# export into one row per finding graph (see verdicts.jq).
verdicts() {
	jq -n --slurpfile f "$1" --slurpfile g "$2" -f "$VERIFY_SCRIPTS/verdicts.jq" >"$3"
}

# check_findings VERDICTS WANT_JSON: append PASS/FAIL per expected finding.
check_findings() {
	jq -r -n --slurpfile v "$1" --argjson want "$2" -f "$VERIFY_SCRIPTS/check-findings.jq" >>"$VERDICT.tmp"
}
