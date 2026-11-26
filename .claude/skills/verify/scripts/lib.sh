#!/usr/bin/env bash
# Shared by build.sh, doctor.sh, run.sh and cleanup.sh. Source it; do not run it.
#
# Everything lives under bin/verify/ in this checkout, so two checkouts never
# collide:
#   bin/verify/crypto-finder        the binary build.sh made
#   bin/verify/state.env            what build.sh recorded about it
#   bin/verify/sandbox/<drive>/     one isolated HOME and work directory per drive
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
# sandbox is $1. Nothing from the caller's environment leaks in except PATH
# and LANG: no SCANOSS_*/SC_* variable (so no API key and no API URL), no
# VIRTUAL_ENV, no real HOME or XDG directory. GOPROXY=off, GOTOOLCHAIN=local
# and CARGO_NET_OFFLINE keep any toolchain the binary runs off the network;
# -modcacherw keeps the sandbox removable. begin_drive creates XDG_CONFIG_HOME.
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
	scan | annotate)
		local has_no_remote=0 rules=0
		for arg in "$@"; do
			case $arg in
			--no-remote-rules) has_no_remote=1 ;;
			--api-key* | --api-url* | --rules-dir* | --no-cache)
				die "refusing $sub with $arg: drives use only testdata/rules via --rules"
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
		((has_no_remote)) || die "refusing $sub without --no-remote-rules"
		((rules > 0)) || die "refusing $sub without a --rules file from $RULES_DIR"
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

# begin_drive FEATURE sets BOX (the sandbox) and EVID (the evidence
# directory), starts both fresh, and takes a lock so the same drive cannot run
# twice at once in this checkout.
begin_drive() {
	local feature=$1 name=$1
	[[ -x $BIN ]] || die "no binary at $BIN; run build.sh"
	mkdir -p "$SANDBOX_ROOT"
	LOCK="$SANDBOX_ROOT/$name.lock"
	mkdir "$LOCK" 2>/dev/null || die "$LOCK exists: another drive of $name is running, or one was killed (run cleanup.sh)"
	trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT
	BOX="$SANDBOX_ROOT/$name"
	EVID="$EVIDENCE_ROOT/$feature"
	remove_tree "$BOX"
	remove_tree "$EVID"
	mkdir -p "$BOX/home/.cache" "$BOX/home/.config" "$BOX/home/.local/share" "$BOX/tmp" "$BOX/work" "$EVID"
	TRANSCRIPT="$EVID/transcript.txt"
	VERDICT="$EVID/verdict.txt"
	: >"$VERDICT.tmp"
	{
		echo "# feature=$feature started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "# binary: $("$BIN" version | head -1); head=$(git -C "$REPO" rev-parse --short HEAD)"
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
