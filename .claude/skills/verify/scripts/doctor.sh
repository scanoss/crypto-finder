#!/usr/bin/env bash
# Read-only: is this checkout ready to drive? Exits 1 when a required piece is
# missing or the binary is stale; a missing language toolchain only marks that
# language SKIP.
#
# Usage: .claude/skills/verify/scripts/doctor.sh
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

bad=0
shopt -s nullglob
ok() { echo "ok    $*"; }
no() {
	echo "FAIL  $*"
	bad=1
}
info() { echo "info  $*"; }

# Binary and build state.
if [[ ! -x $BIN ]]; then
	no "binary: $BIN missing (run build.sh)"
elif [[ ! -f $STATE ]]; then
	no "state: $STATE missing (run build.sh)"
else
	# shellcheck source=/dev/null
	source "$STATE"
	head=$(git -C "$REPO" rev-parse HEAD)
	commit=$("$BIN" version | sed -n 's/^ *Git commit: *//p')
	if [[ $VERIFY_SOURCE_FINGERPRINT != "$(source_fingerprint)" ]]; then
		no "binary: Go sources changed since build.sh ran at ${commit:0:12} (run build.sh)"
	elif [[ $commit != "$head" ]]; then
		ok "binary: $VERIFY_VERSION built at ${commit:0:12}; HEAD ${head:0:12} has the same Go sources"
	else
		ok "binary: $VERIFY_VERSION (HEAD ${head:0:12}, built $VERIFY_BUILT_AT)"
	fi
fi

# Scanner and tools the scripts need.
if command -v opengrep >/dev/null; then
	ok "opengrep: $(opengrep --version 2>/dev/null | head -1) at $(command -v opengrep)"
else
	no "opengrep: not on PATH (every scan drive needs it)"
fi
if command -v semgrep >/dev/null; then info "semgrep: $(command -v semgrep) (drives use opengrep)"; else info "semgrep: absent (not needed)"; fi
for tool in jq git realpath; do
	if command -v "$tool" >/dev/null; then ok "$tool: $(command -v "$tool")"; else no "$tool: not on PATH"; fi
done

# Per-language toolchains for the reachability drives.
have() { command -v "$1" >/dev/null; }
lang() { if "${@:2}"; then ok "lang $1: ready"; else info "lang $1: SKIP ($3 missing)"; fi; }
lang go have go
lang python have python3
if have python3 && ! python3 -c 'import venv, ensurepip' 2>/dev/null; then info "lang python: SKIP (python3 has no venv/ensurepip)"; fi
ok "lang node: ready (the npm resolver reads package-lock.json and node_modules; no node toolchain needed)"
rustup_dir=${RUSTUP_HOME:-$HOME/.rustup}
if have cargo && [[ -d $rustup_dir ]]; then ok "lang rust: ready (RUSTUP_HOME=$rustup_dir kept in the sandbox)"; else info "lang rust: SKIP (cargo or $rustup_dir missing)"; fi
info "lang java: not driven (Maven resolution needs the real ~/.m2)"

# Host environment: drives strip these, but say so.
for var in SCANOSS_API_KEY SC_API_KEY SCANOSS_API_URL VIRTUAL_ENV; do
	if [[ -n ${!var:-} ]]; then info "$var is set in this shell; drives run with env -i and never see it"; fi
done

# Sandboxes: no stale locks, no remote ruleset anywhere.
if [[ -d $SANDBOX_ROOT ]]; then
	for lock in "$SANDBOX_ROOT"/*.lock; do no "stale lock $lock (a drive is running or was killed; cleanup.sh --force)"; done
	for box in "$SANDBOX_ROOT"/*/; do
		box=${box%/}
		[[ $box == *.lock ]] && continue
		if holds_remote_rules "$box"; then no "sandbox $box holds a remote ruleset"; else info "sandbox $box left from a previous drive (cleanup.sh removes it)"; fi
	done
else
	ok "sandbox: none"
fi
if [[ -d $EVIDENCE_ROOT ]]; then
	for v in "$EVIDENCE_ROOT"/*/verdict.txt "$EVIDENCE_ROOT"/*/*/verdict.txt; do
		[[ -f $v ]] && info "evidence ${v#"$EVIDENCE_ROOT"/}: $(head -1 "$v")"
	done
fi

exit "$bad"
