#!/usr/bin/env bash
# Remove the sandboxes (isolated HOMEs, venvs, fixture copies) and stop any
# API stub a killed drive left running. Keeps bin/verify/evidence/ and the
# binary. Refuses while a drive holds a lock unless --force.
#
# Usage: .claude/skills/verify/scripts/cleanup.sh [--force]
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

force=0
[[ ${1:-} == --force ]] && force=1
shopt -s nullglob

if [[ ! -d $SANDBOX_ROOT ]]; then
	echo "cleanup: no sandbox under $RUN_DIR"
else
	locks=("$SANDBOX_ROOT"/*.lock)
	if ((${#locks[@]} > 0 && !force)); then
		die "drives hold locks: ${locks[*]}; wait for them or pass --force"
	fi
	# Stop only the stubs our drives started, by the pid they recorded.
	for pidfile in "$SANDBOX_ROOT"/*/stub.pid; do
		pid=$(cat "$pidfile")
		if [[ -r /proc/$pid/cmdline && $(tr '\0' ' ' <"/proc/$pid/cmdline") == *api-stub.py* ]]; then
			kill "$pid" && echo "cleanup: stopped API stub $pid"
		fi
	done
	remove_tree "$SANDBOX_ROOT"
	echo "cleanup: removed $SANDBOX_ROOT"
fi
if [[ -d $EVIDENCE_ROOT ]]; then
	echo "cleanup: evidence kept in $EVIDENCE_ROOT:"
	for v in "$EVIDENCE_ROOT"/*/verdict.txt "$EVIDENCE_ROOT"/*/*/verdict.txt; do
		echo "  ${v#"$EVIDENCE_ROOT"/}: $(head -1 "$v")"
	done
fi
