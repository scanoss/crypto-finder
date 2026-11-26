#!/usr/bin/env bash
# Drive one feature from features/ against bin/verify/crypto-finder in a fresh
# sandbox and write its evidence to bin/verify/evidence/<feature-id>/.
# Exits 0 when verdict.txt reads PASS, 1 when a check failed, 2 when the drive
# refused to run (missing binary, broken isolation, unknown feature).
#
# Usage: .claude/skills/verify/scripts/run.sh <feature-id>
#   feature-id: a driver name under drive/, without .sh
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

drivers() {
	local f
	for f in "$VERIFY_SCRIPTS"/drive/*.sh; do
		f=${f##*/}
		printf '%s ' "${f%.sh}"
	done
}

feature=${1:-}
[[ -n $feature ]] || die "usage: run.sh <feature-id>; features: $(drivers)"
[[ $# -eq 1 ]] || die "run.sh takes only a feature id; features: $(drivers)"
drive="$VERIFY_SCRIPTS/drive/$feature.sh"
[[ -f $drive ]] || die "unknown feature '$feature'; features: $(drivers)"
# shellcheck source=/dev/null
source "$drive"

begin_drive "$feature"
drive
end_drive
