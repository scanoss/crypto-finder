#!/usr/bin/env bash
# Drive one feature from features/ against bin/verify/crypto-finder in a fresh
# sandbox and write its evidence to bin/verify/evidence/<feature-id>/[<lang>/].
# Exits 0 when verdict.txt reads PASS, 1 when a check failed, 2 when the drive
# refused to run (missing binary, broken isolation, unknown feature).
#
# Usage: .claude/skills/verify/scripts/run.sh <feature-id> [lang|all]
#   feature-id: a file name under features/ without .md
#   lang:       for the per-language features; "all" drives every language
#               whose toolchain is present and reports the rest as SKIP
# Env: VERIFY_FIXTURES=<dir> replaces testdata/projects (same layout).
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
[[ -n $feature ]] || die "usage: run.sh <feature-id> [lang|all]; features: $(drivers)"
drive="$VERIFY_SCRIPTS/drive/$feature.sh"
[[ -f $drive ]] || die "unknown feature '$feature'; features: $(drivers)"
# shellcheck source=/dev/null
source "$drive"

lang=${2:-${DEFAULT_LANG:-}}
if [[ -n ${LANGS:-} ]]; then
	[[ -n $lang ]] || die "$feature needs a language: ${LANGS} or all"
	if [[ $lang == all ]]; then
		status=0
		for l in $LANGS; do
			if ! lang_ready "$l"; then
				echo "SKIP $feature $l: toolchain missing ($(lang_needs "$l"))"
				continue
			fi
			"$0" "$feature" "$l" || status=1
		done
		exit "$status"
	fi
	[[ " $LANGS " == *" $lang "* ]] || die "$feature supports: $LANGS"
	lang_ready "$lang" || die "$feature $lang: toolchain missing ($(lang_needs "$lang")); doctor.sh shows what is present"
else
	[[ -z $lang ]] || die "$feature takes no language"
fi

begin_drive "$feature" "$lang"
drive "$lang"
end_drive
