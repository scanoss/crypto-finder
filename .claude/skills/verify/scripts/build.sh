#!/usr/bin/env bash
# Build cmd/crypto-finder into bin/verify/crypto-finder and record what was
# built in bin/verify/state.env. Run it again after any Go change.
#
# Usage: .claude/skills/verify/scripts/build.sh
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

mkdir -p "$RUN_DIR"
head=$(git -C "$REPO" rev-parse HEAD)
fingerprint=$(source_fingerprint)
pkg=github.com/scanoss/crypto-finder/internal/version
(cd "$REPO" && go build -buildvcs=false -o "$BIN.tmp" \
	-ldflags "-X $pkg.Version=verify-${head:0:12}-$fingerprint -X $pkg.GitCommit=$head -X $pkg.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	./cmd/crypto-finder)
mv "$BIN.tmp" "$BIN"

version_line=$("$BIN" version | head -1)
{
	printf 'VERIFY_BINARY=%q\n' "$BIN"
	printf 'VERIFY_HEAD=%q\n' "$head"
	printf 'VERIFY_SOURCE_FINGERPRINT=%q\n' "$fingerprint"
	printf 'VERIFY_VERSION=%q\n' "$version_line"
	printf 'VERIFY_BUILT_AT=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$STATE"
cat "$STATE"
