#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

readonly OPENGREP_VERSION="v1.12.1"
readonly OPENGREP_AMD64_SHA256="f18f3c7012070dec9ac612e1d6715a3d9d34e966e8c5f67c190c5f6ac8d63963"
readonly OPENGREP_ARM64_SHA256="078d7b69b04e416ed4f2ebf59bdb7dae17e744e0a3af380f9f392af219aec8b8"
readonly OPENGREP_AMD64_URL="https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86"
readonly OPENGREP_ARM64_URL="https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_aarch64"
readonly RUSTUP_INSTALLER_URL="https://sh.rustup.rs"
readonly RUSTUP_INSTALLER_SHA256="6c30b75a75b28a96fd913a037c8581b580080b6ee9b8169a3c0feb1af7fe8caf"

DOCKERFILES=(
  Dockerfile
  Dockerfile.deps
  Dockerfile.test
  Dockerfile.goreleaser
  Dockerfile.goreleaser.deps
  Dockerfile.goreleaser.slim
  Dockerfile.slim
)

failures=0

fail() {
  printf 'dependency tooling verification failed: %s\n' "$1" >&2
  failures=$((failures + 1))
}

check_package_versions() {
  local file=$1
  local manager=$2
  local unpinned

  unpinned=$(awk -v manager="$manager" '
    function scan(text,   count, i, token) {
      count = split(text, tokens, /[[:space:]]+/)
      for (i = 1; i <= count; i++) {
        token = tokens[i]
        gsub(/[\\;&|]+$/, "", token)
        if (token ~ /^(-|$)/) {
          continue
        }
        if (token ~ /^(git|make|gcc|musl-dev|ca-certificates|curl|python3|python3-pip|gradle|maven)(=|$)/ && token !~ /=/) {
          print token
        }
      }
    }
    $0 ~ manager {
      active = 1
      sub("^.*" manager "[[:space:]]*", "")
      scan($0)
      if ($0 ~ /&&|;/) {
        active = 0
      }
      next
    }
    active {
      scan($0)
      if ($0 ~ /&&|;/) {
        active = 0
      }
    }
  ' "$file")

  if [[ -n "$unpinned" ]]; then
    fail "$file contains unpinned $manager packages: ${unpinned//$'\n'/, }"
  fi
}

for file in "${DOCKERFILES[@]}"; do
  while IFS= read -r line; do
    image=${line#FROM }
    image=${image%% AS *}
    case "$image" in
      builder|scanner-installer)
        continue
        ;;
    esac
    if [[ ! "$image" =~ @sha256:[[:xdigit:]]{64}$ ]]; then
      fail "$file has an unpinned base image: $image"
    fi
  done < <(grep -E '^FROM ' "$file" || true)

  while IFS= read -r line; do
    source=${line#COPY --from=}
    source=${source%% /*}
    case "$source" in
      builder|scanner-installer)
        continue
        ;;
    esac
    if [[ "$source" == *:* && ! "$source" =~ @sha256:[[:xdigit:]]{64}$ ]]; then
      fail "$file has an unpinned external build source: $source"
    fi
  done < <(grep -E '^COPY --from=' "$file" || true)

  if grep -Eq 'curl[^|]*\|[[:space:]]*(bash|sh)' "$file"; then
    fail "$file pipes a downloaded script directly to a shell"
  fi

  if grep -Eq 'default-toolchain[[:space:]]+(stable|latest)|@latest|pip install[[:space:]]+pipenv([[:space:];]|$)' "$file"; then
    fail "$file contains an unpinned tool version"
  fi

  check_package_versions "$file" 'apt-get install'
  check_package_versions "$file" 'apk add'
done

for file in "${DOCKERFILES[@]}"; do
  if grep -q 'opengrep-install.sh' "$file"; then
    fail "$file uses the OpenGrep installer (live GitHub releases API lookup); download the pinned release binary instead"
  fi
  if grep -q 'OPENGREP_VERSION' "$file"; then
    grep -q 'opengrep/opengrep/releases/download' "$file" || fail "$file does not download the pinned OpenGrep release binary"
    grep -q "${OPENGREP_AMD64_SHA256}" "$file" || fail "$file does not pin the amd64 OpenGrep checksum"
    grep -q "${OPENGREP_ARM64_SHA256}" "$file" || fail "$file does not pin the arm64 OpenGrep checksum"
  fi
  if grep -q 'rustup-init.sh' "$file" && ! grep -q "${RUSTUP_INSTALLER_SHA256}" "$file"; then
    fail "$file does not pin the rustup installer checksum"
  fi
done

if ! grep -q 'goreleaser-cross:v1.25.9@sha256:' .github/workflows/release.yml; then
  fail '.github/workflows/release.yml does not pin the GoReleaser image digest'
fi

if grep -REn 'go-test-coverage/v2@latest|pip install pipenv([;[:space:]]|$)|pip install semgrep([;[:space:]]|$)' Makefile CONTRIBUTING.md README.md; then
  fail 'development documentation contains an unpinned tool installation'
fi

if [[ "${1:-}" == "--network" ]]; then
  for pair in \
    "${OPENGREP_AMD64_URL}|${OPENGREP_AMD64_SHA256}" \
    "${OPENGREP_ARM64_URL}|${OPENGREP_ARM64_SHA256}" \
    "${RUSTUP_INSTALLER_URL}|${RUSTUP_INSTALLER_SHA256}"; do
    url=${pair%%|*}
    expected=${pair#*|}
    actual=$(curl --fail --location --silent "$url" | sha256sum | awk '{print $1}')
    if [[ "$actual" != "$expected" ]]; then
      fail "$url checksum changed: expected $expected, got $actual"
    fi
  done
fi

if (( failures > 0 )); then
  exit 1
fi

printf 'dependency tooling verification passed (%d Dockerfiles checked)\n' "${#DOCKERFILES[@]}"
