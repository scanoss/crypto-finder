# ============================================================================
# Stage 1: Build Go binary
# ============================================================================
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

# Install build dependencies
RUN apk add --no-cache \
    git=2.54.0-r0 \
    make=4.4.1-r4 \
    gcc=15.2.0-r5 \
    musl-dev=1.2.6-r2

# Set working directory
WORKDIR /build

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version injection
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Build the binary with version info injected
RUN CGO_ENABLED=1 GOOS=linux go build -tags netgo \
    -ldflags="-w -s -extldflags '-static' -X github.com/scanoss/crypto-finder/internal/version.Version=${VERSION} \
    -X github.com/scanoss/crypto-finder/internal/version.GitCommit=${GIT_COMMIT} \
    -X github.com/scanoss/crypto-finder/internal/version.BuildDate=${BUILD_DATE}" \
    -o crypto-finder \
    ./cmd/crypto-finder

# ============================================================================
# Stage 2: Install Scanners (Semgrep and OpenGrep)
# ============================================================================
FROM python:3.11-slim@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff AS scanner-installer

ARG OPENGREP_VERSION=v1.12.1
ARG OPENGREP_AMD64_SHA256=f18f3c7012070dec9ac612e1d6715a3d9d34e966e8c5f67c190c5f6ac8d63963
ARG OPENGREP_ARM64_SHA256=078d7b69b04e416ed4f2ebf59bdb7dae17e744e0a3af380f9f392af219aec8b8
ARG TARGETARCH

# Install system dependencies for downloading the pinned OpenGrep binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=8.14.1-2+deb13u4 \
    ca-certificates=20250419 \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep 1.145.0
RUN pip install --no-cache-dir semgrep==1.145.0

# Install the pinned opengrep release directly. This avoids the installer's
# live releases API lookup while retaining binary integrity verification.
RUN case "${TARGETARCH}" in \
        amd64) asset="opengrep_manylinux_x86"; hash="${OPENGREP_AMD64_SHA256}" ;; \
        arm64) asset="opengrep_manylinux_aarch64"; hash="${OPENGREP_ARM64_SHA256}" ;; \
        *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && install_dir="/root/.opengrep/cli/${OPENGREP_VERSION}" \
    && mkdir -p "${install_dir}" \
    && curl -fsSL "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${asset}" -o "${install_dir}/opengrep" \
    && echo "${hash}  ${install_dir}/opengrep" | sha256sum -c - \
    && chmod a+x "${install_dir}/opengrep" \
    && ln -s "${install_dir}" /root/.opengrep/cli/latest

# ============================================================================
# Stage 3: Final image with Python runtime
# ============================================================================
FROM scanner-installer

# Copy the crypto-finder binary from builder
COPY --from=builder /build/crypto-finder /usr/local/bin/crypto-finder

# Add opengrep to PATH
ENV PATH="$PATH:/root/.opengrep/cli/latest"

# Create workspace directory
WORKDIR /workspace

# Build arguments for labels
ARG VERSION=dev

# Add labels for metadata
LABEL org.opencontainers.image.title="SCANOSS Crypto Finder"
LABEL org.opencontainers.image.description="A tool to scan source code for cryptographic algorithm usage"
LABEL org.opencontainers.image.vendor="SCANOSS"
LABEL org.opencontainers.image.source="https://github.com/scanoss/crypto-finder"
LABEL org.opencontainers.image.licenses="GPL-2.0"
LABEL org.opencontainers.image.version="${VERSION}"

# Verify installations
RUN crypto-finder version && semgrep --version && opengrep --version

# Set entrypoint
ENTRYPOINT ["crypto-finder"]

# Default command shows help
CMD ["--help"]
