# ============================================================================
# Stage 1: Build Go binary
# ============================================================================
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

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
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X github.com/scanoss/crypto-finder/internal/version.Version=${VERSION} \
    -X github.com/scanoss/crypto-finder/internal/version.GitCommit=${GIT_COMMIT} \
    -X github.com/scanoss/crypto-finder/internal/version.BuildDate=${BUILD_DATE}" \
    -o crypto-finder \
    ./cmd/crypto-finder

# ============================================================================
# Stage 2: Install Semgrep
# ============================================================================
FROM python:3.11-slim AS semgrep-installer

# Install Semgrep 1.119.0
RUN pip install --no-cache-dir semgrep==1.119.0

# ============================================================================
# Stage 3: Final image with Python runtime
# ============================================================================
FROM semgrep-installer

# Copy the crypto-finder binary from builder
COPY --from=builder /build/crypto-finder /usr/local/bin/crypto-finder

# Create workspace directory
WORKDIR /workspace

# Add labels for metadata
LABEL org.opencontainers.image.title="SCANOSS Crypto Finder"
LABEL org.opencontainers.image.description="A tool to scan source code for cryptographic algorithm usage"
LABEL org.opencontainers.image.vendor="SCANOSS"
LABEL org.opencontainers.image.source="https://github.com/scanoss/crypto-finder"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="${VERSION}"

# Verify installations
RUN crypto-finder version && semgrep --version

# Set entrypoint
ENTRYPOINT ["crypto-finder"]

# Default command shows help
CMD ["--help"]
