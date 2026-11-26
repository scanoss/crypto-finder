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
# Stage 2: Runtime image (the binary and CA certificates)
# ============================================================================
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

# Install minimal runtime dependencies
# - ca-certificates: For HTTPS requests
RUN apk add --no-cache ca-certificates=20260611-r0 && rm -rf /var/cache/apk/*

# Copy the crypto-finder binary from builder
COPY --from=builder /build/crypto-finder /usr/local/bin/crypto-finder

# Create workspace directory
WORKDIR /workspace

# Add labels for metadata
ARG VERSION=dev
LABEL org.opencontainers.image.title="SCANOSS Crypto Finder"
LABEL org.opencontainers.image.description="A tool to scan source code for cryptographic algorithm usage"
LABEL org.opencontainers.image.vendor="SCANOSS"
LABEL org.opencontainers.image.source="https://github.com/scanoss/crypto-finder"
LABEL org.opencontainers.image.licenses="GPL-2.0"
LABEL org.opencontainers.image.version="${VERSION}"

# Verify installation
RUN crypto-finder version

# Set entrypoint
ENTRYPOINT ["crypto-finder"]

# Default command shows help
CMD ["--help"]
