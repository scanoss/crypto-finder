# Version management
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build variables
BUILD_DIR := ./target
BINARY_NAME := crypto-finder
DOCKER_IMAGE := ghcr.io/scanoss/crypto-finder
LDFLAGS := -ldflags="-s -w \
	-X github.com/scanoss/crypto-finder/internal/cli.Version=$(VERSION) \
	-X github.com/scanoss/crypto-finder/internal/cli.GitCommit=$(GIT_COMMIT) \
	-X github.com/scanoss/crypto-finder/internal/cli.BuildDate=$(BUILD_DATE)"

# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help


lint: ## Lints the code
	@golangci-lint run ./...

build: ## Builds the CLI with version info
	@echo "Building SCANOSS Crypto Finder CLI ($(VERSION))..."
	@mkdir -p $(BUILD_DIR)
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/crypto-finder

clean: ## Cleans build artifacts
	@rm -rf $(BUILD_DIR)

run: build ## Runs the CLI (use ARGS="..." to pass arguments)
	@$(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

version: ## Display current version
	@echo "Current version: $(VERSION)"

test: ## Run all tests
	@go test -v -race -coverprofile=coverage.out ./...

coverage: test ## Generate coverage report
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# ============================================================================
# Docker targets
# ============================================================================

docker-build: ## Build Docker image with Semgrep
	@echo "Building Docker image ($(VERSION))..."
	@docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest \
		-f Dockerfile .
	@echo "Docker image built: $(DOCKER_IMAGE):$(VERSION)"

docker-build-slim: ## Build slim Docker image without Semgrep
	@echo "Building slim Docker image ($(VERSION))..."
	@docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(DOCKER_IMAGE):$(VERSION)-slim \
		-t $(DOCKER_IMAGE):latest-slim \
		-f Dockerfile.slim .
	@echo "Slim Docker image built: $(DOCKER_IMAGE):$(VERSION)-slim"

docker-run: ## Run Docker container with example (use ARGS="scan /workspace/code --rules /workspace/rules")
	@echo "Running Docker container..."
	@docker run --rm -it \
		-v $(PWD):/workspace/code:ro \
		$(DOCKER_IMAGE):latest $(ARGS)

docker-test: ## Test Docker image functionality
	@echo "Testing Docker image..."
	@echo "\n1. Testing version command..."
	@docker run --rm $(DOCKER_IMAGE):latest version
	@echo "\n2. Testing help command..."
	@docker run --rm $(DOCKER_IMAGE):latest --help

docker-shell: ## Open a shell in the Docker container for debugging
	@echo "Opening shell in Docker container..."
	@docker run --rm -it \
		-v $(PWD):/workspace/code:ro \
		--entrypoint /bin/sh \
		$(DOCKER_IMAGE):latest

docker-scan: docker-build ## Quick test: build and scan current directory
	@echo "Running quick scan on current directory..."
	@docker run --rm \
		-v $(PWD):/workspace/code:ro \
		-v $(PWD)/output.json:/workspace/output.json \
		$(DOCKER_IMAGE):latest scan /workspace/code \
		--rules /workspace/code/examples/rules/*.yaml \
		--output-file /workspace/output.json || true
	@echo "Scan complete! Check output.json"

docker-push: ## Push Docker images to GHCR (requires authentication)
	@echo "Pushing Docker images to GHCR..."
	@docker push $(DOCKER_IMAGE):$(VERSION)
	@docker push $(DOCKER_IMAGE):latest
	@docker push $(DOCKER_IMAGE):$(VERSION)-slim
	@docker push $(DOCKER_IMAGE):latest-slim
	@echo "✅ Docker images pushed successfully!"

docker-login: ## Login to GitHub Container Registry
	@echo "Logging in to GHCR..."
	@echo "Please use a GitHub Personal Access Token with 'write:packages' scope"
	@docker login ghcr.io

# ============================================================================
# Release targets
# ============================================================================

release-snapshot: ## Test GoReleaser build locally (no publish)
	@echo "Building release snapshot with GoReleaser..."
	@goreleaser release --snapshot --clean --skip=publish
	@echo "✅ Snapshot build complete! Check dist/ directory"

release: ## Create a release with GoReleaser (requires tag)
	@echo "Creating release $(VERSION)..."
	@if [ "$(VERSION)" = "dev" ]; then \
		echo "❌ Error: Cannot release 'dev' version. Please create a git tag first."; \
		echo "Example: git tag -a v1.0.0 -m 'Release v1.0.0' && git push origin v1.0.0"; \
		exit 1; \
	fi
	@goreleaser release --clean
	@echo "✅ Release $(VERSION) complete!"

release-check: ## Check if GoReleaser config is valid
	@goreleaser check
	@echo "✅ GoReleaser configuration is valid!"

# ============================================================================
# Development helpers
# ============================================================================

install: build ## Install the CLI to $GOPATH/bin
	@echo "Installing $(BINARY_NAME) to $(GOPATH)/bin..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "✅ Installed successfully! Run 'crypto-finder --help' to get started."

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
	@echo "✅ Dependencies updated!"
