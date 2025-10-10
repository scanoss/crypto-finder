# Version management
VERSION ?= $(shell git tag --sort=-version:refname | head -n 1)
ifeq ($(VERSION),)
VERSION := dev
endif


BUILD_DIR := ./target

# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help


lint: ## Lints the code
	@golangci-lint run ./...

build: ## Builds the CLI
	@echo "Building SCANOSS Crypto Finder CLI..."
	@go build -o $(BUILD_DIR)/scanoss-crypto-finder cmd/crypto-finder/main.go

clean: ## Cleans build artifacts
	@rm -rf $(BUILD_DIR)

run: build ## Runs the CLI (use ARGS="..." to pass arguments)
	@$(BUILD_DIR)/scanoss-crypto-finder $(ARGS)