# Contributing to Crypto Finder

Thank you for your interest in contributing to Crypto Finder! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [License](#license)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/crypto-finder.git
   cd crypto-finder
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/scanoss/crypto-finder.git
   ```

## Development Setup

### Prerequisites

- Go 1.25 or later
- Make
- Docker (optional, for container testing)

### Building the Project

```bash
# Install dependencies
go mod download

# Build the binary
make build

# Run tests
make test

# Run linter
make lint
```

### Running Locally

```bash
# Build and install
make install

# Run crypto-finder
crypto-finder scan /path/to/code
```

## How to Contribute

### Reporting Bugs

- Check if the bug has already been reported in [Issues](https://github.com/scanoss/crypto-finder/issues)
- If not, create a new issue with a clear title and description
- Include steps to reproduce, expected behavior, and actual behavior
- Add relevant logs, screenshots, or code samples

### Suggesting Enhancements

- Open an issue with the `enhancement` label
- Clearly describe the feature and its benefits
- Provide examples of how it would be used

### Submitting Code Changes

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the [Code Style Guidelines](#code-style-guidelines)

3. Write or update tests as needed

4. Ensure all tests pass:
   ```bash
   make test
   ```

5. Run the linter and fix any issues:
   ```bash
   make lint
   ```

6. Commit your changes with a clear commit message:
   ```bash
   git commit -m "feat: brief description"
   ```

7. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

8. Open a Pull Request against the `main` branch

## Code Style Guidelines

This project follows standard Go conventions and uses automated linting:

### General Guidelines

- Follow the [Effective Go](https://go.dev/doc/effective_go) guide
- Use `gofmt` to format your code (automatically done by most editors)
- Write clear, self-documenting code with meaningful variable names
- Add comments for exported functions, types, and packages
- Keep functions small and focused on a single responsibility

### Linting

The project uses `golangci-lint` with configuration in `.golangci.yml`. Run the linter before submitting:

```bash
make lint
```

Fix any issues reported by the linter. Common rules include:
- No unused variables or imports
- Proper error handling (don't ignore errors)
- Consistent naming conventions
- No cyclomatic complexity violations
- Proper use of context

### Project Structure

- `cmd/crypto-finder/` - Main application entry point
- `internal/` - Internal packages (not importable by external projects)
  - `cli/` - CLI commands and flags
  - `scanner/` - Scanning engine implementations
  - `converter/` - Output format converters
  - `config/` - Configuration management
  - `cache/` - Caching logic
  - `rules/` - Rule management
- `testdata/` - Test fixtures and sample data

## Testing Requirements

### Writing Tests

- Write unit tests for all new functionality
- Place tests in `*_test.go` files alongside the code they test
- Use table-driven tests where appropriate
- Mock external dependencies

### Test Coverage

- Maintain or improve the current test coverage
- Run coverage report:
  ```bash
  make test-coverage
  ```
- Aim for at least 80% coverage for new code

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run tests for a specific package
go test ./internal/scanner/...

# Run a specific test
go test -run TestScannerName ./internal/scanner/
```

## Pull Request Process

1. **Before Submitting:**
   - Ensure all tests pass (`make test`)
   - Run the linter (`make lint`)
   - Update documentation if needed
   - Add or update tests for your changes
   - Update CHANGELOG.md with your changes (under "Unreleased" section)

2. **PR Title and Description:**
   - Use a clear, descriptive title
   - Reference any related issues (e.g., "Fixes #123")
   - Describe what changes you made and why
   - Include any breaking changes or migration notes

3. **Review Process:**
   - Maintainers will review your PR
   - Address any feedback or requested changes
   - Keep your branch up to date with `main`:
     ```bash
     git fetch upstream
     git rebase upstream/main
     ```

4. **Merging:**
   - PRs require approval from at least one maintainer
   - All CI checks must pass
   - Once approved, a maintainer will merge your PR

## License

By contributing to Crypto Finder, you agree that your contributions will be licensed under the [GNU General Public License v2.0 only (GPL-2.0-only)](LICENSE).

All source code files must include the appropriate GPL-2.0-only license header. New files should include:

```go
// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
```

---

## Questions?

If you have questions about contributing, feel free to:
- Open an issue for discussion
- Contact the maintainers
- Check the project documentation at https://scanoss.readthedocs.io

Thank you for contributing to Crypto Finder!
