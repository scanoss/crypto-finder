# Contributing to Crypto Finder

Thank you for helping. This page gets you from a clone to a pull request.
The rules a change must follow are in [AGENTS.md](AGENTS.md) (for people and
coding agents alike); the code map is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick path

```bash
git clone https://github.com/YOUR_USERNAME/crypto-finder.git
cd crypto-finder
make build          # ./target/crypto-finder
make test           # unit tests with -race, plus reach's tests against the crypto KB
make lint-install   # once: the pinned golangci-lint into ./bin
make lint
```

You need Go 1.26+ and Make. Docker is optional (`make test-docker` runs the
suite as CI does). Tests that need `mvn`, a JDK or another external tool skip
when it is missing.

## Before you open a pull request

- [ ] `make test` and `make lint` pass.
- [ ] Tests cover the new behavior ([CODE_REVIEW_GUIDELINES.md](CODE_REVIEW_GUIDELINES.md#testing-standards)).
- [ ] A user-facing change adds a changelog fragment under `changelog.d/`
      ([its README](changelog.d/README.md)); never edit `CHANGELOG.md` for it.
- [ ] A change to commands, flags, outputs or supported workflows updates
      [the user guide](docs/user-guide/user-guide.html)
      ([its rules](docs/user-guide/AGENTS.md)) and the docs it touches.
- [ ] No detection ruleset content (rules, rule ids, cards, conditions,
      fixtures derived from them) anywhere in the diff. Tests build small,
      invented rules inline.
- [ ] Engine changes (call graph, parsers, contracts loader, stitcher) go to
      [scanoss/reach](https://github.com/scanoss/reach), not here.
- [ ] A graph construction change bumps the ecosystem's graph algorithm id
      ([docs/GRAPH_IDS.md](docs/GRAPH_IDS.md)).
- [ ] The PR body has an `## Evidence` section for every feature the diff
      touches: `go run ./scripts/featuremap check-pr --base origin/main --head HEAD --body-file <file>`.

Use a Conventional Commit title (`feat: ...`, `fix: ...`, `docs: ...`) and
reference the issue it closes.

## Review and merge

Every pull request gets one automated review against [REVIEW.md](REVIEW.md);
answer each of its inline comments with the fixing commit or a reason. A
maintainer merges once checks are green and the merge gate passes
([AGENTS.md](AGENTS.md#pull-requests-and-merging)).

## Tests

```bash
make test                                   # everything, with coverage.out
make test-docker                            # the suite inside Dockerfile.test, as CI runs it
go test ./internal/scanner/...              # one package
go test -run TestName ./internal/scanner/   # one test
make coverage                               # coverage.html
make coverage-check                         # the 80% threshold CI enforces (needs go-test-coverage)
```

Install the coverage checker with
`go install github.com/vladopajic/go-test-coverage/v2@v2.19.0`.

### What CI runs

| Guard | Command | Workflow |
|---|---|---|
| Engine import boundary, graph id guard, equivalence, cards, scripts, feature map | `make test-guards` | `test.yml` |
| reach's tests that need the crypto KB | `make test-reach` | `test.yml` |
| Full suite with coverage thresholds | `make test-docker` | `test.yml` |
| Lint (pinned `golangci-lint`) | `make lint` | `lint.yml` |
| Binary size budget | `.claude/skills/verify/scripts/budgets.sh size` | `lint.yml` |
| Feature map and PR evidence | `go run ./scripts/featuremap check-docs` | `pr-hygiene.yml` |
| Startup budgets, network end-to-end | see the workflow | `nightly-e2e.yml` (nightly) |

### Opt-in harnesses

These need an input that is not in the repository and skip without it.

| Harness | Run with |
|---|---|
| Wall-clock proof of a full fragment export on `bcprov-jdk18on` 1.84 | `make proof-bcprov-mine` (downloads the sources; `CRYPTO_FINDER_BCPROV_SRC` points at an unpacked tree instead) |
| Live fragment equivalence | `CRYPTO_FINDER_EQUIV_LIVE=<live export>` and `CRYPTO_FINDER_EQUIV_FRAGMENT=<fragment>` |
| Card-matching parity against a ruleset | `CARDMATCH_PARITY_RULES=<rules dir>` and `CARDMATCH_PARITY_INDEX=<card index>` |

## Reporting bugs and ideas

Search [Issues](https://github.com/scanoss/crypto-finder/issues) first. For a
bug, include the command line, `crypto-finder version`, what you expected and
what happened (`--error-format json` output helps). For an idea, describe the
use case.

## License

Contributions are licensed under
[GPL-2.0-only](LICENSE). Every new `.go` file starts with this header:

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

Be kind: this project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
