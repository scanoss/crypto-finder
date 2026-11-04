---
name: merge-risk
description: Assess the risk of merging a crypto-finder pull request and record it on the PR, which `go run ./scripts/mergeready check` requires before any merge. Use when a PR is green and its review comments are answered, before merging it, or when asked for a PR's merge risk.
metadata:
  credits:
    skill: merge-risk
    author: Warp (warpdotdev/common-skills), after Matt Pocock; adapted from scanoss/earnie
    url: "https://github.com/mattpocock/skills/blob/main/skills/engineering/pr/SKILL.md"
---

# Merge risk

The merge gate (`scripts/mergeready`, run by the `PreToolUse` hook before every merge) refuses a pull request whose head commit has no merge-risk assessment by its author. A low one lets the agent merge. A medium or high one waits for a person: an approving review of the head commit from someone other than the author who can write to the repository, or the `risk-accepted` label added in GitHub after the latest assessment. An agent never adds, removes or asks a tool to set that label; the hook refuses any command that could.

You judge; `go run ./scripts/mergeready risk` scores. It turns your verdicts into a level, raises it to the floor the changed paths set (below), and keeps one comment on the PR for its head commit. You cannot argue the floor down, and you cannot pick the level: judge each category honestly and let the command add it up. The gate recomputes the floor itself.

## Steps

1. Read the PR as a reviewer would, not as its author:
   - the description, the linked issue if any, and `git diff origin/main...HEAD`;
   - the `## Evidence` section and what the verify runs it links show;
   - the CI results and Claude's review comments with their replies.
2. Judge the five categories below. For each, write the gaps that raise the risk as short bullets that point at files or lines. A category with no gap gets its best verdict and no bullets.
3. Write the verdicts to a JSON file outside the repository (your scratch directory):

   ```json
   {
     "alignment": {"verdict": "good", "gaps": []},
     "impact": {"verdict": "medium", "gaps": ["`internal/scan/export.go`: every callgraph export goes through the changed route ranking"]},
     "verification": {"verdict": "decent", "gaps": ["no run on a dependency graph larger than the fixtures"]},
     "rollback": {"verdict": "low", "gaps": []},
     "error_detection": {"verdict": "n/a", "gaps": []}
   }
   ```

4. Check it with `go run ./scripts/mergeready risk --pr <n> --verdicts <file> --dry-run`, then run it without `--dry-run` to post. Post as the PR's author (the account the agent opened it with): the gate reads only the author's assessment. Run it again after every push: an assessment covers one head commit.
5. Low: merge (`gh pr merge <n> --squash`). Medium or high: tell the person the level and the gaps, link the comment, and stop until they approve or label it.

## Categories

- **Alignment** (`poor`, `decent`, `good`): the code does what the description and the issue say. Behaviour assumptions and drive-by changes are written down in the PR.
- **Impact** (`large`, `medium`, `small`): how far the change reaches. Think about the blast radius: every scan, every ecosystem a parser or the call graph touches, every consumer of an export (Earnie imports `pkg/graphfrag`, `pkg/schema`, `pkg/failure` and `pkg/paramcondition`), large dependency graphs. Sensitive areas carry outsized risk whatever the diff size: the reachability rules in AGENTS.md, output contracts and their versions, the merge gate, CI and release, dependency bumps. `REVIEW.md` lists what matters most.
- **Verification** (`poor`, `decent`, `good`): the behaviour is proven, not only claimed. A change to a verify feature needs its evidence (`.claude/skills/verify/scripts/run.sh <id>`), preferably before and after. A change that can move performance needs a measurement (`budgets.sh`). Edge cases are tested, or the PR says why not. Missing evidence for a change to scan output is `poor`.
- **Rollback** (`high`, `medium`, `low`): the cost of undoing it after the merge. A revert of plain code is `low`. A published release or tag, a schema version consumers already read, a shipped failure code, or a cache key (`GraphAlgoVersion`) consumers already stored is a one-way door: `high`.
- **Error detection** (`poor`, `decent`, `good`, `n/a`): if this breaks in a release, someone finds out before a customer does. Look for swallowed errors, fallbacks that silently drop findings or reachability, and missing warnings on a degraded path. `n/a` when nothing ships (docs, tests, CI).

## Scoring

Each verdict is worth 3 (worst) to 1 (best); `n/a` counts as 1. The weights are alignment 1, impact 2, verification 2, rollback 1.5, error detection 1. A weighted mean below 1.5 is low, below 2.25 medium, otherwise high. The same scale as scanoss/earnie's `tools/merge_risk.py`.

## Path floors

`riskFloors` in `scripts/mergeready/risk.go` holds them. Tests (`_test.go`) and `testdata/` set no floor. A rename counts its old path too.

| Floor | Paths | Why |
| --- | --- | --- |
| high | `.github/workflows/**`, `.github/actions/**` | CI decides what is green, `release.yml` publishes on a tag and `version-bump.yml` creates it; a mistake reaches every PR or a release. |
| high | `scripts/mergeready/**`, `.claude/settings.json` | The merge gate and the hook that runs it: the only stop, since `main` has no branch protection. |
| high | `.goreleaser*`, `Dockerfile.goreleaser*`, `scripts/relprep/**` | What a release builds and publishes (binaries and images), and the release-prep that folds the changelog and the guide. A published release cannot be taken back. |
| medium | `go.mod`, `go.sum` | A dependency bump changes code nobody reviewed in this PR, such as the tree-sitter grammars the parsers use. |
| medium | `schemas/**`, `pkg/schema/**`, `pkg/failure/**`, `pkg/graphfrag/{export,callgraph_export,findings_envelope,intern_functions,model}.go` | The output contracts other tools read: the published JSON schemas, the interim report, the stable failure codes, and the files that define the graph-fragment and callgraph wire formats and their versions. Earnie imports these packages. |
| medium | `.golangci.yml`, `.golangci-lint-version`, `.testcoverage.yml` | The configuration of a CI check; loosening it weakens every later PR. |

The knowledge-base YAML (`internal/callgraph/contracts/**`), the stitcher (`pkg/graphfrag/stitch*.go`) and local-only Dockerfiles (`Dockerfile`, `Dockerfile.test`, ...) set no floor: they change often, the loader and the tests check them, and a revert undoes them. Judge them on impact and verification instead.
