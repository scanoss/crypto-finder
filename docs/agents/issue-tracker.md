# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- Create, read, update, label, comment on, and close issues using `gh issue`.
- Infer the repository from the current clone's Git remote.
- When a skill says "publish to the issue tracker," create a GitHub issue.
- When a skill says "fetch the relevant ticket," use `gh issue view <number> --comments`.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## Wayfinding operations

Use one `wayfinder:map` issue with linked child issues. Prefer GitHub sub-issues and
native issue dependencies; fall back to task lists and `Blocked by:` references when
those features are unavailable. Claim work by assigning the child issue to yourself.
