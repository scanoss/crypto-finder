# Changelog fragments

Every user-facing pull request adds one file here instead of editing
`CHANGELOG.md`. Two pull requests then never touch the same lines.

- Name it `<slug>.<section>.md`, where `<section>` is `added`, `changed`,
  `deprecated`, `removed`, `fixed` or `security`. Example:
  `node-sodium-plus.added.md`. Use a slug that is unique to your change.
- The file holds one or more Markdown bullets, each starting with `- `. No
  headings. A bullet may wrap onto indented continuation lines.
- Write for consumers of the tool, as AGENTS.md describes.

At release time `go run ./scripts/relprep changelog -version X.Y.Z` folds all
fragments into a new `## [X.Y.Z]` section of `CHANGELOG.md` and deletes them.
Entries already written under `[Unreleased]` in `CHANGELOG.md` stay valid and
are released together with the fragments.
