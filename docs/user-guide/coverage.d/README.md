# User-guide coverage fragments

A pull request that adds or extends contract coverage adds one file here instead
of editing the coverage paragraphs of `../user-guide.html`.

- Name it `<ecosystem>-<library>.html` (for example `node-sodium-plus.html`).
  Fragments are appended to the guide in file-name order.
- The file holds exactly one `<p>...</p>` paragraph, on a single line, in the
  same wording the guide uses today.
- Follow the public-content rules in `../AGENTS.md`.

At release time `go run ./scripts/relprep guide` appends every fragment to the
block between the `coverage-fragments` markers of `user-guide.html` and deletes
the fragments. Paragraphs already in the guide stay where they are.
