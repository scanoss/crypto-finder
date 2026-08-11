# User Guide Maintenance

## Source and deliverable

`docs/user-guide/user-guide.html` is the sole source and deliverable for the public user guide. Keep its CSS and vanilla JavaScript inline. The only supported local asset is the necessary SCANOSS logo under `docs/user-guide/assets/`. Do not restore DOCX/PDF authoring, generated review images, package manifests, `node_modules`, or vendored document engines.

## Public-safe content

Keep the guide public, product-focused, and evidence-based. Use only claims supported by public repository documentation. Describe analysis as rules-based, context-aware source-code analysis without naming scanner implementation tools. Do not include internal workflows, sales material, customers, partners, company-specific examples, or invented screenshots. Use CBOM consistently for Cryptography Bill of Materials.

## User-facing updates

When a user-facing command, flag, output, supported workflow, deployment behavior, dependency-scanning capability, or limitation changes, update `user-guide.html` in the same PR. Update the root `CHANGELOG.md` under `[Unreleased]` when the change is user-facing.

## Verification

Run from the repository root:

```sh
python3 - <<'PY'
from html.parser import HTMLParser
from pathlib import Path
class Check(HTMLParser):
    pass
Check().feed(Path('docs/user-guide/user-guide.html').read_text())
print('HTML parsed')
PY

if grep -nE 'Semgrep|OpenGrep|SharePoint|customer|partner|sales asset|PURL|API capability|—|–' docs/user-guide/user-guide.html; then
  echo 'Public-guide policy scan failed' >&2
  exit 1
fi
git diff --check
```

For a browser-like check without project dependencies:

```sh
python3 -m http.server 8765 --directory docs/user-guide
# Open http://127.0.0.1:8765/user-guide.html in a browser, then stop the server.
```

Check navigation, search, code copy buttons, language tabs, finding explorer, pipeline stepper, responsive menu, keyboard focus, and reduced-motion behavior.
