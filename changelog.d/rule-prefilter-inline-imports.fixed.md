- `scan --rule-prefilter imports` no longer skips rules for libraries a file
  imports in a position it did not read: a Java import after another import or a
  block comment on the same line, a Rust `use` after an attribute such as
  `#[cfg(feature = "gcm")]` or inside `mod m { ... }`, a Python `import` or
  `from ... import` after `;`, a C `#include` after a block comment, and any
  first-line import in a file that starts with a UTF-8 byte order mark. A
  `metadata.imports` entry such as `javax.crypto.Cipher` is now satisfied by
  `import javax.crypto.*;`.
- `scan --rule-prefilter imports` no longer skips JavaScript and TypeScript rules
  guarded by a pattern such as `{..., $F, ...} = require("jsonwebtoken")`.
  OpenGrep reads that pattern as its leading brace alone, so such a rule also
  reports in files that never load the module (for example a `jsonwebtoken`
  algorithm rule on a `fast-jwt` file), and the prefilter now keeps it there.
