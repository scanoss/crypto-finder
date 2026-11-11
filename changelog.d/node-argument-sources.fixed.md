- JavaScript and TypeScript scans now resolve an algorithm passed as a
  variable: `crypto.createHash(alg)` is reported with the value when `alg` is a
  string literal bound by a `const`, a never reassigned `let`, or a `var`
  declared earlier in the same function; a module constant of the same file;
  an `export const` of another project module, imported by name (also with
  `as`), as a namespace (`import * as cfg`; `cfg.ALG`) or through `require`
  (`const { ALG } = require("./cfg")`, `cfg.ALG`, with `module.exports = {..}`
  or `exports.ALG = ..` in the declaring module); a member of a TypeScript
  `enum` initialized with a string, or of a `const` bound to
  `Object.freeze({..})` or to a plain object literal; and a plain parameter of
  a function whose callers, in any project module, all pass one of these. A
  value is dropped when the binding is reassigned, shadowed or exported with
  `let`; when the parameter has a default value, is destructured or a rest
  parameter, is reassigned or aliased through `arguments`; when the object is
  mutated, passed elsewhere, or holds a spread, computed key, method or
  accessor; when the enum member is numeric; for a package import, a default
  import, `import()`, a re-export from another module or a template literal
  with a substitution; and when a caller passes the argument after a spread.
  An exported value is also dropped when any project module may write it at
  runtime: `config.hashAlgorithm = process.env.HASH_ALG` through a `require`,
  a named, namespace or default import, or `require("./config")` itself; a
  computed-key write, `delete`, `+=`, `Object.assign` or
  `Object.defineProperty`; or the imported object passed, aliased, returned or
  re-exported. A member of an `Object.freeze({..})` object stays resolved,
  since no write can change it.
  Call-graph exports stamp `graph_algo_version` `graph-algo-23`; cached Node
  structural graphs from `graph-algo-22` are rebuilt.
