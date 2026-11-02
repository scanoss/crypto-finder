- The call graph matched the default exclusions (`node_modules`, `venv`,
  `build`, `dist`, `target`, `docs`, `vendor`, ...) against every directory
  above a source file, not only those inside the scanned project or
  dependency. npm dependency sources, all of which sit in `node_modules`, never
  entered the call graph, so every JavaScript dependency finding read
  reachability `not_applicable`; Python packages installed in a virtualenv
  named `venv` were left out the same way; and a project checked out under a
  directory with one of those names (for example `/ci/build/myrepo`) got
  `not_applicable` for its own findings too. The exclusions now apply only
  inside the project or dependency being graphed, so these findings get real
  reachability verdicts.
- JavaScript and TypeScript calls made through an npm package name
  (`require('pkg')`, `import { fn } from 'pkg'`, `import fn from 'pkg'`,
  scoped `@scope/pkg` and subpaths such as `pkg/sub`) now reach the function
  the package's entry module exports, resolved from its package.json
  `exports`, `main` or `index.js`. Crypto in an npm dependency that the
  application calls, directly or through other packages, now reads
  `reachable` with a call chain into the dependency. Calls the KB models under the package name (such as
  `jsonwebtoken.sign`) and Node built-ins keep their current handling.
