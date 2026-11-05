- `scan --scan-dependencies` accepts `--install-dependencies` to install Node and Python
  dependencies that are not installed yet, instead of finding none. For Node, a lockfile
  whose production packages are missing from `node_modules` gets
  `npm ci --ignore-scripts --no-audit --no-fund` (with `--omit=dev` unless
  `--include-dev-dependencies` is set) when there is no `node_modules`, and
  `npm install --no-save --ignore-scripts --no-audit --no-fund` when there is one, which
  keeps the installed packages the lockfile lists instead of deleting the directory. For Python without an activated or project-local
  virtual environment, the dependencies declared in `requirements.txt`, in the
  `[project]` table of `pyproject.toml` (installed without building the project), or
  through `pyproject.toml`/`setup.py`/`setup.cfg` (a project that cannot be built
  yields no Python dependencies with a warning), are installed with the ambient pip (22.3 or
  later) into a virtual environment outside the scanned tree, reused by later scans unless
  a local project directory had to be built; if
  `requirements.txt` fails as a whole, each requirement is retried on its own. With the
  flag, the ambient interpreter's own packages are never reported as dependencies. The
  flag needs network access, is off by default, and building a Python source distribution
  runs its build backend.
