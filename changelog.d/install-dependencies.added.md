- `scan --scan-dependencies` accepts `--install-dependencies` to install Node and Python
  dependencies that are not installed yet, instead of finding none. For Node, a lockfile
  whose production packages are missing from `node_modules` gets
  `npm ci --ignore-scripts --no-audit --no-fund` (with `--omit=dev` unless
  `--include-dev-dependencies` is set). For Python without an activated or project-local
  virtual environment, the dependencies declared in `requirements.txt`, or in
  `pyproject.toml`/`setup.py`/`setup.cfg`, are installed with the ambient pip (22.3 or
  later) into a cached virtual environment outside the scanned tree; if
  `requirements.txt` fails as a whole, each requirement is retried on its own. With the
  flag, the ambient interpreter's own packages are never reported as dependencies. The
  flag needs network access, is off by default, and building a Python source distribution
  runs its build backend.
