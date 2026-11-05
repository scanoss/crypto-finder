- `scan --scan-dependencies`: a Python dependency the project declares now gets its
  `relationship` (`direct`) and `path` in the callgraph export even when it requires nothing
  itself. Without a Python lockfile, the direct dependencies are the installed distributions
  the target's `requirements.txt` (and the files it includes through `-r`) and
  `pyproject.toml` (`[project]` `dependencies`, `[tool.poetry.dependencies]`) declare. A
  distribution installed next to them that the project does not declare, such as `pip` or a
  tool, is no longer labeled `direct` and has no path unless a declared one requires it.
  A target that declares no requirements takes every installed distribution no other one
  requires as direct, including one that requires nothing; before, such a distribution got
  no relationship, path or depth.
