- The container images pin pydantic below 2.14, so the bundled semgrep
  1.145.0 starts again. With pydantic 2.14 it failed on startup with an
  `ImportError`.
