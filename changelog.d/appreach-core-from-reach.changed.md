- `pkg/appreach` now runs its stitch core (closure parsing, dependency-graph
  splice, stitch policy, verdicts) from the reach module's `appreach` package.
  Its exported API and every `/reachability/application` response are
  unchanged; `Dependency`, `Limits`, `Pins` and `RunError` are now aliases of
  reach's types.
