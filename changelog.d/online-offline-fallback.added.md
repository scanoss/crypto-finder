- `scan --scan-dependencies` online now answers locally the dependencies the
  SCANOSS API holds no reachability data for (`no_reachability_data`): it mines
  them with the `--offline` path (and the dependencies that lead to them in the
  resolved tree, so routes through those are in the stitch) and serves their
  findings and verdicts as `--offline` would. Dependencies without data for
  another reason (`unpinned`, `other_version_requested`, `under_other_version`)
  are not mined. `--no-offline-fallback` turns it off and keeps the API's answer
  as it is. The completed `dependencies` progress event adds
  `deps_answered_online`, `deps_answered_offline` and
  `deps_answered_offline_list` (`purl`, `version`); a dependency the fallback
  could not answer either stays in `deps_skipped_list` with reason
  `no_reachability_data` and a new `offline_fallback` field saying why. A failed
  or timed-out fallback never fails the scan. `--offline-cache-dir`,
  `--offline-memory-mb` and `--offline-python-packages` apply to the fallback.
