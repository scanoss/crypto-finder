- Callgraph export schema `6.18`, the new `--export-callgraph` default: every chain frame carries
  an `excerpt` of up to seven source lines centered on the call that leads to the next frame (or on
  the crypto call in the last frame), so a reviewer can check a route hop by hop, dependency frames
  included, without the source tree. Only files under the scanned target or a dependency source
  directory the scan resolved are read. A frame without an excerpt carries `excerpt_unavailable`
  (`no_source`, `unreadable`, `out_of_range`); exports stitched from graph fragments write
  `no_source` on every frame. A chain's first frame carries `entry_rule`, the ID of the entry-point
  catalog entry that made it an entry point (as `java/spring:decorator:RequestMapping`), and
  `entry_call.call_site_column` gives the column of each call. Published as
  `schemas/callgraph-schema-6.18.json`; `pkg/graphfrag` exposes `ExportExcerpt`.
