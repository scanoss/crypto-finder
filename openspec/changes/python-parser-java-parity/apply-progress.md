# Apply progress: python-parser-java-parity

Batch: BATCH 2 (resume after process restart; no prior apply-progress artifact existed).

## TDD Cycle Evidence (this batch)

| Task | RED | GREEN | REFACTOR |
|---|---|---|---|
| 5.1 | Confirmed pre-existing on resume: all 5 `TestPythonParser_Import_*` present, previously RED against the interrupted batch's uncommitted GREEN work | Confirmed green (`go test ./internal/callgraph/ -run 'TestPythonParser_Import_' -count=1 -v`) | 5.3 confirmed `python_parser_from_import_test.go` unchanged and passing |
| 6.1 | `_SiblingResolution` RED confirmed (`pkg.(Cipher).<init>` vs wanted `pkg.mod.(Cipher).<init>`); `_NoInferredType` green-by-construction (no rewrite exists pre-implementation) | `applyPythonReExports`/`collectPythonReExports` implemented; both tests green | N/A — no separate refactor task in this phase |

## Completed tasks (cumulative, all phases)

- Phase 0 (T0): 0.1, 0.2 — grammar-facts pin (commit `a8d5365`)
- Phase 1 (T1): 1.1-1.4 — parameter receivers (commit `22096df`)
- Phase 2 (T2): 2.1-2.3 — non-assignment binders (commit `5723424`)
- Phase 3 (T3): 3.1-3.4 — self/cls attribute provenance (commit `d2d70b9`)
- Phase 4 (T4): 4.1-4.5 — synthetic `<module>`/`<clinit>` entry points, incl. out-of-scope `ast_anchor.go` fix reported and applied (commit `6e0a9d4`)
- Phase 5 (T5): 5.1-5.3 — nested/relative import resolution (commit `ffb9df2`, this batch)
- Phase 6 (T6): 6.1-6.3 — `__init__.py` re-export stitching (commit `292b494`, this batch)

## Remaining tasks

- [ ] Phase 7 (T7): 7.1-7.3 — performance guard (fixture generator + benchmark)
- [ ] Phase 8: 8.1-8.7 — regression guard, record real pass counts
- [ ] Phase 9: 9.1-9.7 — final gates (race suite, lint, coverage, whitespace, zero-diff, CHANGELOG, user-guide)

## Last commit SHA

`292b494` — feat(python): stitch __init__.py re-exports to declaring module (T6)

## Notes / deviations carried forward

- T6 fixture deviates from the task's literal "pkg/mod.py" flat-file wording: this codebase keys `FunctionID.Package` at directory granularity (`packagePath` param passed to `parseFunctionDef`/`processClass`, never a per-file stem), so a flat sibling file would already share the same FQN as the unresolved import and could never exercise the stitching gate. Used a `pkg/mod/` subdirectory (real `SubPackagePath` recursion) instead — same re-export semantics, an actually distinct package boundary. Full detail in tasks.md 6.1.
