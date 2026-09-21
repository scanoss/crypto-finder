# Captured native wire contract

These are authentic OpenGrep 1.29.0 captures of the included Python source and
single digest rule. They characterize the legacy built-in scanner transport and
report contract, not runtime coverage of OpenGrep 1.12.1 or Semgrep 1.145.0.

`provenance.json` records original stdout, portable stdout, stderr and capture
record SHA-256 values, actual engine argv, exit status and source/rule hashes.
The original stdout bytes remain in the external capture evidence. Delivered
stdout differs only in `results[].path` and `paths.scanned[]`: the original
source root becomes `@TARGET@`. IDs, fingerprint, metadata, metavariable offsets,
match spans and stderr bytes are unchanged. Tests substitute their target root
only; they do not rewrite IDs or invent native metadata.

The positive source has one declaration, `compute`, and one terminal digest on
line 5, columns 12 through 22, bytes 89 through 99. Its known metadata is
`algorithm` / `SHA-256`; no OID, dependency or selector is supplied by this rule.
The no-match source calls `hexdigest` and genuinely returned no matches.
Telemetry is a separate complete native capture; its prefixed rule ID remains
unchanged. Error/warning/skipped/stderr/empty/malformed/exit2 cases are explicitly
labeled transport perturbations of the authentic positive capture, not native
engine observations.

`TestNativeWireReplayContract` runs in normal and short tests with no installed
scanner, Python, shell launcher, native environment setting or extra Go build.
Its Go child process is executed by the actual built-in Initialize/Scan methods;
both adapters decode and transform the captured wire output normally. This is
not a custom fake Scan implementation, certificate test or sharing feature.

The `xnotice` capture records OpenGrep 1.29 using the exact
`--x-ignore-semgrepignore-files --quiet --jobs 2` profile. Only its two
source-root path fields use `@TARGET@`; its metadata and stderr stay unchanged.
The outcome tests vary only the notice timestamp for the positive control.
Other diagnostic and wire changes are labeled transport perturbations, not
native observations or evidence that a report is safe to reuse.

`telemetry.stderr.txt` and `xnotice.stderr.txt` contain native trailing spaces.
Exact-path `.gitattributes` entries treat only these machine captures as non-text
for Git diff checks. Tests read their original bytes; `provenance.json` pins
their SHA-256 values.
