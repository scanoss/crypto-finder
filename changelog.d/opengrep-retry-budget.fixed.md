- The timeout retry now has a time budget: all its rounds together take at most twice the scan's
  first pass, and at least 2 minutes, and they stop early enough to leave a tenth of the time
  before `--timeout` (at least 1 minute) for the work after the scan. A retry that runs out of
  budget keeps the findings of the first pass and of any round that finished, and the files it
  did not finish stay in `incompleteFiles`; the scan no longer runs into `--timeout` and fails
  whole. A crate shipping several large generated files, such as `aws-lc-sys`, reran every rule
  on them until the scan timed out and lost all of its findings.
