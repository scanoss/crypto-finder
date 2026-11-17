- crypto-finder shows a notice the SCANOSS API sends in the `X-SCANOSS-Notice` response
  header, such as the date a version stops working, without failing the request. The first
  notice of a run is shown once, however many API requests carry it: in a box on a terminal,
  as one `NOTICE: <text>` line on stderr otherwise, and not at all while stderr carries JSON
  (`--error-format json` or `--progress`).
