- A ruleset download answered with HTTP 410 Gone or 426 Upgrade Required
  fails the scan with the new failure code `upgrade_required` and prints
  the server's message as
  `ERROR: <message>`, taken from `error.message` of the API's JSON error body
  or from a plain-text body, without control characters and capped at 10
  lines and 1000 characters. That answer is not retried and never replaced
  by a stale cached ruleset.
- A refused API key (HTTP 401/403) on a ruleset download now reads
  `the SCANOSS API refused the ruleset download (HTTP 403): <server message>`
  instead of the raw response body, and an error from a download that was
  not retried no longer says it failed "after 3 retries".
