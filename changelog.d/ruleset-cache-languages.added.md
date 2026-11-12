- The cache metadata (`.cache-meta.json`) of a downloaded or imported ruleset
  carries `languages`: the languages its rules cover (each rule's
  `languages` lowercased and trimmed, `generic` for a rule that names none,
  deduplicated and sorted), so integrations can read them without the rule
  files a leased cache keeps encrypted. `crypto-finder rules status` shows
  them in a `LANGUAGES` column.
