# Compare verdict rows ($v, from verdicts.jq) with expected findings ($want)
# and print one PASS or FAIL line per expectation. An expectation names
# module, file and line, the reachability it must read, and optionally the
# source, relationship and dependency path it must carry and a chain: modules
# some sampled call chain must start at, end at and visit in order.
#
# Usage: jq -r -n --slurpfile v verdicts.json --argjson want '[...]' -f check-findings.jq
def visits($w): (reduce .[] as $m (0; if . < ($w | length) and $m == $w[.] then . + 1 else . end)) == ($w | length);
def crosses($w): any(.[]; length > 0 and .[0] == $w[0] and .[-1] == $w[-1] and visits($w));

$want[] as $w
| "\($w.module)/\($w.file):\($w.line)" as $k
| [$v[0][] | select(.module == $w.module and .file == $w.file and .line == $w.line)] as $hits
| if ($hits | length) == 0 then
    "FAIL \($k): no finding at this location"
  else
    $hits[0] as $h
    | [ (if $h.reachability != $w.reachability then "reachability \($h.reachability), want \($w.reachability)" else empty end),
        (if $w.source != null and $h.source != $w.source then "source \($h.source), want \($w.source)" else empty end),
        (if $w.relationship != null and $h.relationship != $w.relationship then "relationship \($h.relationship), want \($w.relationship)" else empty end),
        (if $w.path != null and $h.path != $w.path then "dependency path \($h.path | join(">")), want \($w.path | join(">"))" else empty end),
        (if $w.chain != null and ($h.chains | crosses($w.chain) | not) then "no chain crosses \($w.chain | join(">")); chains: \($h.chains | map(join(">")))" else empty end)
      ] as $errs
    | if ($errs | length) == 0 then
        "PASS \($k): \($h.reachability)"
        + (if $h.relationship then " (\($h.relationship) via \($h.path | join(">")))" else "" end)
        + (if $w.chain != null then ", chain \($w.chain | join(">"))" else "" end)
      else
        "FAIL \($k): \($errs | join("; "))"
      end
  end
