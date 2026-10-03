- A call that a conditioned rule already matched is no longer reported twice.
  When the scanner reports a rule and the resolved value specializes that
  same rule at the same location, the per-value asset is kept and the
  scanner's copy is dropped, so findings such as hash algorithms in Java and
  Python no longer appear in duplicate. The per-value asset survives because
  its call chains and verdict come from the routes that carry its own value,
  where a scanner pattern covering several values mixes their routes. The
  finding IDs of those duplicates change once. A scanner match whose value is
  not specialized is kept.
