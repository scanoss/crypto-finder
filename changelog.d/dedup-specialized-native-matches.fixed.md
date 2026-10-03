- A call that a conditioned rule already matched is no longer reported twice.
  When the scanner reports a rule and the resolved value specializes that
  same rule at the same location, the scanner's finding is kept and the
  specialized copy is dropped, so findings such as hash algorithms in Java and
  Python no longer appear in duplicate with different finding IDs.
