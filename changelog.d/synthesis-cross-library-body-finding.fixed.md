- A library's public API now keeps its rule's crypto entry point when its body
  only calls another library's crypto. Re-mine the affected libraries to pick up
  the new entry points.
