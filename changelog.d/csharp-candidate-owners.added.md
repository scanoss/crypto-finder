- Graph fragments move to `graph-fragment-1.40`: a C# call into a dependency
  carries `external_calls[].candidate_owners`, the types its owner can be under
  the file's `using` directives (the caller's own namespace first). The stitch
  keeps the one owner a dependency declares, so a .NET application's call into
  a NuGet package is no longer always reported unreachable.
