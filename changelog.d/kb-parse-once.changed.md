- Scans build call graphs faster: each language's built-in knowledge base of
  crypto library types is now parsed once per run instead of once per call
  graph, and a dependency scan builds a call graph for every dependency it
  analyzes.
