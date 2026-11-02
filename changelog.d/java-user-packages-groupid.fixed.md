- A Java dependency that shares the application's Maven groupId, such as an
  in-house library, was treated as application code: its functions the
  application never calls became chain roots, so crypto behind them read
  `reachable` in the callgraph export. Application code is now the packages the
  project's own sources declare, every reactor module included, so such a
  dependency gets its real verdict. A dependency package under an application
  package is a dependency for every ecosystem.
