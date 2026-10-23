- A Go dependency whose findings come from the SCANOSS API keeps them. Since
  0.39.0 every finding of such a dependency was dropped, because the API names
  a Go file under its module root (`golang-jwt/jwt/v5@v5.3.1/ecdsa.go`) and
  `scan --scan-dependencies` did not find that path in the module.
  `github.com/golang-jwt/jwt/v5@v5.3.1` went from 51 findings to none. An API
  answer naming a file outside the module root is now not used, and the
  dependency is scanned locally.
