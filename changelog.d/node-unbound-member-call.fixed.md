- JavaScript and TypeScript call graph: a member call on a chained or
  unresolved receiver, such as `crypto.createHash('md5').update(x).digest('hex')`
  or `param.digest()`, is no longer bound to a module function of the same name.
  That false edge made unrelated functions appear as callers of the function.
