# Domain Docs

Before exploring, read the root `CONTEXT.md` and relevant ADRs under `docs/adr/`.

This repository uses a single-context layout:

```text
/
|-- CONTEXT.md
`-- docs/adr/
```

If these files do not exist, proceed silently. Domain-modeling workflows create them
lazily when terminology or architectural decisions are resolved.

Use vocabulary defined in `CONTEXT.md`. Surface any conflict with an existing ADR
rather than silently overriding it.
