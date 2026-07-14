---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# TypeScript: lint, typecheck, and no suppressions

Three habits agents fall into on TS codebases: silencing the linter instead of fixing the finding, casting around type errors, and running `npx tsc` instead of the project's own scripts. All three are one edit/bash rule each.

## Policy

```toml
# suppressing a finding is not fixing it
[[edit]]
paths = ["**/*.ts", "**/*.tsx"]
pattern = "eslint-disable|@ts-ignore|@ts-expect-error|@ts-nocheck"
action = "deny"
hint = "Fix the lint/type error instead of suppressing it. If the suppression is genuinely warranted, ask the user."

# type assertions mask real mismatches
[[edit]]
paths = ["**/*.ts", "**/*.tsx"]
pattern = "as (any|never|unknown)"
action = "deny"
hint = "No type assertions — fix the type design instead."

# deps go through the package manager, not hand-edited into package.json
[[edit]]
paths = ["**/package.json"]
pattern = '"[^"]+"\s*:\s*"(\^|~|>=?|<=?|\d|\*|npm:|latest)'
action = "deny"
hint = "Don't hand-edit deps — use `bun add <pkg>` / `bun remove <pkg>`."

# the project defines its own scripts — don't bypass their flags/config
[[bash]]
match = "npx tsc*"
action = "deny"
reason = "Use the project script: bun run typecheck."

[[bash]]
match = "bunx tsc*"
action = "deny"
reason = "Use the project script: bun run typecheck."

# the dev loop itself is auto-approved and its output truncated
[[bash]]
match = "bun run*"
action = "allow"

[[minify]]
match = "eslint*"
wrap = "tokf run --"    # or `max_lines = 80` for the built-in truncator
allow = true            # auto-approve the wrapped command too

[[minify]]
match = "tsc*"
wrap = "tokf run --"
allow = true

[[minify]]
match = "vitest*"
max_lines = 80
preserve = ["(?i)error", "(?i)fail"]
```

## How it plays out

```
Edit src/api.ts  (adds `// eslint-disable-next-line`)   → deny: fix the lint error instead…
Edit src/api.ts  (adds `res as any`)                    → deny: no type assertions…
Edit package.json (adds `"zod": "^3.23.0"`)             → deny: use `bun add zod`
npx tsc --noEmit                                        → deny: use bun run typecheck
bun run lint                                            → auto-approved
eslint src/                                             → rewritten to `tokf run -- eslint src/`, auto-approved, output shrunk
```

The `pattern` regex runs over the **written content** of every `Edit`/`Write`/`MultiEdit`/`NotebookEdit` call — a suppression comment never reaches the file, and the deny `hint` tells the agent what to do instead, so it corrects in one turn instead of retrying blind.

## Variations

- Soften suppressions to `action = "ask"` if you occasionally approve one.
- Protect tsdoc comments from "cleanup" with `removed_pattern` — see [protect-docs-and-tests.md](protect-docs-and-tests.md).
- Monorepos: the `pm-cwd` module rewrites `cd pkg && bun run lint` to `bun --cwd pkg run lint`; add `match = "bun --cwd * run*"` allow rules so the rewritten form is auto-approved too.
