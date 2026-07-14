---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Edit rules

Gate the file-authoring tools (`Edit`/`Write`/`MultiEdit`/`NotebookEdit`) by path glob plus content regexes — in four directions. Use them for the stuff bash rules can't see: what the agent writes *into* files.

| Field | Fires when… |
|---|---|
| `pattern` | written content **matches** — gate what's added |
| `removed_pattern` | old content matched, new doesn't — gate what's deleted |
| `required_pattern` | written content is **missing** the regex — demand boilerplate |
| `changed_pattern` | a text the regex matched in the old content no longer appears **verbatim** in the new — gate in-place edits |

All specified conditions must hold. Actions are the same as bash rules (`deny`/`ask`/`warn`/`allow`/`log`/`skip`).

`changed_pattern` vs `removed_pattern`: `removed_pattern` asks "does *any* match survive?" — so swapping `toBe("foo")` for `toBe("bar")` never fires (the new text still matches the regex). `changed_pattern` checks **each match individually**: `"foo"` is gone, so it fires. Pure additions keep every old match and stay silent, and `Write` (no prior content) can never fire it.

## Config

```toml
[[edit]]
paths = ["**/*.ts", "**/*.tsx"]
pattern = "as (any|never|unknown)"
action = "deny"
hint = "No type assertions — fix the type design instead."

[[edit]]
paths = ["**/*.test.ts"]
removed_pattern = '(?m)^\s*(it|test|describe)\('
action = "deny"
hint = "Never delete test cases — refactor them, or ask the user per case."

[[edit]]
paths = ["docs/**/*.md"]
required_pattern = '(?m)^updated_at: \d{4}-\d{2}-\d{2}'
action = "deny"
hint = "Bump `updated_at:` in the frontmatter as part of this edit."

# tests are not made to pass blindly: editing an existing expectation denies
# once with a consult instruction; a resubmit after consulting passes
[[edit]]
paths = ["**/*.test.ts", "**/*_test.go", "**/tests/**/*.rs"]
changed_pattern = '"[^"]*"'
action = "deny"
hint = "Test expectation edited — consult the user: did the behaviour change, and is that wanted? If confirmed, resubmit."
retry_count = 1
retry_window = 600
```

## What happens

```
Edit adds `res as any`                     → blocked; hint tells it to fix the type
Edit deletes an it(...) block              → blocked; test survives
Write docs/x.md without updated_at:        → blocked (Write = full content checked)
Edit docs/x.md, body only                  → blocked (Edit = new_strings checked; none carries updated_at)
MultiEdit: body change + updated_at bump   → passes (any pair satisfying the pattern is enough)
Write with no old content                  → removed_pattern never fires (nothing was deleted)
Edit swaps toBe("ok") for toBe("fine")     → blocked once (changed_pattern); resubmit after consulting passes
Edit appends a brand-new it(...) block     → silent (additions keep every old match)
```

Worked examples: [markdown frontmatter](../use-cases/markdown-frontmatter.md), [TypeScript discipline](../use-cases/typescript.md), [protect docs & tests](../use-cases/protect-docs-and-tests.md).
