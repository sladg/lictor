---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Require frontmatter metadata in Markdown files

Every Markdown file the agent writes must carry `created_at:` / `updated_at:` frontmatter, and every later edit must bump `updated_at:`. Agents skip metadata unless forced; `required_pattern` forces it.

## Policy

```toml
[[edit]]
paths = ["docs/**/*.md", "notes/**/*.md"]
required_pattern = '(?m)^created_at: \d{4}-\d{2}-\d{2}'
action = "deny"
hint = "Markdown docs carry frontmatter — start the file with `---`, `created_at: YYYY-MM-DD`, `updated_at: YYYY-MM-DD`, `---`."

[[edit]]
paths = ["docs/**/*.md", "notes/**/*.md"]
required_pattern = '(?m)^updated_at: \d{4}-\d{2}-\d{2}'
action = "deny"
hint = "Bump `updated_at:` in the frontmatter as part of this edit."
```

## How it plays out

`required_pattern` fires when the **written content is missing** the regex — the inverse of `pattern`, which fires when content matches.

- **Write** sends the full file, so the check is against the whole document: a new `docs/plan.md` without frontmatter is denied, the hint lands in the agent's context, and the retry arrives with the `---` block on top.
- **Edit / MultiEdit** are checked against the edit's `new_string`s — the rule is satisfied when **any** edit pair contains the pattern. A body-only edit is denied, so the agent learns to attach one extra edit pair that rewrites the `updated_at:` line. That's the enforcement: you can't touch the file without touching the timestamp.

```
Write docs/plan.md ("# Plan\n...")          → deny: start the file with `---`, created_at…
Write docs/plan.md ("---\ncreated_at: …")   → passes
Edit  docs/plan.md (body change only)       → deny: bump `updated_at:` as part of this edit
MultiEdit (body change + updated_at bump)   → passes
```

## Variations

Prefer a nudge over a hard block — `warn` attaches the hint without denying, and `retry_count`/`retry_window` stop it from nagging forever:

```toml
[[edit]]
paths = ["docs/**/*.md"]
required_pattern = '(?m)^updated_at: \d{4}-\d{2}-\d{2}'
action = "warn"
hint = "Consider bumping `updated_at:` in the frontmatter."
retry_count = 2      # after 2 hints in the window, stop repeating it
retry_window = 300
```

Scope the paths deliberately: `**/*.md` would also catch `README.md` and generated changelogs. List the directories where the convention actually applies.
