---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Search discipline: ripgrep only

`grep -r`, `find -name`, `ack`, `ag` — slower, ignore `.gitignore`, and each needs its own flags. One tool covers content search and file discovery. Deny the legacy tools with a hint that teaches the replacement.

## Policy

```toml
# deny rather than rewrite: a naive `rewrite = "rg"` keeps grep's flags, and
# `grep -r` would become `rg -r` (--replace) — a different command. The deny
# hint makes the agent redo it correctly in one turn.
[[bash]]
match = "grep"
action = "deny"
reason = "Use rg (ripgrep): recursive by default, `rg <pattern> [path]`. Flags differ from grep."

[[bash]]
match = "find*"
action = "deny"
reason = "Use rg: `rg --files --glob \"*.ext\"` for files, `rg <pattern>` for content."

[[bash]]
match = "ack*"
action = "deny"
reason = "Use rg instead."

[[bash]]
match = "ag*"
action = "deny"
reason = "Use rg instead."
```

## How it plays out

The ban holds inside pipes and chains — `cat log.txt | grep ERROR` is denied just like a bare `grep`, and the reason lands in the agent's context:

```
grep -r TODO src/          → deny: use rg (ripgrep)…   → agent runs `rg TODO src/`
find . -name "*.rs"        → deny: use rg --files…     → agent runs `rg --files --glob "*.rs"`
cargo test | grep FAILED   → deny (grep found inside the pipeline)
```

## Variations

**Nudge instead of ban** — the built-in `search-nudge` catalog attaches a "prefer rg" hint to `grep`/`find`/`sed` without blocking or granting anything (it ships in the `read-only` and `recommended` bundles).

**Auto-rewrite** works when your usage is flag-free:

```toml
[[bash]]
match = "grep*"
action = "rewrite"
rewrite = "rg"       # grep TODO src/ → rg TODO src/, then re-gated
```

**Watch for name collisions**: `match = "grep"` (exact word) rather than `grep*`, so a tool like `grepai` isn't swallowed by the ban. Glob patterns match word-wise against the command.
