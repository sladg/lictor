---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# skip

True no-op: no decision, no hint, no log entry. `skip` overrides any `ask`/`warn`/`log`/`allow` another rule gives the **same** match — so a narrow rule can carve an exception out of a broad catalog without overriding the whole thing. An explicit `deny` elsewhere still wins. With lictor silent, Claude Code's own permission rules decide.

## Config

```toml
[settings]
catalogs = ["recommended"]       # mutating catalog: rm → ask

[[bash]]
match = "rm .claude/scratch/*"   # our own scratch dir specifically
action = "skip"
```

## What happens

```
rm src/main.rs                → prompt (mutating catalog's ask, untouched)
rm .claude/scratch/tmp.json   → lictor steps aside; Claude Code's own rules decide
rm -rf /                      → blocked (destructive catalog's deny beats skip)
```

Why not `allow`? An `allow` auto-approves — a stronger statement than you may want. `skip` just removes lictor's opinion and hands the call back to the harness.
