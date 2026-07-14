---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Agent rules

`[[agent]]` rules run a regex over subagent traffic (the `Task`/`Agent` tool). `on = "prompt"` gates **before launch** — deny/ask/warn. `on = "output"` matches the **returned result** — hint only (`warn`/`log`), because the work already happened; the hint lands as context next to the result.

## Config

```toml
[[agent]]
pattern = "(?i)comprehensive analysis|deep dive"
on = "output"
action = "warn"
hint = "subagent output smells like filler — ask for specifics"

[[agent]]
pattern = "(?i)delete all|rm -rf"
on = "prompt"
action = "deny"
reason = "destructive subagent prompt"
```

## What happens

```
Task("please delete all failing tests")   → blocked before the subagent spawns
Task("review src/lib.rs")                 → runs
  ↳ returns "A Comprehensive Analysis…"   → hint: "subagent output smells like filler"
```

Per-rule `modes` maps apply here too: `modes = { auto = "deny" }` on a prompt rule hard-stops in unattended runs what merely warns elsewhere.
