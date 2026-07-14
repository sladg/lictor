---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# log

Audit-only: records the match in the audit log, decides nothing — the command runs (or prompts) exactly as it would without the rule. Use it when you want visibility before opinion: watch what the agent actually does with a tool for a week, then write the real rule.

## Config

```toml
[settings]
log_file = "~/.local/state/lictor/audit.jsonl"   # required — no log_file, no entries

[[bash]]
match = "gh *"
action = "log"
```

## What happens

```
gh pr list                    → runs as normal; a JSONL entry lands in the audit log
gh pr merge 42                → same — log grants nothing and blocks nothing
```

`lictor gain` summarizes the log: decisions, rule-log matches, minify/spill bytes saved.
