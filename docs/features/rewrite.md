---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# rewrite

Replaces the matched command words with yours, keeps the arguments, runs the result. Use it when the agent's command is *fixable* — blocking wastes a turn, rewriting doesn't. The rewritten command is re-gated, so a rewrite can't smuggle past a ban.

## Config

```toml
[[bash]]
match = "grep*"
action = "rewrite"
rewrite = "rg"
hint = "grep is banned here; the command was rewritten to ripgrep."
```

## What happens

```
grep TODO src/                → runs `rg TODO src/`; agent is told about the rewrite
grep -r TODO | head           → rewrite applies inside the pipeline too
```

Careful: the args are kept as-is. `grep -r` becomes `rg -r` — and `-r` means `--replace` in ripgrep. If flags don't translate, prefer a `deny` with a teaching reason (see the [search-discipline recipe](../use-cases/search-discipline.md)).

Context-aware rewrites (`mv`→`git mv`, `cd pkg && bun run x`→`bun --cwd pkg run x`, bin-path stripping) are [modules](modules.md), not pattern rules — they check real state before rewriting.
