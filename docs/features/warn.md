---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# warn

No decision — the command runs as it would anyway, but your `hint` is attached to the agent's context. Use it to steer habits without blocking: strong enough that the agent adjusts, soft enough that nothing breaks when it doesn't.

## Config

```toml
[[bash]]
match = "curl*"
action = "warn"
hint = "Prefer the internal fetch proxy for web pages."

[[edit]]
paths = ["**/*.ts", "**/*.tsx"]
removed_pattern = '(?s)/\*\*.*?\*/'
action = "warn"
hint = "A doc-comment was removed by this edit — keep it unless the user asked."
```

## What happens

```
curl https://example.com      → runs; agent's context gets: "Prefer the internal fetch proxy…"
Edit deleting a /** */ block  → edit lands; hint lands with it — agent restores the comment next turn
```

A repeated warn can go quiet after N deliveries — see [retries](retries.md).
