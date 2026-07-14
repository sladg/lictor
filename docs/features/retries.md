---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Retries

`retry_count` + `retry_window` (seconds) on a `[[bash]]`/`[[edit]]` rule — both required. Two uses: a deny that's a speed bump instead of a wall, and a warn that stops nagging once the agent has seen it. Counters are per rule per session and expire on their own.

## Config

```toml
# deny-then-allow: first attempt bounces with the hint, the resubmit goes through
[[bash]]
match = "git checkout -- *"
action = "deny"
reason = "This discards local changes. Resubmit if that is really what you want."
retry_count = 1
retry_window = 30

# hint quieting: deliver the warn twice, then shut up
[[edit]]
paths = ["**/*.ts"]
removed_pattern = '(?s)/\*\*.*?\*/'
action = "warn"
hint = "A doc-comment was removed by this edit."
retry_count = 2
retry_window = 300
```

## What happens

```
git checkout -- src/x.ts       → deny: "This discards local changes. Resubmit if…"
git checkout -- src/x.ts       → runs (identical resubmit within 30s of the deny)
                                  …next session, or after 30s idle: denies again

Edit removing a doc-comment    → hint delivered (1)
Edit removing a doc-comment    → hint delivered (2)
Edit removing a doc-comment    → silent (quieted; counter resets, will fire again later)
```

`lictor check` never touches the counters — every debug run looks like a first attempt.
