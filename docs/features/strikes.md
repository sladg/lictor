---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Strikes

Rogue-actor brake: N consecutive lictor denies with no command executed in between pauses shell autonomy — every Bash call asks until one actually runs. Use it as the backstop for an agent that's stuck fighting the policy or being steered somewhere it shouldn't go; it puts you back in the loop automatically.

## Config

```toml
[settings]
strikes = 5
```

## What happens

```
deny #1 … deny #5 (nothing executed in between)
→ lictor: 3+ consecutive denied commands — shell autonomy paused; a user-approved command lifts it
git status                    → prompt (yes, even though it's allowed)
  …you approve, it executes   → counter resets, autonomy restored
```

Any successfully executed command resets the counter — normal work never trips it; only a deny streak does.
