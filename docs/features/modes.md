---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Modes

A `[modes.<mode>]` block is one more config layer, applied only when the session's `permission_mode` matches — `default`, `plan`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`. Use it to run a relaxed policy while you're watching and a strict one when nothing is: same command, different rules per mode.

Settings override, rule lists append, most-restrictive still wins across base + overlay.

## Config

```toml
[[bash]]
match = "curl*"
action = "allow"                  # base: fine while I'm watching

[[modes.auto.bash]]
match = "curl*"
action = "deny"                   # unattended: no network
reason = "auto mode: no unattended network access"

[modes.bypassPermissions.settings]
jail = "deny"                     # nothing's watching → hard-confine to the repo
```

## What happens

```
(default mode)  curl https://x     → runs
(auto mode)     curl https://x     → blocked: "auto mode: no unattended network access"
(bypass mode)   cat /etc/hosts     → blocked (jail escalated from ask to deny)
```

Built in, no config: in `auto` mode every `ask` lictor would emit becomes `deny` — nobody's there to answer a dialog, and a deny gives the agent a reason instead of a stalled turn.

Dry-run a mode: `lictor check --mode auto -- 'curl https://x'`.
