---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Auto-approve everything read-only

Most permission prompts are for commands that can't hurt you: `ls`, `git diff`, `docker ps`, `kubectl get`. One line auto-approves ~150 of them; anything that mutates, installs, or hits the network still asks.

## Policy

```toml
[settings]
catalogs = ["read-only"]     # the 16 *-read/query catalogs → allow, nothing else
```

Or take the batteries-included variant — same read-only allows, plus `net-egress`/`mutating`/`pkg-install` → ask and `secrets-read`/`destructive`/`gtfobins`/`obfuscation` → deny:

```toml
[settings]
catalogs = ["recommended"]
```

The full command list per catalog lives in [`src/catalogs/builtin.toml`](../../src/catalogs/builtin.toml); how catalogs work is in [features/catalogs](../features/catalogs.md).

## What "read-only" survives

Auto-approval is conservative — the allow only holds when lictor can prove it:

- **Every command in a chain must be vetted.** `git status && rm -rf x` is not covered by the `git status` allow.
- **An output redirect disqualifies the command.** `git diff > patch.txt` writes a file, so it's no longer read-only and falls back to the normal prompt. `/dev/null` and `2>&1` stay harmless.
- **Wrappers count separately.** `sudo git status` is not `git status`.
- **Overlaps resolve toward the dangerous case.** `cat` is allowed (`text-read`) but `cat .env` is denied (`secrets-read`) — most-restrictive wins, no ordering rules.

## Extending it

Your own read-only tools get plain allow rules, or a custom catalog when there are several:

```toml
[[bash]]
match = "lictor check*"
action = "allow"

[catalog.my-readers]
match = ["moon query*", "moon project*", "proto plugin search *"]
action = "allow"
```

Read-heavy CLIs with noisy output get a `[[minify]]` wrap; `allow = true` auto-approves the wrapped form in the same block:

```toml
[[minify]]
match = "git log*"
wrap = "rtk"       # git log → rtk git log
allow = true
```

Trim a built-in instead of abandoning it:

```toml
[catalog.git-read]
add    = ["git worktree list"]
remove = ["git grep"]
```

## Unattended modes

The starter policy remaps every `ask` to `deny` in `auto` mode (nobody's there to answer), so a read-only allowlist is what keeps an unattended agent moving. Pair it with a jail so "read-only" also means "inside the repo":

```toml
[modes.auto.remap]
ask = "deny"

[modes.auto.settings]
jail = "deny"
```
