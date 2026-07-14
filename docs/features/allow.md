---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# allow

Auto-approves a matching command — no permission prompt. Use it for commands you'd approve every time anyway (read-only stuff, your dev loop), so the agent keeps moving and you stop clicking.

## Config

```toml
[[bash]]
match = "git status*"
action = "allow"

[[bash]]
match = "rg*"
action = "allow"

[[bash]]
match = "bun run*"
action = "allow"
```

## What happens

Simple cases:

```
git status                    → runs, no prompt
bun run lint                  → runs, no prompt
sudo git status               → prompt (wrapper variants count separately)
```

Chains, pipes, loops — the allow only holds when **every** command in the structure is vetted:

```
git status | rg modified               → runs, no prompt (both pipe stages vetted)
for d in a b; do git status; done      → runs, no prompt (loop decomposed, body vetted)
git status && rm -rf dist              → prompt (rm isn't vetted — one bad link breaks the chain)
git status && curl https://example.com → prompt (curl asks; chain inherits the strictest member)
```

Redirects break the "read-only" claim, so they break the allow:

```
git status > out.txt          → no opinion — the normal permission flow decides
git status 2>&1               → runs, no prompt (fd dup is harmless)
rg TODO > /dev/null           → runs, no prompt (/dev/null target is harmless)
```

Deny always beats allow — an `allow` in a project config can't unban a user-level `deny`.
