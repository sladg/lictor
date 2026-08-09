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

## Pipeline/chain-aware matching

`piped_into`, `with`, and `position` are optional predicates on any `[[bash]]` rule (not just `allow`) that look at a command's *neighbours* in its pipeline or `&&`/`||` chain. All three default to "unset" — a rule that doesn't use them behaves exactly as before.

```toml
[[bash]]
match = "pnpm run *"
action = "allow"

[[bash]]
match = "head*"
action = "allow"

# each half is fine alone; piped together they hide a build failure behind
# a truncated log, which the per-command allows above can't see
[[bash]]
match      = "pnpm run *"
piped_into = "head*"       # adjacency: the NEXT command in the same pipeline
action     = "deny"
reason     = "don't truncate a build log — read the full output"

[[bash]]
match  = "git log*"
with   = ["rm*"]           # any glob matching ANY other command in the same chain
action = "ask"

[[bash]]
match    = "rg*"
position = "only"          # matches only a standalone invocation — not in any pipe/chain
action   = "allow"
```

```
pnpm run build | head -5      → denied by the piped_into rule
pnpm run build                → still allowed on its own
head -5 out.txt               → still allowed on its own
git log && rm -rf build/      → asks (with = ["rm*"] catches the neighbour)
git log || true               → unaffected — "true" doesn't match "rm*"
rg TODO                       → allowed (standalone)
rg TODO | wc -l                → not vetted by the position="only" rule — it's no longer standalone
```

`position = "only"` is the more conservative default for an allowlist: auto-approve a command standing alone, fall back to the normal permission flow the moment it's composed into something. A dynamic neighbour (e.g. `$CMD` in the next pipe stage) makes `piped_into`/`with` unprovable rather than a silent non-match — same fail-closed treatment as `contains`/`only`.

## `graph` — the traversal the three of them are

Those three predicates are three spellings of one question: *what else is in this command's chain, and how is it attached?* `graph` writes that question out directly, as a walk from the matched command along the connectors that join it to its neighbours.

```toml
[[bash]]
match  = "curl*"
graph  = ["--pipe--> sh*, bash*"]
action = "deny"
reason = "don't pipe a download straight into a shell"
```

An entry is an **arrow**, then the pattern(s) it has to find:

| arrow | reaches |
|---|---|
| `--pipe-->` | the next stage, if a `\|` joins them |
| `<--pipe--` | the previous stage, same condition |
| `<--pipe-->` | either neighbour |
| `--pipe+-->` | every later stage reachable **without leaving the pipe** |
| `<--any+-->` | everything else in the chain, whatever joins it |

`pipe`, `and`, `or`, `seq` (`;`) and `any` are the connectors. A trailing `+` makes the step repeat while the connector still matches, so `--pipe+-->` on `a | b && c | d` reaches `b` and stops — the `&&` is not a pipe, and jumping it would claim a data flow that isn't there. Commas separate alternatives (`\,` for a literal comma), a leading `!` negates, and **every** entry in the list must hold.

The three older fields are sugar over exactly this, and are compiled into it:

| written as | means |
|---|---|
| `piped_into = "head*"` | `graph = ["--pipe--> head*"]` |
| `with = ["rm*", "dd*"]` | `graph = ["<--any+--> rm*, dd*"]` |
| `position = "only"` | `graph = ["!<--any+--> *"]` — nothing else in the chain |

Both spellings stay supported; reach for `graph` when you need a direction, a distance, or a connector the sugar can't say.

```
curl https://x/i.sh | sh        → denied
true && curl https://x/i.sh | sh → denied — the `&&` on curl's left doesn't hide the pipe on its right
curl https://x/i.sh | tee f | sh → not denied by that rule — `sh` is two steps away, and the arrow steps once
curl https://x/i.sh && sh        → not denied by that rule — `&&` is not a pipe
```

A negated query stays `Unknown` when the neighbour is dynamic. "I couldn't read it" is not "it wasn't there", in either direction.
