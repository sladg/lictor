---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Git write-ban: the agent reads history, never rewrites it

The agent can inspect anything — `git log`, `git diff`, `git blame` — but every state-changing git operation is denied with a reason it can act on. Commits, staging, stashes, resets, checkouts, and pushes stay manual.

## Policy

```toml
[settings]
catalogs = ["recommended"]   # includes git-read → allow (log/diff/show/blame/status/…)

[[bash]]
match = "git commit*"
action = "deny"
reason = "Commits are manual — propose a commit message and wait for the user."

[[bash]]
match = "git add*"
action = "deny"
reason = "Staging is manual — the user stages and commits."

[[bash]]
match = "git stash*"
action = "deny"
reason = "Never stash — ask the user how to handle dirty state."

[[bash]]
match = "git reset*"
action = "deny"
reason = "Destructive history operation — ask the user."

[[bash]]
match = "git checkout*"
action = "deny"
reason = "Working-tree switch is manual — ask the user."

[[bash]]
match = "git rebase*"
action = "deny"
reason = "History rewrite is manual — ask the user."

[[bash]]
match = "git push*"
action = "deny"
reason = "Pushes are manual — ask the user."
```

## Why the ban actually holds

Pattern-based permission systems check the top-level command; lictor gates **every command in the chain** after unwrapping, so the usual leaks are closed:

```
echo ok && git commit -m wip          → deny (ban found inside the chain)
bash -c "git commit -m wip"           → deny (payload parsed)
eval 'git add -A'                     → deny
/usr/bin/git commit                   → deny (path-qualified git == git)
git -C /elsewhere commit              → deny (global flags unwrapped)
git $ACTION                           → ask  (dynamic word — fail closed, not allowed)
```

The `reason` is handed back verbatim, so instead of retrying variants the agent proposes a commit message and stops — which is the behavior you wanted.

## Variations

**Softer:** `action = "ask"` on `git push*` if you want a prompt rather than a ban for pushes specifically.

**Deny once, then allow the retry** — for rules that are a speed bump, not a wall. The first attempt is denied with the hint; an identical resubmission inside the window goes through:

```toml
[[bash]]
match = "git checkout -- *"
action = "deny"
reason = "This discards local changes. Resubmit if that is really what you want."
retry_count = 1
retry_window = 30
```

**Branch-scoped force-push ban** while allowing plain pushes:

```toml
[[bash]]
match = "git push*"
action = "ask"

[[bash]]
match = "git push"
contains = ["--force", "-f", "--force-with-lease"]
action = "deny"
reason = "Force pushes are banned."
```
