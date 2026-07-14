---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# deny

Blocks a matching command and hands your `reason` to the agent verbatim. Use it for hard bans — the reason is what makes the agent stop trying variants and do the right thing instead.

## Config

```toml
[[bash]]
match = "git commit*"
action = "deny"
reason = "Commits are manual — propose a commit message and wait for the user."

[[bash]]
match = "git add*"
action = "deny"
reason = "Staging is manual — the user stages and commits."

[[bash]]
match = "git push"
contains = ["--force", "-f"]   # flag-level ban; plain `git push` unaffected
action = "deny"
reason = "Force pushes are banned."
```

## What happens

Simple cases:

```
git commit -m wip             → blocked; agent reads: "Commits are manual — propose a commit message…"
git push --force              → blocked; git push → untouched
/usr/bin/git commit           → blocked (path-qualified git == git)
git -C /elsewhere commit      → blocked (global flags unwrapped)
```

The ban is found wherever the command hides — chains, pipes, substitution, loop and conditional bodies, `find -exec`:

```
echo ok && git commit -m x                → blocked (chain member gated individually)
echo $(git commit -m x)                   → blocked (inside command substitution)
bash -c "git commit"                      → blocked (payload parsed)
eval 'git add -A'                         → blocked
while true; do git add .; done            → blocked (loop body decomposed)
if [ -f x ]; then git stash; fi           → blocked (conditional body decomposed)
find . -name "*.rs" -exec git add {} \;   → blocked (-exec payload gated)
```

What can't be proven doesn't slip through — it escalates:

```
CMD=git; $CMD stash list      → prompt: "cannot statically verify `<dynamic> stash list` against rule `git stash*`"
git $ACTION                   → prompt (dynamic arg defeats the ban check, fail closed)
```

Deny is the strongest action: it wins over allow/ask/warn from any other matching rule, in any config file.
