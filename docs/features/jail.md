---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Jail

Confines the agent to the project: literal paths outside the repo (and your allowed roots) get warn/ask/deny. Use it so "the agent works on my repo" actually means the repo — not your dotfiles, not `/etc`.

The project root is the git repo containing cwd (`git rev-parse --show-toplevel`), so the agent moves freely anywhere inside the repo even after `cd`-ing around; outside a repo it falls back to plain cwd. A `cd` earlier in a chain shifts what later relative paths resolve against; a subshell's `cd` (`bash -c`, `eval`, `find -exec`) doesn't leak out; `cd -` or a dynamic target freezes tracking at the last known cwd rather than guessing. Resolution is lexical — `~` expanded, `..` collapsed, no symlink or `$VAR` resolution.

Inside a **linked git worktree** the main checkout is trusted as well. `--show-toplevel` returns the worktree, so on its own it would leave the main checkout reading as "outside the project" — and a shell that `cd`ed into a worktree could then never `cd` back out, including to edit `jail_allow` itself. Note this also trusts sibling worktrees under the same main checkout: they are normally the same user's agent scratch space, and that is a deliberate trade against an unrecoverable lockout.

## Where "this word is a path" comes from

`settings.jail_paths` chooses. Default `heuristic` — unchanged behaviour.

| value | meaning |
|---|---|
| `heuristic` | the shape of the word: a leading `/`, `~`, or `..`. What lictor has always done |
| `graph` | only what a reviewed recipe in `recipes/` says is a path |
| `compare` | run both, **decide with the heuristic**, print where they differ |

**The graph source is not strictly better.** It trades one kind of error for the other:

```
sed -n '/needle/p' README.md    heuristic: flags /needle/p   graph: silent
ssh host cat /etc/hosts         heuristic: flags /etc/hosts  graph: silent
cd /tmp && cat passwd           heuristic: misses it         graph: flags /tmp/passwd
frobnicate /etc/passwd          heuristic: flags it          graph: MISSES it
```

- it removes the false positives issue #4 is about — a sed script and a remote path stop being treated as local files
- it closes a false negative the shape test cannot reach: `cat passwd` after a `cd` names a real file, but the bare word is not path-*shaped*, so the guess never looks at it
- it introduces a new false negative: **a program with no recipe references no paths**, so an escape through one is invisible

Which trade is right depends on how much of what you actually run has a recipe. That is what `compare` is for: leave decisions on the heuristic, collect the disagreements against real usage, and switch when the evidence says to.

## Config

```toml
[settings]
jail = "ask"                                        # warn | ask | deny
jail_allow = ["~/Downloads", "~/.cargo/registry"]   # extra roots that are fine
```

## What happens

```
cat src/main.rs               → silent (inside the repo)
cat /etc/hosts                → prompt: outside the project jail
cp x ~/Documents/y            → prompt
cat ~/Downloads/data.csv      → silent (allowed root)
cd .. && cat ../secret        → checked against the post-cd directory, not the original cwd
grep x $HOME/.zshrc           → dynamic path — the jail reads literals; $VARs are the fail-closed machinery's job
```

The agent is told *why*, so it self-corrects: `lictor: '/etc/hosts' is outside the project jail — stay in the repo or have the user extend settings.jail_allow`.

For unattended sessions, harden it per mode ([modes](modes.md)): `[modes.auto.settings] jail = "deny"`.
