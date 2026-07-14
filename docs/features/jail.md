---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Jail

Confines the agent to the project: literal paths outside the repo (and your allowed roots) get warn/ask/deny. Use it so "the agent works on my repo" actually means the repo — not your dotfiles, not `/etc`.

The project root is the git repo containing cwd (`git rev-parse --show-toplevel`), so the agent moves freely anywhere inside the repo even after `cd`-ing around; outside a repo it falls back to plain cwd. A `cd` earlier in a chain shifts what later relative paths resolve against; a subshell's `cd` (`bash -c`, `eval`, `find -exec`) doesn't leak out; `cd -` or a dynamic target freezes tracking at the last known cwd rather than guessing. Resolution is lexical — `~` expanded, `..` collapsed, no symlink or `$VAR` resolution.

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
