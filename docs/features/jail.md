---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Jail

Confines the agent to the project: literal paths outside the repo (and your allowed roots) get warn/ask/deny. Use it so "the agent works on my repo" actually means the repo — not your dotfiles, not `/etc`.

The project root is the git repo containing cwd (`git rev-parse --show-toplevel`), so the agent moves freely anywhere inside the repo even after `cd`-ing around; outside a repo it falls back to plain cwd. Inside a **linked git worktree**, the main checkout (`git rev-parse --git-common-dir`'s parent) is trusted too — otherwise a shell that `cd`s into a worktree can never `cd` back out, since every route, including editing `jail_allow` itself, would read as outside the project. This also grants sibling worktrees under the same main checkout (they're the same user's working trees, not a different tenant).

A `cd` earlier in a chain shifts what later relative paths resolve against; a subshell's `cd` (`bash -c`, `eval`, `find -exec`) doesn't leak out; `cd -` or a dynamic target freezes tracking at the last known cwd rather than guessing. Resolution is lexical — `~` expanded, `..` collapsed, no symlink or `$VAR` resolution.

Some programs relocate their own arguments onto another filesystem entirely — `ssh host cat /etc/hosts` reads a path on the remote host, `kubectl exec pod -- cat /etc/config.yaml` reads inside the container. The jail (and `[[path]]` rules) recognize these and stop reasoning about local containment past the boundary (the remote command, the payload after `--`); `[[bash]]` deny rules are unaffected and still see every word, so `kubectl exec pod -- rm -rf /` stays gateable. Certain arguments are program text rather than paths too — `sed`/`awk` scripts, `grep`/`rg` patterns passed positionally or via `-e`, `find`'s `-name`/`-path`/`-regex` values, `jq`/`yq` filters — and are recognized the same way, so `sed -n '/needle/p' file` doesn't deny on `/needle/p`.

## Config

```toml
[settings]
jail = "ask"                                        # warn | ask | deny
jail_allow = ["~/Downloads", "~/.cargo/registry"]   # extra roots that are fine
jail_require_existing = false                       # backstop, see below
```

### `jail_require_existing`

Off by default. When `true`, a candidate outside every root whose path *and every parent directory* don't exist on disk is treated as a false positive (a stray shell-syntax token the argument-role table didn't catch) instead of an escape.

**Trade-off:** this also blinds the jail to a genuine attempt to *create* a file outside the repo — the whole reason a `deny` jail exists. Leave it off for anything load-bearing; it's a backstop for the long tail, not a substitute for the argument-role/locality recognition above.

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
