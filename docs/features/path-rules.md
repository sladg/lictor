---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Path rules

Your own directory policy: `[[path]]` globs are matched against **every filesystem path a command touches** — args, `NAME=val`/`export` values, write-redirect targets, and Write/Edit file paths. Use them for temp/scratch/secrets opinions; lictor ships no default here, you bring the dirs and the message.

First matching rule wins, so a specific `allow` carves an exception out of a broad `deny`. Each glob is tested against both the lexical and symlink-resolved path — one `/tmp/**` covers macOS's `/private/tmp` too.

## Config

```toml
[[path]]
match  = ["/private/tmp/claude-501/**"]   # sanctioned scratchpad — first match wins
action = "allow"

[[path]]
match  = ["/tmp/**", "/private/tmp/**"]
action = "deny"
hint   = "scratch goes in .claude/scratch/ or `kv set`, never /tmp"

[[path]]
match  = ["~/.ssh/**", "~/.aws/**"]
action = "ask"
hint   = "touching credentials — confirm intent"
```

## What happens

```
touch /tmp/notes.txt                  → blocked: "scratch goes in .claude/scratch/…"
echo secret > /tmp/leak               → blocked (redirect target)
OUT=/tmp/build cargo build            → blocked (assignment value)
bash -c 'echo x > /tmp/nested'        → blocked (redirect inside a nested shell)
Write /private/tmp/analysis.md        → blocked (file-edit path, same rule)
echo hi > /private/tmp/claude-501/x   → runs (the allow above matched first)
cat ~/.ssh/config                     → prompt: "touching credentials — confirm intent"
```
