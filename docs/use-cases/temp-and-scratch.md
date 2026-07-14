---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Temp hygiene: no /tmp, cache output in kv, scratch in the repo

Agents love `/tmp`: dump a log there, write a helper script there, `tee` intermediate output there. Files in system temp are invisible to you and survive nothing. `[[path]]` rules ban the directories with your own message, and the spill guard makes the kv cache the natural place for command output.

## Policy

```toml
[settings]
# oversized/slow output is cached via `kv set` automatically; the model sees
# the tail plus the exact `kv get <key>` command to re-query it
spill_lines = 200
spill_keep = 20
spill_seconds = 30
spill_expires = "24h"

# every macOS system-temp location. /tmp resolves to /private/tmp and $TMPDIR
# lives under /var/folders, so both spellings are listed — each glob is tested
# against the lexical AND the symlink-resolved path.
[[path]]
match = [
  "/tmp/**", "/private/tmp/**",
  "/var/tmp/**", "/private/var/tmp/**",
  "/var/folders/**", "/private/var/folders/**",
]
action = "deny"
hint = "No system temp — cache command output with `kv set <key>`, or write scratch files to .claude/scratch/."

# the spill retrieval loop depends on kv — never prompt for it
[[bash]]
match = "kv *"
action = "allow"
```

## How it plays out

`[[path]]` rules match **every filesystem path a command touches**: arguments (cd-aware), `NAME=val` / `export` assignment values, write-redirect targets, and Write/Edit file paths. There is no redirect loophole:

```
touch /tmp/notes.txt                        → deny: no system temp…
echo secret > /tmp/leak                     → deny (redirect target)
OUT=/var/tmp/build cargo build              → deny (assignment value)
bash -c 'echo x > /tmp/nested'              → deny (redirect inside a nested shell)
Write /private/tmp/analysis.md              → deny (file-edit path, same rule)
cargo test   (3400 lines)                   → runs; output spilled to kv, model
                                              sees the tail + `kv get lictor-cargo-test-…`
```

The deny `hint` teaches the workflow: expensive output goes through `kv set` / `kv get` instead of `> /tmp/out.txt`, and deliberate scratch files go in a visible, project-scoped directory.

## Variations

First matching rule wins, so a specific `allow` carves an exception out of the broad deny — e.g. permit one sanctioned scratchpad:

```toml
[[path]]
match = ["/private/tmp/claude-501/**"]   # this harness's session scratchpad
action = "allow"

[[path]]
match = ["/tmp/**", "/private/tmp/**"]
action = "deny"
hint = "No system temp — use the session scratchpad or `kv set`."
```

Prefer `ask` over `deny` if some temp usage is legitimate but you want to see it. And if you'd rather ban shell-redirect file authoring everywhere (not just in temp): `on_shell_write = "deny"` routes `echo x > f` / `cat > f <<EOF` to "use the Write tool".
