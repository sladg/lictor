---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Detectors

Structural checks that don't need a rule to match — they fire on *how* a command is built, not what it's named. Use the defaults; loosen or tighten per setting. All under `[settings]`.

| Setting | Default | Fires on |
|---|---|---|
| `on_obfuscation` | deny | invisible/zero-width/bidi chars, undecodable `$'\x..'` escapes, fork bombs |
| `on_dangerous_env` | deny | code-injecting env prefixes: `LD_PRELOAD=…`, `BASH_ENV=…`, `GIT_SSH_COMMAND=…` |
| `on_inline_script` | ask | opaque interpreter payloads: `python -c`, `node -e`, `curl x \| sh`, heredoc-fed shells |
| `on_unparseable` | ask | commands tree-sitter can't parse, nesting deeper than 5 |
| `on_shell_write` | off | authoring files via redirection: `echo x > f`, `cat > f <<EOF` |
| `strip_program_paths` | off | `/usr/local/bin/rg` → `rg`, `./node_modules/.bin/tsc` → `tsc` (set to `rewrite`) |

Writes to raw disk devices (`> /dev/sda`, `dd of=/dev/nvme0n1`) are always denied — not configurable.

## Config

```toml
[settings]
on_obfuscation = "deny"
on_inline_script = "ask"
on_shell_write = "deny"          # author files with Write/Edit, not `echo > f`
strip_program_paths = "rewrite"
```

## What happens

```
$'\x67'it commit               → escapes decoded first → hits the normal `git commit` ban
gi​t commit  (zero-width char)  → blocked outright (obfuscation)
LD_PRELOAD=./evil.so ls        → blocked (dangerous env)
python -c "import os; …"       → prompt (inline script)
echo '#!/bin/sh…' > run.sh     → blocked: use the Write tool (on_shell_write = deny)
/usr/local/bin/rg TODO         → runs as `rg TODO` (path stripped)
```

The GTFOBins-style flag vectors (`tar --checkpoint-action=exec=sh`, `git -c core.pager=…`, `awk 'BEGIN{system(…)}'`) live in the `gtfobins` [catalog](catalogs.md), deny by default in the `recommended` bundle.
