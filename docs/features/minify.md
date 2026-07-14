---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Minify

Shapes what the model sees after a command runs — wrap it in a token-efficient proxy, pipe the output through a filter, or truncate it. Use it on noisy CLIs (builds, tests, `git log`, `kubectl`): the model needs the signal, not 400 lines of progress bars.

Three mechanisms, one `[[minify]]` block each:

| Field | Does |
|---|---|
| `wrap` | rewrite the command to run under a proxy: `git log` → `rtk git log` |
| `pipe` | filter captured stdout through any stdin→stdout program |
| `max_lines` / `min_lines` / `preserve` | built-in head+tail truncation; `preserve` regexes keep matching lines |

## Config

```toml
[[minify]]
match = "git log*"
wrap  = "rtk"            # git log → rtk git log
allow = true             # …and auto-approve the wrapped command

[[minify]]
match = "cargo test*"
wrap  = "tokf run --"    # cargo test → tokf run -- cargo test
allow = true

[[minify]]
match = "npm install*"
pipe  = "tail -20"       # model sees the last 20 lines

[[minify]]
match = "vitest*"
max_lines = 80
preserve  = ["(?i)error", "(?i)fail"]   # error lines survive truncation
```

## What happens

```
git log --oneline -20         → runs as `rtk git log --oneline -20`, no prompt (allow = true)
cargo test                    → runs as `tokf run -- cargo test`; model sees the filtered result
npm install                   → runs normally; model sees only the last 20 lines
vitest run  (500 lines)       → model sees head+tail within 80 lines, every error line kept
git log > log.txt             → wrap skipped (redirect disqualifies wrap and auto-allow)
```

Safety valve: a `pipe` filter that fails or changes nothing leaves the output untouched — output is never lost. For the "too big" case there's [spill](spill.md).
