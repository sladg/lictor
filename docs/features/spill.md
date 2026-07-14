---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Spill

Oversized or slow command output goes to a local [kv](https://github.com/AmrSaber/kv) cache instead of the context window; the model gets the tail plus the exact `kv get` command to query the rest. Use it so one `cargo test` doesn't eat 3 000 lines of context — and so the agent re-queries the cache instead of re-running the suite.

`kv` is a separate CLI: `brew install AmrSaber/tap/kv` (source: [github.com/AmrSaber/kv](https://github.com/AmrSaber/kv)). The built-in `kv-cache` [catalog](catalogs.md) allows all its subcommands so the retrieval loop never prompts.

## Config

```toml
[settings]
spill_lines = 200        # outputs over 200 lines spill
spill_seconds = 30       # …or anything from a command that ran ≥ 30s (worth caching)
spill_keep = 20          # tail lines the model still sees
spill_expires = "24h"    # forwarded to `kv set --expires-after`
# spill_command = "kv"   # override the storage CLI

[[bash]]
match = "kv *"           # the retrieval loop depends on kv — never prompt for it
action = "allow"
```

## What happens

```
cargo test   (3 400 lines)
→ full output stored: `kv set lictor-cargo-test-1751833542`
→ model sees:
  [lictor] output too large: 3412 lines / 214806 bytes. Full output stored: retrieve with
  `kv get lictor-cargo-test-1751833542` and pipe through rg/tail — do not dump it whole. Last 20 lines:
  …

agent follows up:
kv get lictor-cargo-test-1751833542 | rg "^test result"   → instant, no re-run
```

Degrades gracefully at run time: `kv` not installed → the tail still replaces the output, marked as unstored. But `lictor check` treats it as an **error** when spill is configured and the CLI is missing — every retrieval note the model would see points at a store that doesn't exist. Runs after [minify](minify.md), applies to all commands.
