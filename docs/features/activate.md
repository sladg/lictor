---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Activate

When a command fails with *command not found* and a toolchain marker file sits in cwd, the agent is told how to activate the toolchain and retry. Use it with version managers (proto, nvm, asdf) — otherwise the agent sees `bun: command not found` and starts installing things globally instead of running one activation command.

Hooks can't silently re-run a failed command, so this is guidance, not magic — but the agent follows it in one turn.

## Config

```toml
[[activate]]
file  = ".prototools"
run   = "proto use"
tools = ["node", "npm", "npx", "pnpm", "yarn", "bun", "tsc", "uv", "go"]

[[activate]]
file  = ".nvmrc"
run   = "nvm use"
tools = ["node", "npm", "npx", "yarn"]
```

## What happens

```
bun run build     (.prototools in cwd, bun not on PATH)
→ exits 127: "bun: command not found"
→ agent's context gets: "`bun` did not resolve. This project pins toolchains via
  `.prototools` — run `proto use`, then retry the command."
→ agent runs `proto use`, retries, moves on

cargo build       (not in the tools list)
→ plain command-not-found, no hint
```

Pairs with the `path-check` [module](modules.md), which flags a guaranteed-unresolvable program *before* the run and includes the activation command in its hint when a marker file is present.
