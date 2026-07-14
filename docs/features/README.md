---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Features

One short doc per feature: what it does, config example, what happens when the agent runs something.

## Actions

When several rules match the same command, **most-restrictive wins, order-independent**:

```
deny  >  skip  >  ask  >  warn  >  rewrite  >  allow
```

| Doc | One-liner |
|---|---|
| [allow](allow.md) | auto-approve a command, skip the permission prompt |
| [deny](deny.md) | block a command, hand the agent your reason |
| [ask](ask.md) | force the permission prompt |
| [warn](warn.md) | let it run, attach a hint to the agent's context |
| [rewrite](rewrite.md) | replace the command with a better one, re-gate the result |
| [log](log.md) | audit-only: record the match, decide nothing |
| [skip](skip.md) | true no-op — carve an exception out of a catalog, harness rules decide |

## Rule types

| Doc | One-liner |
|---|---|
| [catalogs](catalogs.md) | named command groups — gate ~150 commands with one line |
| [edit rules](edit-rules.md) | gate file edits by path + what's added / removed / missing |
| [path rules](path-rules.md) | your own dir policy, matched against every path a command touches |
| [retries](retries.md) | deny once then allow the resubmit; quiet a repeated hint |

## Guards

| Doc | One-liner |
|---|---|
| [jail](jail.md) | paths outside the project → warn/ask/deny |
| [strikes](strikes.md) | N consecutive denies → autonomy paused until a command runs |
| [detectors](detectors.md) | obfuscation, injected env vars, inline scripts, shell-written files |
| [fail-closed](fail-closed.md) | what can't be statically proven escalates to a prompt |
| [modes](modes.md) | different policy per permission mode (auto, bypassPermissions, …) |

## Output & context

| Doc | One-liner |
|---|---|
| [minify](minify.md) | wrap/pipe/truncate noisy command output |
| [spill](spill.md) | oversized output → kv cache, model gets the tail + retrieval note |

## Helpers

| Doc | One-liner |
|---|---|
| [modules](modules.md) | context-aware rewrites: `mv`→`git mv`, `cd pkg && bun run`→`bun --cwd`, … |
| [activate](activate.md) | "command not found" + toolchain marker → tell the agent how to fix it |
