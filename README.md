# Lictor

<img src="docs/logo.png" align="left" width="180" hspace="26" vspace="12" alt="A Roman lictor bearing the fasces — the rods-and-axe mark of enforcing authority">

Policy gate for coding-agent tool calls. One Rust binary in Claude Code's `PreToolUse`/`PostToolUse` hooks, configured in TOML.

A **lictor** was the Roman officer who walked ahead of a magistrate and enforced his orders on the spot. Same job here — walks in front of every tool call, stops the ones that shouldn't pass.

> _Designed by human, coded by Claude._

<br clear="left">

## Why

Agent permission systems are prefix matchers. I got tired of that:

- can't say "allow `git push`, deny `git push --force`"
- `echo ok && git commit` walks right past a `git commit` rule
- deny is a silent wall — the agent doesn't know *why*, so it retries variants until something slips through
- zero control over output: `cargo test` dumps 3 000 lines into the context, model forgets what it was doing, re-runs the suite because the output scrolled away

End state: you either click "approve" all day or turn the checks off. Lictor is the third option — a real policy engine in the hook layer.

## What it does

- **gates** — commands parsed with [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash), every command in a chain judged individually: pipes, subshells, `$(...)`, `bash -c "..."`, `eval`, loop bodies. Can't prove it statically → [fail closed](docs/features/fail-closed.md) to a prompt.
- **talks back** — [deny](docs/features/deny.md) reasons and [warn](docs/features/warn.md) hints are your words, handed to the agent verbatim. Blocked agent with a reason corrects in one turn; blocked agent without one brute-forces variants.
- **rewrites** — fix instead of block: `grep` → `rg` ([rewrite](docs/features/rewrite.md)), `mv` of a tracked file → `git mv` ([modules](docs/features/modules.md)). Result is re-gated, so a rewrite can't smuggle past a ban.
- **gates file edits too** — by path + content: what's added, what's deleted, what must be present ([edit rules](docs/features/edit-rules.md)).
- **shrinks output** — [minify](docs/features/minify.md) noisy CLIs, [spill](docs/features/spill.md) oversized output to a local cache; the model gets the tail + a retrieval command instead of 3 000 lines.

| agent runs | lictor decides |
|---|---|
| `echo ok && git commit -m wip` | **deny** — "Commits are manual…" (ban found inside the chain) |
| `bash -c "gi''t commit"` | **deny** — payload parsed, quote-splice resolved |
| `grep -r TODO src/` | **rewrite** → `rg TODO src/`, auto-approved |
| `mv src/a.ts src/b.ts` | **rewrite** → `git mv src/a.ts src/b.ts` (file is git-tracked) |
| `cat ~/.zshrc` | **ask** — path outside the project jail |
| `git $ACTION` | **ask** — dynamic arg defeats the ban check, fail closed |
| `cargo test` (3 400 lines) | output **spilled** to `kv`; model sees the tail + a `kv get` note |

## Quick start

```sh
brew install sladg/tap/lictor
```

Or with Rust 1.85+: `cargo install --git https://github.com/sladg/lictor`.

```sh
lictor init --write            # starter lictor.toml + the hooks snippet for settings.json
lictor check                   # validate config (a broken config fails closed: everything asks until this passes)
lictor check -- <command...>   # dry-run one command through the exact hook pipeline
lictor gain                    # audit-log summary: decisions + tokens/bytes saved
```

`lictor init` prints the hooks block to paste into `.claude/settings.json` (or `~/.claude/settings.json`): `PreToolUse` for Bash and the file-edit tools, `PostToolUse` for output minify. Optional companions: [`kv`](https://github.com/AmrSaber/kv) for spill (`brew install AmrSaber/tap/kv`) and [`rtk`](https://github.com/rtk-ai/rtk) for wrap. Without `kv`, spill falls back to plain truncation — nothing is lost. `wrap` rules rewrite unconditionally, so only write them for tools you actually have installed.

Dry-run anything before trusting it:

```
$ lictor check -- 'echo ok && git commit -m wip'
lictor: deny — Commits are manual — propose a commit message and wait for the user.

$ lictor check -- 'seq 1 900'
lictor: allow
lictor: output shrunk 3492 → 267 bytes
```

## Configuration

Everything lives in `lictor.toml`. Configs chain — user file (`~/.config/lictor/config.toml`, or `$XDG_CONFIG_HOME`), then `.claude/lictor.toml` / `lictor.toml` in every directory from the filesystem root down to cwd — so a monorepo root config applies in every package. Rule lists concatenate, deeper files win per key, deny beats allow — a project file can't unban a user-level ban.

```toml
[settings]
catalogs = ["recommended"]        # ~150 commands gated in one line
spill_lines = 800                 # oversized output -> kv cache + retrieval note
jail = "ask"                      # paths outside the repo -> prompt

[[bash]]
match  = "git commit*"            # word-wise glob, checked against every command in a chain
action = "deny"                   # allow | deny | ask | rewrite | warn | log | skip
reason = "Commits are manual — propose a commit message and wait for the user."

[[edit]]
paths   = ["**/*.ts", "**/*.tsx"]
pattern = "as (any|never|unknown)"   # regex over written content
action  = "deny"
hint    = "No type assertions — fix the type design instead."
```

Full annotated config: [`examples/lictor.toml`](examples/lictor.toml). Every command each catalog covers: [`src/catalogs/builtin.toml`](src/catalogs/builtin.toml).

## Features

One short doc per feature — what it does, config, and exactly what happens when the agent runs something:

| Area | Docs |
|---|---|
| Actions | [allow](docs/features/allow.md) · [deny](docs/features/deny.md) · [ask](docs/features/ask.md) · [warn](docs/features/warn.md) · [rewrite](docs/features/rewrite.md) · [log](docs/features/log.md) · [skip](docs/features/skip.md) |
| Rule types | [catalogs](docs/features/catalogs.md) · [edit rules](docs/features/edit-rules.md) · [path rules](docs/features/path-rules.md) · [retries](docs/features/retries.md) |
| Guards | [jail](docs/features/jail.md) · [strikes](docs/features/strikes.md) · [detectors](docs/features/detectors.md) · [fail-closed](docs/features/fail-closed.md) · [modes](docs/features/modes.md) |
| Output & context | [minify](docs/features/minify.md) · [spill](docs/features/spill.md) |
| Helpers | [modules](docs/features/modules.md) · [activate](docs/features/activate.md) |

## Recipes

Worked policies for common scenarios — [`docs/use-cases/`](docs/use-cases/):

| Recipe | You get |
|---|---|
| [Read-only auto-approve](docs/use-cases/read-only-autoapprove.md) | ~150 read/query commands run without prompts; anything mutating still asks |
| [Git write-ban](docs/use-cases/git-write-ban.md) | agent reads history freely; commit/stash/reset/checkout/push stay manual, chain-proof |
| [TypeScript discipline](docs/use-cases/typescript.md) | no `eslint-disable`/`@ts-ignore`/`as any`, project scripts over `npx tsc`, quiet lint output |
| [Protect docs & tests](docs/use-cases/protect-docs-and-tests.md) | edits that delete doc-comments or test cases warn or bounce |
| [Markdown frontmatter](docs/use-cases/markdown-frontmatter.md) | every `.md` the agent writes carries `created_at:`/`updated_at:`, bumped on each edit |
| [Search discipline](docs/use-cases/search-discipline.md) | `grep`/`find`/`ack` denied with a hint that teaches `rg` |
| [Temp & scratch hygiene](docs/use-cases/temp-and-scratch.md) | `/tmp` banned in every form (args, redirects, env values); big output cached in `kv` |

## Threat model

Defense-in-depth against a sloppy or manipulated agent, not a sandbox — no process isolation. Lictor decides what the permission system sees; the permission prompt stays the last line. Details: [fail-closed](docs/features/fail-closed.md).

## License

[MIT](./LICENSE)
