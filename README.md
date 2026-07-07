# Lictor

<img src="docs/logo.png" align="left" width="180" hspace="26" vspace="12" alt="A Roman lictor bearing the fasces — the rods-and-axe mark of enforcing authority">

A policy gate for coding-agent tool calls. One Rust binary in Claude Code's
`PreToolUse`/`PostToolUse` hooks, configured in TOML.

A **lictor** was the Roman officer who walked ahead of a magistrate, cleared the way,
and enforced his orders on the spot. `lictor` does the same for a coding agent: it walks
in front of every tool call, and stops the ones that shouldn't pass.

> _Designed by human, coded by Claude._

<br clear="left">

## Why

Agent permission systems match command patterns. That works for allowing `git status`,
but it can't express policy: no "allow `git push`, deny `git push --force`", no
deny-with-reason the agent can learn from, no rewriting (`grep` → `rg`), and no control
over how much tool output floods the context window. So you either click "approve" all
day or turn the permission system off.

Lictor is a policy engine in the hook layer. It parses every command with
[tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash), gates each
command in a chain individually, and fails closed on anything it can't statically prove.
It never executes a command to analyze it.

| agent runs | lictor decides |
|---|---|
| `echo ok && git commit -m wip` | **deny** — "Commits are manual…" (ban found inside the chain) |
| `bash -c "gi''t commit"` | **deny** — payload parsed, quote-splice resolved |
| `grep -r TODO src/` | **rewrite** → `rg TODO src/`, auto-approved |
| `mv src/a.ts src/b.ts` | **rewrite** → `git mv src/a.ts src/b.ts` (file is git-tracked) |
| `cat ~/.zshrc` | **ask** — path outside the project jail |
| `git $ACTION` | **ask** — dynamic arg defeats the ban check, fail closed |
| `cargo test` (3 400 lines) | output **spilled** to `kv`; model sees the tail + a `kv get` note |

Decisions arrive as words the agent can act on — deny reasons, warn hints, and retrieval
notes land in its context verbatim:

```
lictor: `git stash pop` is banned by rule `git stash*`
lictor: cannot statically verify `git $ACTION` against rule `git commit*`
lictor: `/etc/hosts` is outside the project jail — stay in the repo or have the user extend settings.jail_allow
lictor: `mv src/a.ts src/b.ts` targets git-tracked paths; rewrote to `git mv` (keeps history)
lictor: 3+ consecutive denied commands — shell autonomy paused; a user-approved command lifts it
lictor: `tsc` did not resolve. This project pins toolchains via `.prototools` — run `proto use`, then retry the command.

[lictor] output too large: 3412 lines / 214806 bytes. Full output stored: retrieve with
`kv get lictor-cargo-test-1751833542` and pipe through rg/tail — do not dump it whole. Last 40 lines:
```

A rule's `reason` or `hint` replaces the default text — that's how "Commits are manual —
propose a commit message and wait for the user." reaches the agent instead of a bare ban notice.

## What it does

**Gate** — every command in a chain, individually:

- **Bans that hold** — `git commit` stays denied inside pipes, subshells, `$(...)`, `bash -c "..."`, `eval`, `xargs`, `sudo env ...`, `find -exec`, loop/if/case bodies, and behind `/usr/bin/git` or `git -C /x commit`. The `reason` is handed back to the agent, so it corrects course in one turn.
- **Catalogs** — `catalogs = ["recommended"]` covers ~150 commands in one line: read-only allow, network/mutating/pkg-install ask, secrets/destructive deny. Also `read-only` and `paranoid`.
- **Argument-level rules** — `contains` (must include) and `only` (nothing else may appear) globs, so "allow `curl` but only against this one host" is three lines of TOML.
- **GTFOBins detectors** — shell escapes in flag values (`tar --checkpoint-action=exec=sh`), program mini-languages (`awk 'BEGIN{system(...)}'`, `sqlite3 '.shell'`), git config injection (`git -c core.pager=…`), env-var prefixes (`LD_PRELOAD=…`), fork bombs, raw-device writes.
- **Project jail** — literal paths outside the project and its allowed roots warn/ask/deny; catches `cat ~/.zshrc`, `cp x /tmp/y`, `../` escapes, `--flag=/abs/path`.
- **Path rules** — your own dir globs (`/tmp/**`, `~/.ssh/**`) warn/ask/deny with your own hint, matched against every path a command touches: args, `NAME=val`/`export` values, redirect targets (`> /tmp/x`), and Write/Edit file paths. First match wins, so a specific `allow` can carve an exception out of a broad deny. This is where temp-scratch / secrets policy lives — ships no default, you bring the dirs and the message.
- **Rogue-actor guard** — N consecutive denies pause shell autonomy: every Bash call asks until a command actually executes, which puts the user back in the loop.
- **File-edit gates** — `Edit`/`Write`/`MultiEdit`/`NotebookEdit` matched by path glob + content regex.
- **Per-mode overrides** — `[modes.auto]` / `[modes.bypassPermissions]` blocks layer on top of the base policy only when the session's `permission_mode` matches; settings override, rule lists append. Built in, no config needed: in `auto` mode any `ask` lictor would emit is downgraded to `deny` — nobody's there to answer a permission dialog, so an unanswerable `ask` would just stall the turn.

**Rewrite** — fix commands instead of blocking them; the result is re-gated, so bans still apply:

- **Pattern rewrites** — `grep` → `rg`, or anything you configure.
- **Git-aware moves** — `mv`/`rm` of git-tracked paths become `git mv`/`git rm` (checked via `git ls-files`).
- **Monorepo cwd hygiene** — `cd pkg && bun run lint` → `bun --cwd pkg run lint` (`pnpm -C`, `npm --prefix`, `yarn --cwd`).
- **Bin-path shortening** — `/usr/local/bin/rg` → `rg`, `./node_modules/.bin/tsc` → `tsc`.
- **Delete/recreate detection** — `rm` targets are fingerprinted; a later `Write` whose content fuzzy-matches the deleted file warns/asks/denies with "restore + `git mv` instead".

**Shrink** — control what reaches the model's context:

- **Wrap** — put an output-minifying proxy like [rtk](https://github.com/rtk-ai/rtk) in front: `git log` → `rtk git log`.
- **Pipe** — captured stdout through any stdin→stdout filter.
- **Truncate** — error-preserving head+tail.
- **Spill** — oversized or slow output (`spill_lines`, `spill_seconds`) goes to the [kv](https://github.com/AmrSaber/kv) store; the model gets the last N lines plus the exact `kv get` command, so it re-queries the cache instead of re-running the test suite.
- **Toolchain activation** — on a `command not found` failure with a `.prototools`/`.nvmrc`/`.tool-versions` marker in cwd, tell the agent to activate and retry.

## Quick start

```sh
brew install sladg/tap/lictor
```

Or build from source (needs Rust 1.85+): `cargo install --git https://github.com/sladg/lictor`,
or `cargo install --path .` in a clone.

Then wire it into Claude Code:

```sh
lictor init --write            # starter lictor.toml + the hooks snippet for settings.json
lictor check                   # validates every config file it can find
lictor check -- <command...>   # gate + run + minify one command — see what the model would see
lictor check --mode auto -- <command...>   # dry-run as if permission_mode were `auto`
lictor gain                    # audit-log summary: decisions + minify/spill bytes saved
```

`kv` and `rtk` are optional companions for spill/wrap.

`lictor init` prints the hooks block to paste into `.claude/settings.json` (or
`~/.claude/settings.json`): `PreToolUse` for Bash and the file-edit tools, `PostToolUse`
for output minify.

### Try your policy

`lictor check -- <command>` runs one command through the exact hook pipeline: it prints
the gate decision, asks `y/N` where the agent harness would prompt, executes, and prints
the output the model would see — minify, wrap, and spill applied. Narration goes to
stderr, output to stdout, deny exits 1. Quote to keep `$vars` and pipes intact:
`lictor check -- 'cargo test | tail'`. Without a tty there is nobody to approve, so
`ask` refuses instead of running.

```
$ lictor check -- git stash list
lictor: deny — Never stash — ask the user how to handle dirty state.

$ lictor check -- 'curl --version'
lictor: ask — Outbound network access.
lictor: run it? [y/N] y
lictor: exec: curl --version
curl 8.7.1 (x86_64-apple-darwin25.0) …

$ lictor check -- 'seq 1 900'
lictor: allow
lictor: exec: seq 1 900
lictor: output shrunk 3492 → 267 bytes
[lictor] output too large: 900 lines / 3492 bytes. Full output stored: retrieve with
`kv get lictor-seq-1-900-1783373321` and pipe through rg/tail — do not dump it whole. Last 20 lines:
…
```

## Configuration

**Everything lives in `lictor.toml`.** Configs chain: the user file first, then every
`lictor.toml` (or `.claude/lictor.toml`) from the filesystem root down to cwd — so a
monorepo root config applies in every package dir. Rule lists concatenate, deeper files
win per key, and deny beats allow, so a project file can't unban a user-level ban:

1. `~/.config/lictor/config.toml` (user)
2. `<ancestor dirs>/lictor.toml`, top → bottom (e.g. the monorepo root)
3. `<cwd>/.claude/lictor.toml`, `<cwd>/lictor.toml` (project)

A working policy covering the common cases:

```toml
[settings]
catalogs = ["recommended"]        # safe defaults for ~150 commands; also: read-only | paranoid
strip_program_paths = "rewrite"   # /usr/local/bin/rg -> rg, ./node_modules/.bin/tsc -> tsc
spill_lines   = 800               # oversized output -> kv store, model gets tail + retrieval note
spill_expires = "24h"             # forwarded to `kv set --expires-after`
log_file = "~/.local/state/lictor/audit.jsonl"

[[bash]]
match  = "git commit*"            # word-wise glob, matched against every command in the chain
action = "deny"                   # allow | deny | ask | rewrite | warn | log
reason = "Commits are manual — propose a commit message and wait for the user."

[[bash]]
match    = "git push"
contains = ["--force", "-f"]      # argument globs, order-independent
action   = "deny"
reason   = "Force pushes are banned."

[[bash]]
match  = "npx tsc*"               # the project defines its own scripts
action = "deny"
reason = "Use the project script: bun run typecheck."

[[bash]]
match   = "grep*"
action  = "rewrite"
rewrite = "rg"                    # replaces the matched pattern words, args are kept

[[bash]]
match    = "curl"
contains = ["https://pullmd.example/*"]        # must actually hit this host
only     = ["-*", "https://pullmd.example/*"]  # and nothing else may appear
action   = "allow"

[[bash]]
match  = "gh *"
action = "log"                    # audit-only: record the call, decide nothing

[catalog.kubectl-read]            # mention-to-activate a built-in catalog
action = "allow"

[catalog.git-read]                # tweak built-in membership
action = "allow"
add    = ["git submodule status"]
remove = ["git grep"]

[catalog.prod-surface]            # custom group: one block gates many commands
match  = ["terraform apply", "flyctl deploy", "kubectl * -n prod*"]
action = "ask"
reason = "Production surface — confirm."

[[edit]]
paths   = ["**/*.ts", "**/*.tsx"]     # globset
pattern = "as (any|never|unknown)"    # regex over written content
action  = "deny"
hint    = "No type assertions — fix the type design instead."

[[edit]]
paths  = ["**/.env*"]
action = "ask"
hint   = "Touching environment files."

[[path]]
match  = ["/tmp/**", "/private/tmp/**"]   # dir globs, matched against every path a command touches
action = "deny"                           # first match wins; a specific `allow` can precede a broad deny
hint   = "scratch goes in .claude/scratch/ or `kv set`, never /tmp"

[[minify]]
match = "git log*"
wrap  = "rtk"                     # git log -> rtk git log
allow = true                      # and auto-approve it

[[minify]]
match = "npm install*"
pipe  = "squeez filter"           # stdout | squeez filter -> what the model sees;
                                  # any stdin->stdout program works: `tail -20`,
                                  # `rtk pipe`, `ecotokens filter-output`

[[minify]]
match     = "vitest*"
max_lines = 80                    # built-in truncator, keeps head+tail
min_lines = 20                    # skip outputs already smaller than this
preserve  = ["(?i)error"]         # matching lines survive truncation

[[activate]]                      # on `command not found` + marker file in cwd,
file  = ".prototools"             # tell the agent to activate and retry
run   = "proto use"
tools = ["node", "npm", "bun", "tsc"]
```

The fully annotated example (every rule type, every option) is in
[`examples/lictor.toml`](examples/lictor.toml). [`docs/reference.md`](docs/reference.md)
lists every built-in catalog, bundle, module, structural detector, and the
[`[modes.*]` per-permission-mode overlay](docs/reference.md#per-mode-overrides-modes)
with a copy-paste example each; the catalog definitions themselves — every command each
one covers — live in [`src/catalogs/builtin.toml`](src/catalogs/builtin.toml).

Behavior worth knowing before first run:

- A broken config fails closed: every `PreToolUse` call escalates to `ask` with the parse error as the reason, until `lictor check` passes.
- Spill degrades gracefully: if `kv` isn't installed, the tail still replaces the output (marked as unstored). A `pipe` filter that fails or changes nothing leaves the output untouched — output is never lost.
- An output redirect (`> file`, `>> file`, `&>`) disqualifies a command from auto-allow and from `wrap` — a read-only command that writes a file isn't read-only. `/dev/null` targets and fd dups (`2>&1`) stay harmless.

## Fail closed

Anything that defeats static analysis escalates to the permission prompt: parse errors, `eval "$X"`, `bash -c "$PAYLOAD"`, dynamic program names (`$CMD commit`), and deny rules that can't be verified because an argument is dynamic (`git push $FLAGS` against a `--force` ban). A banned token appearing *literally* inside a dynamic word is still a definite deny — `echo "EXIT: $?"` against `contains = ['*$\?*']` matches the raw source (`\?`/`\*` escape the glob metacharacters). Structural obfuscation — invisible/zero-width/bidi characters, undecodable escapes — is denied outright; decodable ones are resolved first, so `$'\x67'it commit` hits the normal `git commit` ban.

Loops and conditionals are decomposed, not trusted: every command inside `for`/`while`/`if`/`case` bodies and function definitions is gated individually. Opaque interpreter payloads (`python -c`, `node -e`, `curl x | sh`, heredocs) ask by default. Auto-approval is conservative: **every** command in a chain must be vetted, and wrapper variants count separately — `sudo git status` is not covered by an allow rule for `git status`.

Each of these defaults is a setting; [`docs/reference.md`](docs/reference.md) covers them all.

Threat model: lictor is defense-in-depth against a sloppy or manipulated agent, not a sandbox — there is no process isolation. It decides what the permission system sees; the permission prompt stays the last line.

## License

[MIT](./LICENSE)
