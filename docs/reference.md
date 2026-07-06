# Lictor policy reference

Orientation for `lictor.toml`: every catalog, module, and detector Lictor ships **today**, with
a copy-paste example each — the *current-state* reference.

Source of truth: catalogs → `src/catalogs/builtin.toml`, bundles → `src/catalogs/mod.rs`,
modules → `src/modules/`, settings → `src/config.rs`.

---

## How config loads

Files are read and merged **user → ancestors → cwd** (later wins per key; a project can
override your global defaults). Every directory from the filesystem root down to cwd is
checked, so a monorepo root config applies in every package dir:

1. `~/.config/lictor/config.toml` (or `$XDG_CONFIG_HOME/lictor/config.toml`)
2. `<dir>/.claude/lictor.toml` then `<dir>/lictor.toml`, for each ancestor dir, root-most first
3. the same pair in `<cwd>` itself, last (deepest wins per key)

`lictor init` writes a starter `lictor.toml` (the shipped [`src/default.toml`](../src/default.toml)).

### Actions — the shared vocabulary

Every gate rule resolves to one action. When several rules match a command, **most-restrictive
wins, order-independent**:

```
deny  >  ask  >  warn  >  rewrite  >  allow
```

| Action | Effect |
|---|---|
| `allow` | auto-approve (no prompt). Only when *every* command in the chain is vetted. |
| `deny` | block; the `reason` is handed back to the agent so it can correct in one turn. |
| `ask` | surface a permission prompt to you. Also the fail-closed default for anything dynamic. |
| `warn` | no decision; attach a `hint` to the agent's context. |
| `rewrite` | replace the command with a safer/cheaper form, then re-gate the result. |
| `log` | audit-only: record the match, decide nothing. |

Modules use the same words minus `log`, plus `off` (disabled).

---

## Catalogs

A catalog is a named group of commands sharing one config block. At load time it **expands into
plain `[[bash]]`/`[[minify]]` rules** — no separate engine path. Activate a built-in two ways:

```toml
# 1. bundle line — pull a curated set at their default actions
[settings]
catalogs = ["recommended"]

# 2. mention-to-activate — name a built-in and (optionally) override its action
[catalog.net-egress]
action = "deny"            # this project never hits the network
```

Tweak a built-in's membership with `add`/`remove`, or define your own with `match`:

```toml
[catalog.git-read]
add = ["git submodule status"]          # extend the built-in

[catalog.prod-surface]                   # brand-new group
match  = ["terraform apply", "flyctl deploy", "kubectl * -n prod*"]
action = "ask"
reason = "production surface — confirm"
```

### Built-in catalogs

| Catalog | Default | Covers (examples) |
|---|---|---|
| `shell-core` | allow | `echo printf read cd true false test [ : seq sleep` |
| `fs-read` | allow | `ls tree eza stat file du df realpath readlink basename dirname pwd which type` |
| `text-read` | allow | `cat head tail nl less strings od xxd grep rg sort uniq cut tr diff wc jq yq sed` (plain `sed`; `-i` routes to `mutating`) |
| `sysinfo` | allow | `uname nproc uptime free lscpu printenv date whoami id groups hostname sw_vers` |
| `proc-read` | allow | `ps pgrep pstree pmap lsof` |
| `net-query` | allow | `dig host nslookup ss ping traceroute mtr whois getent` |
| `git-read` | allow | `git status/log/diff/show/blame/ls-files/rev-parse/branch --list/config --get …` |
| `gh-read` | allow | `gh pr/issue/run/repo/release list+view`, `gh auth status`, `gh search` |
| `docker-read` | allow | `docker ps/images/inspect/logs/top/history/version/info/diff` |
| `kubectl-read` | allow | `kubectl get/describe/logs/top/explain/version/config view/auth can-i` |
| `helm-read` | allow | `helm list/status/get/show/history/search/template/lint` |
| `tf-read` | allow | `terraform validate/fmt -check/show/output/state list/providers/graph` |
| `svc-read` | allow | `systemctl status/list-*/is-*/show/cat`, `journalctl`, `launchctl list` |
| `pkg-query` | allow | `npm/pnpm/pip/uv/cargo/brew/apt/gem … list/show/outdated/search` |
| `kv-cache` | allow | `kv` (all subcommands) — the cache behind `settings.spill_command`; disposable local store, not a source of truth |
| `net-egress` | ask | `curl wget http https nc ncat telnet` |
| `mutating` | ask | `rm mv cp ln mkdir rmdir touch chmod chown tee truncate` |
| `pkg-install` | ask | `npm/pnpm/yarn/bun/pip/uv/cargo/brew/apt/gem … install/add/remove/upgrade` |
| `secrets-read` | deny | readers (`cat less head tail bat grep rg sed …`) hitting `*.env* *.pem *.key *id_rsa* .aws/credentials .ssh/* .npmrc .netrc .kube/config` |
| `destructive` | deny | `shred mkfs* fdisk parted wipefs`, `dd of=/dev/*`, `rm` on `/ ~ --no-preserve-root`, `git push --force`, `DROP DATABASE/TABLE` |
| `gtfobins` | deny | shell-escape flag vectors: `tar --checkpoint-action`, `awk 'BEGIN{system()}'`, `git -c core.pager=`, `ssh -o ProxyCommand`, `sqlite3 .shell`, `vim -c`, … |
| `obfuscation` | deny | **structural** detector (invisible chars, undecodable escapes, fork bomb) — routes to `on_obfuscation`, not a pattern list |
| `interactive` | ask | binaries that can spawn a shell via a typed escape: `less more man vi vim nano gdb ftp ed …` |
| `noisy-build` | minify | `cargo build/test/clippy`, `npm/pnpm run build`, `go build/test`, `vitest tsc make` → output truncation (no gate action) |
| `search-nudge` | warn | `grep find sed` → hint to prefer `rg`/`rg --files`; grants no permission, doesn't change any decision |

### Bundles (`settings.catalogs`)

| Bundle | Contents |
|---|---|
| `read-only` | the 16 `*-read`/query/nudge catalogs → **allow** (`search-nudge` is warn-only), nothing else |
| `recommended` | `read-only` **+** `net-egress`/`mutating`/`pkg-install` → ask, `secrets-read`/`destructive`/`obfuscation`/`gtfobins` → deny |
| `paranoid` | `recommended` but `net-egress` and `mutating` → **deny**, plus `interactive` → ask |

Precedence makes overlaps safe automatically: `cat` is `allow` (text-read) but `cat .env` is
`deny` (secrets-read) — the dangerous case wins with no ordering rules.

---

## Modules

Context-aware checks backed by **read-only probes** (a `git ls-files`, a path resolve, session
state). Two config styles:

### A. The `[modules]` namespace

Toggle each by name. Values: `off | warn | rewrite | ask | deny` (each module accepts a subset).
These run **before** gating, so a rewrite is judged in its final form.

| Module | Accepts | What it does |
|---|---|---|
| `git-mv` | off·warn·rewrite | `mv` of a git-tracked path → `git mv` (keeps history) |
| `git-rm` | off·warn·rewrite | `rm` of a git-tracked path → `git rm` (records the deletion) |
| `delete-recreate` | off·warn·ask·deny | a `Write` resembling a just-`rm`'d file → "restore + `git mv`" instead of delete+recreate |
| `pm-cwd` | off·warn·rewrite·ask·deny | `cd pkg && bun run x` → `bun --cwd pkg run x` (also `pnpm -C`, `npm --prefix`, `yarn --cwd`) |
| `abs-paths` | off·warn·ask·deny | absolute paths the agent needlessly builds → nudge to relative / ban temp scratch (see below) |
| `path-check` | off·warn·ask·deny | guaranteed *command not found* flagged upfront: program word not on PATH, or an unquoted zsh `=cmd` word that can't resolve (see below) |

```toml
[modules]
git-mv = "rewrite"
git-rm = "rewrite"
delete-recreate = "ask"
pm-cwd = "rewrite"
abs-paths = "deny"        # opt-in; NOT in the shipped default
path-check = "warn"
```

**Examples**

```bash
# git-mv (rewrite)
mv tracked.rs renamed.rs                 → git mv tracked.rs renamed.rs

# git-rm (rewrite)
rm -f tracked.rs                         → git rm -f tracked.rs

# pm-cwd (rewrite)
cd monorepo/pkg && bun run lint          → bun --cwd monorepo/pkg run lint

# delete-recreate (ask): after `rm old.rs`, a Write of near-identical content →
#   "this is 95% similar to recently deleted old.rs — git checkout -- old.rs, then git mv"

# abs-paths (deny): absolute path INSIDE the project
grep -c "" /Users/me/proj/apps/courier/src/x.ts
#   → deny: reference it relative to the repo root as `apps/courier/src/x.ts`

# abs-paths (deny): system-temp scratch (also catches D=/tmp/... prefixes)
D=/private/tmp/scratch/exploit cargo build
#   → deny: put scratch under .claude/scratch/ or cache with `kv set`, never /tmp

# path-check (warn): program that can't resolve — command runs, agent is told why it failed
tokf run -- cargo check                  → hint: `tokf` is not on PATH
bun run check     # .prototools in cwd   → hint: … run `proto use` first, then retry

# path-check (warn): zsh =cmd expansion — `echo ===` makes zsh look up a
# command named `==` and abort the whole line with "(eval):1: == not found"
git status && echo === && cargo check    → hint: quote it as '===' or drop it
```

`abs-paths` reads **literal** paths only (command args + `NAME=val` prefix values); dynamic
`$HOME/…` / `$TMPDIR/…` are left alone. Paths *outside* the project are the jail's job, not
this module's.

`path-check` resolves against the hook process's own `PATH` and skips builtins, functions
defined in the command, and program words containing `/` (a `./tool` may be built by an
earlier chain link). Aliases and functions from your rc files are invisible to it — the
`warn` default tolerates that; escalate to `ask`/`deny` to stop the command instead. When a
missing tool matches an `[[activate]]` rule whose marker file is present, the message
includes the activation command.

### B. Modules configured via `[settings]` / their own tables

| Module | Config | What it does |
|---|---|---|
| jail | `settings.jail` = warn·ask·deny + `settings.jail_allow` | literal paths outside the project (and allowed roots) → gate. The project root is the git repo containing cwd (`git rev-parse --show-toplevel`), not cwd itself — free movement anywhere inside the repo, even after `cd ..` out of a subdirectory; falls back to plain cwd outside a repo. A `cd` earlier in the same chain shifts the base every later relative path resolves against (`cd .. && cat ../secret` is checked against the post-`cd` directory, not the original cwd); a subshell's `cd` (`bash -c`/`eval`/`find -exec`) never leaks out. `cd -` or a dynamic target freezes tracking at the last known cwd rather than guessing. Lexical (`~` expanded, `..` collapsed; no symlink/`$VAR` resolution). |
| strikes | `settings.strikes` = N | N consecutive Lictor denies with no command executed in between → every Bash call `ask`s until one runs (rogue-actor brake). |
| activate | `[[activate]]` blocks | on a *command-not-found* failure with a toolchain marker in cwd → hint "run `<activate>`, retry". |

```toml
[settings]
jail = "ask"
jail_allow = ["~/Downloads", "/private/tmp/claude-501"]   # extra roots
strikes = 5

[[activate]]
file = ".prototools"
run  = "proto use"
tools = ["node", "npm", "bun", "tsc", "uv", "go"]
```

```bash
# jail (ask): outside the project
cat /etc/hosts                → ask   (cat src/main.rs → silent)

# activate: `.prototools` present, exit 127
bun run build  → "bun: command not found"
#   → hint: run `proto use`, then retry
```

---

## Structural detectors & hygiene settings

Signals detected in `bash::extract` (not word-globs) plus output/token guards. All under
`[settings]`; defaults in parentheses.

| Setting | Default | Fires on |
|---|---|---|
| `on_obfuscation` | deny | invisible/bidi chars, undecodable `$'\x..'` escapes, fork bomb (`obfuscation` catalog is an alias) |
| `on_dangerous_env` | deny | code-injecting env prefix: `LD_PRELOAD`, `BASH_ENV`, `PYTHONSTARTUP`, `GIT_SSH_COMMAND`, `BASH_FUNC*`, … |
| `on_inline_script` | ask | opaque interpreter payloads: `python -c`, `node -e`, `curl … \| sh`, stdin/heredoc-fed shells |
| `on_unparseable` | ask | command tree-sitter can't parse, or nesting deeper than 5 |
| `on_shell_write` | off | content emitter authoring a file via redirection (`echo x > f`, `cat > f <<EOF`) — use the Write/Edit tool |
| `strip_program_paths` | off | bin-dir program paths (`/usr/local/bin/rg`, `./node_modules/.bin/tsc`) → basename; `warn`/`ask`/`deny` also available |

Plus **hard, unconditional** denies (not configurable): write redirect to a raw disk device
(`> /dev/sda`, `dd of=/dev/nvme0n1`).

### Output guards (PostToolUse)

| Setting | Meaning |
|---|---|
| `spill_lines` / `spill_seconds` | output over N lines, or from a command that ran ≥ N seconds, is cached via `spill_command` (default `kv`) — the agent sees the tail + a `kv get <key>` note |
| `spill_keep` / `spill_expires` | tail lines to retain / cache TTL (e.g. `"24h"`) |
| catalog `max_lines` / `pipe` / `wrap` | per-group output shaping (e.g. `noisy-build`) |

---

## A complete `lictor.toml`

```toml
[settings]
catalogs = ["recommended"]        # ~150 commands gated in one line
on_obfuscation = "deny"
on_inline_script = "ask"
on_shell_write = "deny"           # author files with Write/Edit, not `echo > f`
strip_program_paths = "rewrite"
spill_lines = 800
spill_seconds = 30
strikes = 5
# jail = "ask"                    # uncomment to confine to the repo
# jail_allow = ["~/Downloads", "/private/tmp/claude-501"]

[modules]
git-mv = "rewrite"
git-rm = "rewrite"
delete-recreate = "ask"
pm-cwd = "rewrite"
abs-paths = "deny"                # nudge absolute paths → relative; ban /tmp scratch
path-check = "warn"               # tell the agent when a program can't resolve on PATH

# --- project overrides ---
[catalog.git-read]
add = ["git worktree list"]

[catalog.net-egress]
action = "allow"                  # this project curls a local API
add    = ["gh api"]

[[bash]]                          # one-offs still work
match  = "rm -rf node_modules"
action = "allow"

[[activate]]
file = ".prototools"
run  = "proto use"
tools = ["node", "npm", "bun", "tsc"]
```
