---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Catalogs

A catalog is a named group of commands sharing one config block — gate ~150 commands without writing 150 rules. Built-ins ship in the binary ([`src/catalogs/builtin.toml`](../../src/catalogs/builtin.toml)); bundles activate curated sets.

## Config

```toml
[settings]
catalogs = ["recommended"]   # bundle: *-read → allow, net/mutating/pkg-install → ask,
                             # secrets/destructive/gtfobins/obfuscation → deny
                             # also: "read-only" (just the allows) | "paranoid" (stricter)

[catalog.net-egress]         # mention a built-in to activate/override it
action = "deny"

[catalog.git-read]           # tweak membership
add    = ["git worktree list"]
remove = ["git grep"]

[catalog.prod-surface]       # or define your own group
match  = ["terraform apply", "flyctl deploy", "kubectl * -n prod*"]
action = "ask"
reason = "Production surface — confirm."
```

## What happens

With `catalogs = ["recommended"]`:

```
ls, cat src/x.rs, git diff, docker ps   → run, no prompt (read catalogs → allow)
rm src/x.rs, npm install left-pad       → prompt (mutating / pkg-install → ask)
cat .env, shred file, git push --force  → blocked (secrets-read / destructive → deny)
cat .env                                → deny wins over text-read's allow — most-restrictive, no ordering rules
```

Carve an exception out of a catalog's blanket action with a narrow [`skip`](skip.md) rule (lictor steps aside, Claude Code's own rules decide):

```toml
[[bash]]
match = "rm .claude/scratch/*"
action = "skip"
```

## Built-in catalogs

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
| `kv-cache` | allow | `kv` (all subcommands) — the cache behind spill; disposable local store, not a source of truth |
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

`kv-cache` covers the [kv](https://github.com/AmrSaber/kv) CLI that [spill](spill.md) stores output in — it's not a system tool, install it with `brew install AmrSaber/tap/kv`.

## Bundles (`settings.catalogs`)

| Bundle | Contents |
|---|---|
| `read-only` | the 16 `*-read`/query/nudge catalogs → **allow** (`search-nudge` is warn-only), nothing else |
| `recommended` | `read-only` **+** `net-egress`/`mutating`/`pkg-install` → ask, `secrets-read`/`destructive`/`obfuscation`/`gtfobins` → deny |
| `paranoid` | `recommended` but `net-egress` and `mutating` → **deny**, plus `interactive` → ask |
