---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Modules

Context-aware checks backed by read-only probes (`git ls-files`, a PATH resolve, session state) — they look at real state before deciding, which plain pattern rules can't. Toggle each by name; values are a subset of `off | warn | rewrite | ask | deny | allow` per module. Rewrites run **before** gating, so the result is judged in its final form.

## Config

```toml
[modules]
git-mv = "rewrite"          # mv of a git-tracked path → git mv (keeps history)
git-rm = "rewrite"          # rm of a git-tracked path → git rm (records the deletion)
delete-recreate = "ask"     # a Write resembling a just-deleted file → rename it properly
self-rm = "allow"           # rm of files the agent itself created this session → no prompt
pm-cwd = "rewrite"          # cd pkg && bun run x → bun --cwd pkg run x
abs-paths = "deny"          # absolute path to an in-project file → use the relative one
path-check = "warn"         # program guaranteed not to resolve on PATH → tell the agent why
```

## What happens

```
mv src/a.ts src/b.ts              → runs `git mv src/a.ts src/b.ts` (file is tracked)
mv untracked.log old.log          → untouched (not tracked — nothing to preserve)
rm -f tracked.rs                  → runs `git rm -f tracked.rs`
cd pkgs/api && bun run lint       → runs `bun --cwd pkgs/api run lint` (cwd stays put)
rm scratch.rs                     → no prompt (agent created it this session — self-rm)
rm scratch.rs some-old-file.rs    → prompt (chain touches a pre-existing file)
cat /Users/me/proj/src/x.ts       → blocked: reference it as `src/x.ts` (abs-paths)
tokf run -- cargo check           → runs; hint: `tokf` is not on PATH (path-check)

after `rm old.rs`, a Write of ~95% identical content
→ prompt: "restore + `git mv` instead of delete/recreate" (delete-recreate)

git status && echo === && cargo check
→ hint: zsh expands `===` as a command lookup (`== not found` aborts the line) — quote it or drop it (path-check)
```

Fine print: `abs-paths` reads **literal** paths only — dynamic `$HOME/…` args are left alone, and paths *outside* the project are the [jail](jail.md)'s job. `path-check` resolves against the hook's own PATH and skips shell builtins, functions defined in the command, and program words containing `/`; aliases and functions from your rc files are invisible to it — the `warn` default tolerates that, escalate to `ask`/`deny` to stop the command instead. When the missing tool matches an [activate](activate.md) rule whose marker file is present, the hint includes the activation command.

Jail, path rules, strikes, and activate are modules too, configured via `[settings]` / their own tables — see [jail](jail.md), [path rules](path-rules.md), [strikes](strikes.md), [activate](activate.md).
