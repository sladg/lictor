---
created_at: 2026-08-09
updated_at: 2026-08-09
---

# Delete rules

`[[delete]]` globs are matched against the paths a command actually **removes** — not every path it mentions. Use them for the files where "don't touch this" is meant literally and getting it wrong is least recoverable: migrations, lockfiles, generated schemas.

`[[path]]` fires on any command that merely *names* a path, so "never delete `src/migrations/**`" could otherwise only be written as a blunt deny on `rm` — which also blocks `rm` everywhere else, and still misses `unlink`.

Same shape as `[[path]]`: a glob list, an action, an optional hint. First matching rule wins, so a specific `allow` carves an exception out of a broad `deny`.

## Config

```toml
[[delete]]
match  = ["**/src/migrations/**"]
action = "deny"
hint   = "migration files must not be deleted; revert them instead"

[[delete]]
match  = ["**/*.lock"]
action = "ask"
```

`action` is `deny` / `ask` / `warn` / `allow`. `rewrite`, `skip` and `log` are rejected at config load — they have no meaning for a deletion.

## What counts as deleting

`rm`, `unlink`, `rmdir` and `git rm` — the same extraction the delete/recreate detector uses, so the two cannot drift on what "deleting" means.

- `git rm --cached` leaves the file on disk, so it is not a deletion
- a dynamic word anywhere in the command (`rm $TARGET`) means the targets are unknowable, so the rule abstains rather than guesses
- deletions inside a nested shell (`bash -c 'rm x'`) still count
- a `Delete`-shaped tool call is gated the same way, so a rule covers a deletion however it arrives

## Deleting a directory

A rule protecting `**/src/migrations/**` also stops `rm -rf src/migrations`. Without that, the most obvious bypass would defeat the rule.

Because a glob cannot be asked "could you match anything under this directory?", that case is probed with synthetic descendant paths. Two consequences, both deliberate:

- **it over-approximates**, in the safe direction for a rule about deletion: a glob that *could* match something beneath the path fires even if no such file exists
- **it under-approximates on contents**: `rm -rf logs/` is *not* caught by a `**/*.lock` rule even if `logs/` happens to contain one. Knowing that needs the filesystem, and a rule engine that stats the disk on every command is racy and slow. Name the directory if you want it protected.

## Examples

```
rm src/migrations/001.sql          → deny (matches directly)
rm -rf src/migrations              → deny (would remove protected paths)
cat src/migrations/001.sql         → silent (reading is not deleting)
unlink src/migrations/001.sql      → deny
git rm --cached src/migrations/x   → silent (file stays on disk)
rm Cargo.lock                      → ask
rm target/debug/junk               → silent (no rule matches)
rm $TARGET                         → silent (dynamic target, abstains)
```

## See also

- [path rules](path-rules.md) — the same glob shape, matched against every path a command touches
- [edit rules](edit-rules.md) — gate what an edit adds, removes or changes in place
