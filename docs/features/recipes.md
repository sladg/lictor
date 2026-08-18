---
created_at: 2026-08-18
updated_at: 2026-08-18
---

# Recipes

Where the graph's meaning comes from: one reviewed TOML file per program in `recipes/`, saying which arguments are paths, which flags consume the next word, and what the program does to what it names (read/write/delete/create/exec). Every path the [jail](jail.md) and [path rules](path-rules.md) reason about exists because a recipe said so — there is no shape-guessing fallback.

The full authoring guide lives next to the recipes themselves: [`recipes/README.md`](../../recipes/README.md) — the format, the slots/kinds/effects vocabulary, and the rules of the directory (hand-written, reviewed, no runtime `--help` probing).

## Adding one

Drop `recipes/<program>.toml` and rebuild — `build.rs` embeds every file, no Rust to edit. The one-recipe-per-need workflow is the supported remedy whenever lictor is silent about a program it should see through:

```toml
[[cmd]]
name = "frobnicate"
[[cmd.args]]
slots  = "all"
kind   = "path"
effect = ["read"]
```

## Accepted gaps

These are the places the recipe model is silent **on purpose**. Each is a trade against a worse failure mode, not an oversight:

- **Unmapped programs.** A program with no recipe references no paths, so an escape through one is invisible. Silence is the honest failure direction — the alternative was guessing from word shape, which produced the false positives issue #4 collected. Remedy: add the recipe.
- **Unknown flag-attached values.** `rg --path=/var/log/x` or a glued short flag like `tail -o/etc/shadow` rides a flag no recipe marks as taking a path. Same trade, same remedy: extend the program's recipe, don't guess.
- **Dynamic paths.** `cat $CONFIG_DIR/secrets` names a path only the runtime knows. Literal `$HOME`/`${VAR}` prefixes are expanded from the live environment, but a genuinely dynamic word is left to the [fail-closed](fail-closed.md) machinery rather than resolved optimistically.
- **Symlinked access paths.** Resolution is lexical (`~` expanded, `..` collapsed). A path that lexically sits inside the project is trusted even when a symlink on it points outside; canonicalization runs only to *admit* aliased spellings of trusted roots (`/tmp` vs `/private/tmp`), never to reject an in-project spelling. Chasing every link would mean syscalls per word per command.
- **Unenumerated secrets.** The secrets catalogs match known locations (`~/.ssh`, `~/.aws`, …). A credential in an unlisted file is just a file; nothing infers secrecy from content.
- **Pattern-vs-pattern silence.** A rule glob and a command glob never intersect symbolically: `rm build/*` is judged by the pathset it names, and a `[[path]]` rule whose glob overlaps only partially errs toward its declared verdict. Two patterns reasoning about each other is where static precision ends.

If a gap on this list starts biting in practice, the answer is a recipe, a catalog entry, or a rule — the vocabulary is deliberately small so extending it stays a review-sized change.
