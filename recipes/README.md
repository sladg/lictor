# Recipes

One file per program: what each argument **means** to it. Which slots are paths,
which flags consume the next word, and what the program does to what it names.

`build.rs` embeds every `*.toml` here into the binary, so adding a map is
dropping a file — no Rust to edit. The filename must match the program it maps
(`grep.toml` maps `grep`), which a test enforces.

## The rule for this directory

Hand-written and reviewed. There are no provenance tiers and no runtime `--help`
probing: a `--help` pass may be used **once** to draft an entry, and its output is
reviewed by a person before it lands here.

**A program with no recipe gets no reference edges, and lictor says nothing about
it.** That is deliberate. Silence on an unmapped program is the honest failure
direction, and it is the whole reason this directory exists instead of another
heuristic. Adding a recipe is cheap; guessing is not.

Full coverage is **not** the goal. Local and project-specific scripts are
expected to stay unmapped: their interfaces change without notice and are known
only to their author, so a recipe for one is a guess with a longer shelf life
than the script. Map the tools many people run and whose interfaces are
documented.

## Format

```toml
[[cmd]]
name = "mv"
[[cmd.args]]
slots  = "except-last"
kind   = "path"
effect = ["read", "delete"]   # a set: mv's source is both
[[cmd.args]]
slots  = "last"
kind   = "path"
effect = ["write", "create"]
```

| field | values |
|---|---|
| `name` | the program, matched on its basename (`/usr/bin/rm` matches `rm`) |
| `subcommand` | only apply when the leading positionals match — `git rm` and `git log` share a binary and nothing else. Space-separated for a tree: `"s3 cp"` matches `aws s3 cp`, and the deepest matching entry wins |
| `slots` | `all` · `first` · `last` · `except-last` · `rest` · a number |
| `kind` | `none` · `path` · `cmd` — plus `pathset` `glob` `regex` `code` `url` `host` `container`, which validate but produce no edges yet |
| `effect` | `read` · `write` · `delete` · `create` · `exec` — a set |
| `when` | `{ with = [...], without = [...] }` — guards an entry on the flags present |
| `[cmd.flags]` | per flag: `takes`, `kind`, `effect` |

Slots are counted **after** flag arguments are removed. `grep -e PATTERN file`
has *one* positional, not two.

## Locality is not a field

`aws s3 cp`, `kubectl cp` and `scp` put local and remote references in **one
positional list**, and the same slot is local in one spelling and remote in the
other:

```
aws s3 cp ./build s3://bucket/path    slot 0 here, slot 1 elsewhere
aws s3 cp s3://bucket/path ./build    the reverse
scp host:/etc/hosts .                 the same shape, no scheme
```

So no entry can declare it. Locality is a fact of the **word** — a `:` in a word
that does not start at a filesystem root (`graph::locality_of`) — and a word that
carries one produces no reference edges, because a reference edge is a claim
about *this* machine. Map the slot for what the program does to it and let the
argument say where it lives.

The exemption for words starting with `/`, `~` or `.` is what keeps
`/var/log/build:2024.log` a local path. The cost is silence on a relative name
below the cwd that contains a colon and no leading `./`.

## Two fields that look optional and are not

**`takes`.** Whether a flag consumes the next word decides every slot number
after it. Guessing that from a leading dash is how `sed -n '/needle/p'` came to be
denied as a filesystem path (issue #4).

**`when`.** `grep PATTERN file` and `grep -e PATTERN file` disagree about what
slot 0 *is*. Without a guard, grep's recipe is wrong in one direction or the
other: either the pattern is read as a path, or a real file loses its read edge.

## Writing a new recipe

1. `recipes/<program>.toml`, one `[[cmd]]` per subcommand you cover.
2. Map only what you are sure of. An absent entry is silence; a wrong entry is a
   false positive or a missed deny.
3. `effect` is a set — ask whether the argument is read *and* something else.
4. `cargo test` — the recipe is parsed, validated, and checked against its
   filename.

Nothing here is Turing-complete on purpose: slots, kinds and effects, and nothing
else. A recipe that cannot express something is a recipe that gets extended after
review, not one that grows a scripting language.
