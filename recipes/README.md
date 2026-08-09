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
| `slots` | `all` · `first` · `last` · `except-last` · `rest` · `N+` · a number |
| `kind` | `none` · `path` · `pathset` · `cmd` · `shell` · `host` / `container` — plus `glob` `regex` `code` `url`, which validate but produce no edges yet |
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
that does not start at a filesystem root (`graph::locality_of`). Map the slot for
what the program does to it and let the argument say where it lives.

The reference edge exists either way: `aws s3 rm s3://bucket/key` really does
delete a key, and the graph says so with the reference marked remote. Consumers
that mean *this* machine ask for local references only. So an entry for a slot
that is always remote in practice is still worth writing — it is what makes the
silence a decision rather than an omission.

The exemption for words starting with `/`, `~` or `.` is what keeps
`/var/log/build:2024.log` a local path. The cost is silence on a relative name
below the cwd that contains a colon and no leading `./`.

## Saying that a program runs somewhere else

`ssh host cat /etc/hosts` reads a file on another machine. A recipe says so by
naming **a machine and a payload**:

```toml
[[cmd.args]]
slots = "first"
kind  = "host"      # or "container"
[[cmd.args]]
slots = "1+"        # the payload starts AFTER the host
kind  = "cmd"
effect = ["exec"]
```

Those two entries together already say the payload runs on that machine, so
there is no third field to set and no way to write a recipe where they disagree.
The payload is lowered as its own command, `cat`'s recipe applies to it, and
every path it names is marked remote.

## `shell` vs `code`

Both say "this argument is source, not a filesystem path", which is all issue #4
ever needed. They differ in what follows from that:

- **`code`** — source in *some* language. Nothing more can be said about it, so
  it produces no edges. `python3 -c`, `perl -e`.
- **`shell`** — source in a language *this parser can read*. The string is
  re-parsed and grafted onto the command behind a `spawns` edge, so
  `bash -c 'cat /etc/passwd'` claims the read instead of claiming nothing.

```toml
[cmd.flags]
"-c" = { takes = true, kind = "shell", effect = ["exec"] }
```

Only the shells get `shell`. Lowering a Python payload as bash would manufacture
claims about a language the graph cannot parse, which is worse than silence —
and `settings.on_inline_script` already covers the interpreters that stay quiet.

Inferring this from the program name instead would mean a hand-maintained list
of which programs are shells, which is one of the tables issue #13 exists to
delete.

`slots = "1+"` means "from slot 1 onward". `rest` is slot 0 onward, which is what
`sudo` and `xargs` want and what would make ssh run the *hostname*.

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
