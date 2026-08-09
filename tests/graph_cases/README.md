# Graph cases

Each `*.toml` file here is a list of commands and what the graph should claim
about each. `tests/graph_cases.rs` discovers and runs them all.

Same idea as `tests/cases/` (issue #10), one layer down: those files assert what
lictor *decides*, these assert what the graph *sees*.

```toml
name  = "what this file covers"   # optional, shown in failure messages
issue = 25                        # optional, the issue this pins

[[case]]
name    = "local source, remote destination"
command = "aws s3 cp ./build s3://bucket/path"
expect  = { local = ["reads ./build"], remote = ["writes s3://bucket/path"] }
```

## Every case asserts P1 for free

`emit()` must give the source back byte for byte, and no two nodes may claim the
same bytes. Adding a case here adds a round-trip case, which is why
`graph_p1.rs` no longer keeps a hand-written shape list — see `shapes.toml`.

## Fields

| field | meaning |
|---|---|
| `command` | the source to lower, with the built-in recipes applied |
| `edit` | apply an edit before asserting — see below |
| `expect.local` | every reference **on this machine**, as `"<effect> <target>"`, exact set |
| `expect.remote` | every reference somewhere else, same shape |
| `expect.commands` | the command nodes in source order: `"ssh"`, `"cat @host"`, `"rm @remote"`, `"rm !root"` |
| `expect.binds` | `Takes` edges, as `"<flag>=<value>"` — `"-e=pat"`, `"Out=/etc/passwd"` |
| `expect.flow` | connector edges, as `"cat --pipe--> grep"` |
| `expect.spawns` | `Spawns` edges, as `"sudo spawns rm"` |
| `expect.facts` | lexical facts, as `"<word> <fact>"`: `absolute`, `relative`, `glob`, `literal`, `dynamic`, `remote` |
| `expect.emit` | the emitted text; required when `edit` is set |

A **path set** renders with `/**` when it reaches beneath its root, so
`"deletes build"` and `"deletes build/**"` are visibly different claims.

## An empty list is an assertion

`local = []` means *this command claims nothing about this machine*, which is
most of what the recipes exist to get right — `aws s3 rm s3://bucket/key` and
`kubectl exec pod -- cat /etc/config` are both silence, for different reasons.
An **omitted** field asserts nothing at all.

## `edit` — P2 as data

```toml
[[case]]
command = "grep -n TODO src/main.rs"
edit    = { command = "grep", to = "rg" }
expect  = { emit = "rg -n TODO src/main.rs", local = ["reads src/main.rs"] }
```

The edit is applied to the graph, the result is emitted, and **the emitted text
is re-parsed** — every other expectation describes that re-parsed graph. That is
`parse(emit(g′)) ≡ g′` with the intended graph written down by a person instead
of derived from the graph under test, which is the stronger form: a derivation
shares its bugs with the thing it checks.

Use `edit = { command = "…" }` to rewrite a program name and
`edit = { value = "…" }` to rewrite an argument.

## What stays in Rust

Properties over a corpus (`graph_p1.rs`, `graph_p2.rs`), pure functions, and the
span bookkeeping that is expressed in node ids rather than in text
(`src/graph.rs`'s test module). Everything that is an *example* belongs here.

## Two things the runner is strict about

- **Unknown fields are errors.** A typo'd `expect.locl` would otherwise assert
  nothing while looking like it asserts something.
- **An empty `expect` is an error.** A case that checks nothing passes forever.

Both are covered by tests in `tests/graph_cases.rs`, along with a case that must
fail — a data-driven harness is only worth trusting if it can.
