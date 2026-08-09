# Declarative test cases

Each `*.toml` file here is a policy plus a list of tool calls and what lictor
should decide about each. `tests/cases.rs` discovers and runs them all.

Adding a case is four lines of data. No `#[test] fn`, no `const POLICY`, no
`json!` boilerplate.

```toml
name  = "what this file covers"    # optional, shown in failure messages
issue = 7                          # optional, the issue this pins

[config]                           # the policy, exactly as in config.toml
[[config.bash]]
match   = "grep*"
action  = "rewrite"
rewrite = "rg"

[[case]]
name    = "flag survives the rewrite"
command = "grep -n TODO src/main.rs"
expect  = { decision = "allow", command = "rg -n TODO src/main.rs" }
```

## Fields

| field | meaning |
|---|---|
| `command` | shorthand for `tool = "Bash"`, `input = { command = … }` |
| `tool` + `input` | any other tool; `input` is the raw `tool_input` |
| `response` | `tool_response`, for `PostToolUse` cases |
| `event` | defaults to `PreToolUse` |
| `cwd`, `session_id` | literal values; omitted means the hook gets none |
| `expect.decision` | `allow` / `ask` / `deny`, or `none` to assert lictor stayed silent. **Omitted means the decision is not asserted at all** |
| `expect.command` | exact `updatedInput.command`; `"<unchanged>"` asserts the command was not rewritten |
| `expect.reason` | substring of `permissionDecisionReason` |
| `expect.hint` / `expect.no_hint` | substring that must / must not appear in `additionalContext` |

## `reason` vs `hint`

They are different output fields, and which one a rule's configured `hint` lands
in depends on its action:

- `deny` / `ask` → `permissionDecisionReason`, the text shown when the call is
  blocked. Assert with **`reason`**.
- `warn` → `additionalContext`, a nudge to the model that blocks nothing. Assert
  with **`hint`**.

## Why TOML

lictor's config is already TOML, so the policy is a native sub-table checked by
the same parser the real config uses. In YAML it would have to be an indented
block scalar — escaping-sensitive and un-lintable.

Keeping the policy **inline** also matters: a harness that wrote a
`$XDG_CONFIG_HOME/lictor/config.toml` fixture would be blocked by lictor's own
`[[path]]` self-protection rule (`src/default.toml:59-65`). That is correct
behaviour, and it has already forced three separate agents into three different
workarounds. A case file never writes a config-shaped path.

## Two things the runner is strict about

- **Unknown fields are errors.** A typo'd `expect.decison` would otherwise
  assert nothing while looking like it asserts something.
- **An empty `expect` is an error.** A case that checks nothing passes forever
  and hides the behaviour it was added to pin.

Both are covered by tests in `tests/cases.rs` — a data-driven harness is only
worth trusting if its own failure modes are pinned.

## Migration

These files are not a full replacement for the Rust suite. The tests that moved
here so far are the ones that were self-contained and pure boilerplate; the rest
migrate incrementally, as they are touched. New cases should start here.
