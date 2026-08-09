---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Protect doc-comments and tests from "cleanup"

Agents delete things that get in their way: a doc-comment on a function they refactor, a failing test that "no longer applies". `removed_pattern` fires when content that matched in the old text is **gone from the new text** — the inverse direction of `pattern`, which checks what's being added.

## Policy

```toml
# tsdoc / jsdoc blocks must survive refactors
[[edit]]
paths = ["**/*.ts", "**/*.tsx"]
removed_pattern = '(?s)/\*\*.*?\*/'
action = "warn"
hint = "A doc-comment was removed by this edit — keep it unless the user asked for its removal."

# rust doc-comments
[[edit]]
paths = ["**/*.rs"]
removed_pattern = "(?m)^///"
action = "warn"
hint = "Rust doc-comments (///) must not be removed."

# deleting a test is a decision the user makes, not the agent
[[edit]]
paths = ["**/*.test.ts", "**/*.spec.ts", "**/*.test.tsx"]
removed_pattern = '(?m)^\s*(it|test|describe)\('
action = "deny"
hint = "Never delete test cases — refactor them to the new API. If a test genuinely cannot survive, list it and ask the user."

[[edit]]
paths = ["**/*.rs"]
removed_pattern = '(?m)^\s*#\[test\]'
action = "deny"
hint = "Never delete tests — port them to the new shape, or ask the user per case."
```

## How it plays out

`removed_pattern` compares each edit pair: it fires when the regex matches `old_string` but not `new_string`. `Write` calls send no prior content, so they never trigger it — this is a guard on **edits**, where deletion is visible.

```
Edit: "/** Returns the user. */\nfunction getUser…" → "function getUser…"
  → warn: a doc-comment was removed by this edit…

Edit: reworded comment, /** */ block still present   → silent
Edit: "it('rejects empty input', …)" block deleted   → deny: never delete test cases…
```

A `warn` doesn't block — the edit lands and the hint lands with it, so the agent restores the comment in its next edit or explains why it had to go. A `deny` blocks outright; the assertion never leaves the file.

## Changed expectations, not just deleted ones

`removed_pattern` can't see a value swap — `toBe("foo")` → `toBe("bar")` still matches the regex, so nothing fires. `changed_pattern` checks each old match individually: fire when *that exact text* is gone from the new content. Pair it with deny-then-allow so the first attempt gets the consult instruction and the resubmission (after consulting) passes:

```toml
[[edit]]
paths = ["**/*.test.ts", "**/*.spec.ts", "**/*_test.go", "**/tests/**/*.rs"]
changed_pattern = '"[^"]*"'
action = "deny"
hint = "Test expectation edited — tests are not made to pass blindly. Did the behaviour change, and is that wanted? Confirm with the user, then resubmit."
retry_count = 1
retry_window = 600
```

Adding a brand-new test never fires (old matches all survive); `Write` sends no prior content, so it never fires there either. The same trick closes `removed_pattern`'s blind spot on comments — deleting one comment while another survives:

```toml
[[edit]]
paths = ["**/*.ts", "**/*.rs", "**/*.go"]
changed_pattern = '(?m)[ \t]*//[^\n]*'
action = "warn"
hint = "A comment was edited or removed — restore it unless the user asked."
```

## Variations

Combine directions in one rule — both conditions must hold. This catches "replaced the real docs with a TODO placeholder":

```toml
[[edit]]
paths = ["**/*.ts"]
pattern = "TODO"
removed_pattern = '(?s)/\*\*.*?\*/'
action = "warn"
hint = "Doc-comment replaced by a TODO placeholder — restore the docs."
```

Let a repeated warn go quiet once it's been delivered — the agent saw the hint, no need to repeat it every edit:

```toml
[[edit]]
paths = ["**/*.ts", "**/*.tsx"]
removed_pattern = '(?s)/\*\*.*?\*/'
action = "warn"
hint = "A doc-comment was removed by this edit."
retry_count = 2
retry_window = 300
```
