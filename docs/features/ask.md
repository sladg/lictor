---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# ask

Forces the permission prompt, with your `reason` as the dialog text. Use it for things you want to see case-by-case — network access, package installs, production surface — instead of banning or blanket-allowing them.

## Config

```toml
[[bash]]
match = "curl*"
action = "ask"
reason = "Outbound network access."

[catalog.prod-surface]
match = ["terraform apply", "flyctl deploy", "kubectl * -n prod*"]
action = "ask"
reason = "Production surface — confirm."
```

## What happens

Simple cases:

```
curl https://api.example.com  → prompt: "Outbound network access." — you approve or reject
terraform apply               → prompt: "Production surface — confirm."
```

A chain inherits its strictest member — one ask-worthy command anywhere and the whole call prompts:

```
git status && curl https://example.com   → prompt (git status alone would auto-run)
ls | xargs rm                            → prompt: "Filesystem mutation." (rm unwrapped from xargs)
for f in *.json; do curl -T $f https://x; done   → prompt (loop body gated)
```

`ask` is also the fail-closed default for everything static analysis can't prove:

```
CMD=git; $CMD stash list      → prompt (dynamic program name — can't verify against the stash ban)
eval "$PAYLOAD"               → prompt (opaque)
python -c "import os; …"      → prompt (inline script, on_inline_script = ask)
```

The starter policy ships `[modes.auto.remap] ask = "deny"`: in `auto` mode every `ask` becomes `deny` — nobody's there to answer the dialog, and a deny gives the agent a reason it can act on instead of a stalled turn. See [modes](modes.md).
