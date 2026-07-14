---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Modes

Rules can differ per `permission_mode` — `default`, `plan`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`. Three primitives, least to most sweeping:

1. **Per-rule `modes` map** — one shared pattern, mode-specific action. No duplication.
2. **`[modes.<mode>]` overlay** — extra rules/settings that exist only in that mode.
3. **`[modes.<mode>.remap]`** — rewrites the *final* decision, applied after everything else.

Plus **allowlist fallbacks**: `default_bash` / `default_edit` / `default_web` decide when *no* rule matched.

## Per-rule modes map

Every `[[bash]]` / `[[edit]]` / `[[path]]` / `[[web]]` / `[[agent]]` rule and `[catalog.*]` block takes it:

```toml
[[web]]
domains = ["docs.rs", "github.com"]
action = "ask"                            # base behavior
modes = { plan = "allow", auto = "deny" } # research freely while planning; never unattended

[catalog.mutating]
modes = { plan = "deny" }                 # no mutations while planning
```

## Overlay

A `[modes.<mode>]` block is one more config layer: settings override, rule lists append, most-restrictive still wins across base + overlay.

```toml
[modes.bypassPermissions.settings]
jail = "deny"                     # nothing's watching → hard-confine to the repo

[[modes.auto.bash]]
match = "curl*"
action = "deny"
reason = "auto mode: no unattended network access"
```

## Remap

Final-decision lookup. Keys are the decisions (`allow`/`ask`/`deny`) plus `warn` (the emitted hints); applied last, after rules, modules, and defaults.

```toml
[modes.auto.remap]
ask = "deny"                      # nobody to answer a dialog — shipped in the starter policy
warn = "skip"                     # drop hints too: fully binary decisions

[modes.acceptEdits.remap]
ask = "warn"                      # demote prompts to hints while babysitting edits
```

## Allowlist lockdown

`default_*` close the no-rule-matched hole — lictor flips from blocklist to allowlist:

```toml
[modes.plan.settings]
default_bash = "deny"             # unmatched command → denied
default_edit = "deny"             # unmatched write → denied
default_web = "deny"              # unmatched WebFetch URL → denied

[[modes.plan.edit]]
paths = ["**/*.md"]               # the plan file is the only writable thing
action = "allow"
```

Read-only allows from the `recommended` bundle still pass — plan mode can read code and research, write only markdown.

## What happens

```
(plan mode)  Write plan.md                → runs (edit allow rule)
(plan mode)  Write src/main.rs            → blocked (default_edit)
(plan mode)  curl https://docs.rs/regex   → runs (web rule, plan = "allow")
(auto mode)  curl https://docs.rs/regex   → blocked (web rule, auto = "deny")
(auto mode)  git push                     → ask becomes deny (remap), reason preserved
```

## Mode names

Names are matched **verbatim** against the `permission_mode` the harness sends — lictor hardcodes no list, so an unknown mode simply matches nothing. If the harness ever renames a mode, `settings.mode_aliases` maps the new name back to the one your config uses (single hop, no lictor update needed):

```toml
[settings]
mode_aliases = { unattended = "auto" }   # harness name = the name in this file
```

Every `[modes.auto]` overlay, `modes = { auto = ... }` map, and `[modes.auto.remap]` keeps firing when the harness sends `unattended`.

Dry-run a mode: `lictor check --mode auto -- 'curl https://x'`.
