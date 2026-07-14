---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Fail closed

Anything that defeats static analysis escalates to the permission prompt instead of slipping through. This is the default posture, not a rule you write — lictor never guesses and never executes a command to analyze it.

## What escalates

```
eval "$X", bash -c "$PAYLOAD"        → prompt (opaque payload)
$CMD commit                          → prompt (dynamic program name)
git push $FLAGS   (vs --force ban)   → prompt (can't verify the ban against a dynamic arg)
python -c "…", curl x | sh, heredocs → prompt (inline scripts, on_inline_script = ask)
unparseable command, nesting > 5     → prompt (on_unparseable = ask)
broken lictor.toml                   → every call prompts, parse error as the reason, until `lictor check` passes
```

## What stays a hard deny

```
gi​t commit  (zero-width char)        → blocked (structural obfuscation — invisible/bidi chars, undecodable escapes)
$'\x67'it commit                     → decodable escape resolved first → hits the normal `git commit` ban
echo "EXIT: $?"  (vs '*$\?*' ban)    → blocked (a banned token appearing literally inside a dynamic word is definite)
```

## Conservative by design

- loops and conditionals are decomposed, not trusted — every command in `for`/`while`/`if`/`case` bodies and function definitions is gated individually
- auto-approval needs the whole chain vetted: `git status && rm x` is not covered by a `git status` allow
- wrapper variants count separately: `sudo git status` ≠ `git status`
- an output redirect (`> file`) disqualifies a command from auto-allow — a read-only command that writes a file isn't read-only

## Threat model

Defense-in-depth against a sloppy or manipulated agent, not a sandbox — there is no process isolation. Lictor decides what the permission system sees; the permission prompt stays the last line.
