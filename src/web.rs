//! [[web]] URL rules: domain/path globs matched against static http(s) URLs in
//! Bash arguments and the WebFetch tool's `url`. Compilation reuses the same
//! glob dialect as bash rules (`*`/`?`, no `**` semantics — `*` crosses `/`).

use crate::bash::Command;
use crate::config::{Action, Config, WebRule};
use crate::rules::glob_to_regex;
use regex::Regex;

pub struct CompiledWebRule<'a> {
    pub rule: &'a WebRule,
    domains: Vec<Regex>,
    paths: Vec<Regex>,
}

pub fn compile(config: &Config) -> Result<Vec<CompiledWebRule<'_>>, String> {
    config
        .web
        .iter()
        .map(|rule| {
            let domains = rule
                .domains
                .iter()
                .map(|g| glob_to_regex(g))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("web rule domains: {e}"))?;
            // case-insensitive: URL paths are case-sensitive server-side, but an
            // attacker-controlled server can serve `archive.ZIP` — deny globs
            // must not be evadable by casing
            let paths = rule
                .paths
                .iter()
                .map(|g| glob_to_regex(g).map(case_insensitive))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("web rule match: {e}"))?;
            Ok(CompiledWebRule {
                rule,
                domains,
                paths,
            })
        })
        .collect()
}

fn case_insensitive(re: Regex) -> Regex {
    Regex::new(&format!("(?i){}", re.as_str())).expect("valid regex stays valid with (?i)")
}

pub struct Url {
    pub host: String,
    pub path: String,
}

// ponytail: hand-rolled split, no url crate — IPv6 bracket hosts land in `host`
// verbatim and simply won't glob-match; switch to the url crate if that matters
pub fn parse(word: &str) -> Option<Url> {
    // scheme is case-insensitive (curl accepts HTTPS://) — an uppercase scheme
    // must not slip a URL past the deny globs
    let rest = ["https://", "http://"].iter().find_map(|prefix| {
        word.get(..prefix.len())
            .filter(|head| head.eq_ignore_ascii_case(prefix))
            .map(|_| &word[prefix.len()..])
    })?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    let path = rest[end..].split(['?', '#']).next().unwrap_or("");
    Some(Url {
        host: host.to_ascii_lowercase(),
        path: path.to_string(),
    })
}

fn matches(rule: &CompiledWebRule, url: &Url) -> bool {
    let domain_ok = rule.domains.is_empty() || rule.domains.iter().any(|re| re.is_match(&url.host));
    let path_ok = rule.paths.is_empty() || rule.paths.iter().any(|re| re.is_match(&url.path));
    domain_ok && path_ok
}

// most severe verdict for one URL: deny > ask > warn > allow; None = no rule matched
pub fn check_url<'a>(rules: &'a [CompiledWebRule], url: &Url) -> Option<(Action, &'a WebRule)> {
    let mut best: Option<(Action, &WebRule)> = None;
    for rule in rules {
        // skip = the rule doesn't exist (lets `modes = { plan = "skip" }`
        // disable a rule per mode); it must not poison vetting as an unmatched
        if rule.rule.action == Action::Skip || !matches(rule, url) {
            continue;
        }
        let rank = severity(rule.rule.action);
        if best.is_none_or(|(action, _)| rank > severity(action)) {
            best = Some((rule.rule.action, rule.rule));
        }
    }
    best
}

fn severity(action: Action) -> u8 {
    match action {
        Action::Deny => 5,
        Action::Ask => 4,
        Action::Rewrite => 3,
        Action::Warn => 2,
        Action::Allow => 1,
        Action::Log | Action::Skip => 0,
    }
}

// WebFetch only: bash URLs are left alone (a rewrite match there just blocks
// vetting, so the bash rules decide)
pub fn rewrite_url(rule: &WebRule, url: &str) -> Option<String> {
    Some(rule.rewrite.as_deref()?.replace("{url}", url))
}

pub fn deny_message(rule: &WebRule, url: &str) -> String {
    rule.reason
        .clone()
        .unwrap_or(format!("lictor: `{url}` is banned by a web rule"))
}

pub fn ask_message(rule: &WebRule, url: &str) -> String {
    rule.reason
        .clone()
        .unwrap_or(format!("lictor: `{url}` matches a web ask rule"))
}

pub fn warn_message(rule: &WebRule, url: &str) -> String {
    rule.hint
        .clone()
        .unwrap_or(format!("lictor: `{url}` matches a web warn rule"))
}

#[derive(Default)]
pub struct CommandVerdict {
    pub deny: Option<String>,
    pub ask: Option<String>,
    pub hints: Vec<String>,
    // every URL in the command matched an allow rule AND every word is static —
    // a dynamic word could hide a URL, so it blocks vetting (fail-safe: the
    // command just falls back to the bash rules)
    pub vetted: bool,
    pub allow_reasons: Vec<String>,
}

pub fn gate_command(rules: &[CompiledWebRule], command: &Command) -> CommandVerdict {
    let mut verdict = CommandVerdict::default();
    if rules.is_empty() {
        return verdict;
    }
    let mut urls = 0usize;
    let mut all_allowed = true;
    let all_static = command.words.iter().all(|w| w.text.is_some());
    for word in &command.words {
        // deny globs also get a shot at the raw source of dynamic words
        // (`https://evil.com/$f` still parses host); allow never vets raw
        let candidates = [word.text.as_deref(), word.raw.as_deref()];
        let Some((raw, url)) = candidates
            .iter()
            .flatten()
            .find_map(|s| parse(s).map(|u| (s.to_string(), u)))
        else {
            continue;
        };
        urls += 1;
        match check_url(rules, &url) {
            Some((Action::Deny, rule)) => {
                verdict.deny.get_or_insert(deny_message(rule, &raw));
                all_allowed = false;
            }
            Some((Action::Ask, rule)) => {
                verdict.ask.get_or_insert(ask_message(rule, &raw));
                all_allowed = false;
            }
            Some((Action::Warn, rule)) => {
                let hint = warn_message(rule, &raw);
                if !verdict.hints.contains(&hint) {
                    verdict.hints.push(hint);
                }
                all_allowed = false;
            }
            Some((Action::Allow, rule)) => {
                if word.text.is_none() {
                    // allow matched only via raw source of a dynamic word — not vettable
                    all_allowed = false;
                } else if let Some(reason) = &rule.reason {
                    verdict.allow_reasons.push(reason.clone());
                }
            }
            _ => all_allowed = false,
        }
    }
    verdict.vetted = urls > 0 && all_allowed && all_static && !command.redirects_output;
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(toml: &str) -> Config {
        toml::from_str(toml).expect("config parses")
    }

    const POLICY: &str = r#"
[[web]]
domains = ["docs.rs", "*.github.com"]
action = "allow"

[[web]]
match = ["*.zip", "*.sh"]
action = "deny"
reason = "no archives or scripts"
"#;

    #[test]
    fn parse_extracts_host_and_path() {
        let url = parse("https://user@Docs.RS:8080/regex/latest?q=1#frag").unwrap();
        assert_eq!(url.host, "docs.rs");
        assert_eq!(url.path, "/regex/latest");
    }

    #[test]
    fn parse_rejects_non_urls() {
        assert!(parse("docs.rs").is_none());
        assert!(parse("ftp://x").is_none());
        assert!(parse("https://").is_none());
    }

    #[test]
    fn domain_allow_matches() {
        let config = rules(POLICY);
        let compiled = compile(&config).unwrap();
        let url = parse("https://docs.rs/regex").unwrap();
        assert!(matches!(
            check_url(&compiled, &url),
            Some((Action::Allow, _))
        ));
    }

    #[test]
    fn extension_deny_beats_domain_allow() {
        let config = rules(POLICY);
        let compiled = compile(&config).unwrap();
        let url = parse("https://api.github.com/repo/archive.zip").unwrap();
        assert!(matches!(
            check_url(&compiled, &url),
            Some((Action::Deny, _))
        ));
    }

    #[test]
    fn unmatched_url_is_none() {
        let config = rules(POLICY);
        let compiled = compile(&config).unwrap();
        let url = parse("https://example.com/page").unwrap();
        assert!(check_url(&compiled, &url).is_none());
    }

    #[test]
    fn wildcard_subdomain_does_not_match_apex() {
        let config = rules("[[web]]\ndomains = [\"*.github.com\"]\naction = \"allow\"\n");
        let compiled = compile(&config).unwrap();
        let apex = parse("https://github.com/x").unwrap();
        assert!(check_url(&compiled, &apex).is_none());
        let sub = parse("https://raw.github.com/x").unwrap();
        assert!(check_url(&compiled, &sub).is_some());
    }
}
