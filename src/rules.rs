use crate::bash::{Command, Extraction, Word, basename, bin_path_basename};
use crate::config::{Action, BashRule, Config};
use regex::Regex;

struct Pattern {
    words: Vec<Regex>,
    program_by_basename: bool,
}

pub struct CompiledBashRule<'a> {
    pub rule: &'a BashRule,
    patterns: Vec<Pattern>,
    contains: Vec<Regex>,
    only: Vec<Regex>,
}

fn compile_pattern(source: &str) -> Result<Pattern, String> {
    let words = source
        .split_whitespace()
        .map(glob_to_regex)
        .collect::<Result<Vec<_>, _>>()?;
    if words.is_empty() {
        return Err("empty match pattern".to_string());
    }
    Ok(Pattern {
        words,
        program_by_basename: !source.starts_with('/'),
    })
}

pub fn compile_bash_rules(config: &Config) -> Result<Vec<CompiledBashRule<'_>>, String> {
    config
        .bash
        .iter()
        .map(|rule| {
            let patterns = vec![
                compile_pattern(&rule.pattern)
                    .map_err(|e| format!("bash rule '{}': {e}", rule.pattern))?,
            ];
            let contains = rule
                .contains
                .iter()
                .map(|g| glob_to_regex(g))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("bash rule '{}': {e}", rule.pattern))?;
            let only = rule
                .only
                .iter()
                .map(|g| glob_to_regex(g))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("bash rule '{}': {e}", rule.pattern))?;
            Ok(CompiledBashRule {
                rule,
                patterns,
                contains,
                only,
            })
        })
        .collect()
}

pub fn glob_to_regex(glob: &str) -> Result<Regex, String> {
    let mut pattern = String::from("^");
    let mut chars = glob.chars();
    while let Some(c) = chars.next() {
        match c {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            // `\*` / `\?` / `\\` match the literal character (`*$\?` = ends in "$?")
            '\\' => {
                let next = chars.next().unwrap_or('\\');
                pattern.push_str(&regex::escape(&next.to_string()));
            }
            c => pattern.push_str(&regex::escape(&c.to_string())),
        }
    }
    pattern.push('$');
    Regex::new(&pattern).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Match {
    No,
    Unknown,
    Yes,
}

fn match_prefix(pattern: &Pattern, command: &Command) -> Match {
    if command.words.len() < pattern.words.len() {
        return Match::No;
    }
    let mut unknown = false;
    for (i, word_re) in pattern.words.iter().enumerate() {
        match command.words[i].text.as_deref() {
            Some(text) => {
                let candidate = if i == 0 && pattern.program_by_basename {
                    basename(text)
                } else {
                    text
                };
                if !word_re.is_match(candidate) {
                    return Match::No;
                }
            }
            None => {
                if word_re.as_str() != "^.*$" {
                    unknown = true;
                }
            }
        }
    }
    if unknown { Match::Unknown } else { Match::Yes }
}

// any of the contains globs matching any argument after the program (flag bans,
// order-independent); dynamic arguments make the result Unknown, not No
fn match_contains(contains: &[Regex], command: &Command, match_raw: bool) -> Match {
    if contains.is_empty() {
        return Match::Yes;
    }
    let mut has_dynamic = false;
    for word in command.words.iter().skip(1) {
        match word.text.as_deref() {
            Some(text) => {
                if contains.iter().any(|re| re.is_match(text)) {
                    return Match::Yes;
                }
            }
            None => {
                // a dynamic value is unknowable, but a glob hit on the raw source
                // (`echo "EXIT: $?"` vs `*$\?*`) means the banned token is literally
                // present — a definite hit. Deny rules only: syntax can't vet an allow.
                if match_raw
                    && word
                        .raw
                        .as_deref()
                        .is_some_and(|raw| contains.iter().any(|re| re.is_match(raw)))
                {
                    return Match::Yes;
                }
                has_dynamic = true;
            }
        }
    }
    if has_dynamic {
        Match::Unknown
    } else {
        Match::No
    }
}

// EVERY argument must match one of the `only` globs (strict allowlist);
// a dynamic argument can't be checked -> Unknown
fn match_only(only: &[Regex], args: &[Word]) -> Match {
    if only.is_empty() {
        return Match::Yes;
    }
    let mut unknown = false;
    for word in args {
        match word.text.as_deref() {
            Some(text) => {
                if !only.iter().any(|re| re.is_match(text)) {
                    return Match::No;
                }
            }
            None => unknown = true,
        }
    }
    if unknown { Match::Unknown } else { Match::Yes }
}

pub fn match_command(rule: &CompiledBashRule, command: &Command) -> Match {
    let match_raw = matches!(rule.rule.action, Action::Deny);
    let mut best = Match::No;
    for pattern in &rule.patterns {
        let prefix = match_prefix(pattern, command);
        if prefix == Match::No {
            continue;
        }
        let contains = match_contains(&rule.contains, command, match_raw);
        let only = match_only(&rule.only, &command.words[pattern.words.len()..]);
        best = best.max(prefix.min(contains).min(only));
    }
    best
}

#[derive(Debug, Clone)]
pub struct SpanEdit {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

#[derive(Debug, Default)]
pub struct GateOutcome {
    pub decision: Option<&'static str>,
    pub reason: Option<String>,
    pub edits: Vec<SpanEdit>,
    pub hints: Vec<String>,
    // command indices vetted by allow/rewrite rules; wrap coverage is unioned in by the engine
    pub vetted: Vec<usize>,
    // (rule pattern, subject) pairs from action = "log" rules, for the audit log
    pub logged: Vec<(String, String)>,
    // path-normalization rewrites; applied to updatedInput but never affect the decision
    pub cosmetic_edits: Vec<SpanEdit>,
    // (rule key, retry_count, retry_window) of the deny rule that fired, when
    // it carries a deny-then-allow retry policy
    pub deny_retry: Option<(String, u32, u64)>,
    // (rule key, retry_count, retry_window, hint_message) of the warn rule that fired,
    // when it carries a hint-then-allow retry policy; message is stored so only that
    // specific hint is suppressed once the threshold is reached
    pub hint_retry: Option<(String, u32, u64, String)>,
}

// a chain auto-approves only when every site has a vetted variant
pub fn site_coverage(extraction: &Extraction, vetted: &[usize]) -> bool {
    if extraction.commands.is_empty() {
        return false;
    }
    for command in &extraction.commands {
        let mut covered = false;
        for (i, other) in extraction.commands.iter().enumerate() {
            if other.site == command.site && vetted.contains(&i) {
                covered = true;
                break;
            }
        }
        if !covered {
            return false;
        }
    }
    true
}

pub fn gate(
    extraction: &Extraction,
    rules: &[CompiledBashRule],
    web_rules: &[crate::web::CompiledWebRule],
    config: &Config,
    cwd: Option<&str>,
) -> GateOutcome {
    let mut outcome = GateOutcome::default();
    let mut rewritten: Vec<usize> = Vec::new();
    let mut allowed: Vec<usize> = Vec::new();
    let mut allow_reasons: Vec<String> = Vec::new();
    let mut deny_hit: Option<String> = None;
    let mut unknown_hit: Option<String> = None;
    let mut ask_hit: Option<String> = None;
    let mut synthetic_rewrite: Option<String> = None;

    // a command a `skip` rule confidently matches is exempted from every OTHER
    // rule's ask/warn/log/allow/rewrite verdict — only an explicit `deny`
    // elsewhere still wins. Lets a narrow rule carve an exception out of a
    // broad catalog (e.g. one `rm` pattern out of `mutating`'s blanket ask),
    // handing the decision back to Claude Code's own permission rules.
    let skipped: Vec<bool> = extraction
        .commands
        .iter()
        .map(|command| {
            rules.iter().any(|rule| {
                rule.rule.action == Action::Skip && match_command(rule, command) == Match::Yes
            })
        })
        .collect();

    // [[web]] verdicts, computed first: a fully-vetted command (every URL on an
    // allow rule, all words static) is exempted from other rules' ask/warn — the
    // verified URL is the vetting they'd ask for. An explicit deny still wins.
    let web_verdicts: Vec<crate::web::CommandVerdict> = extraction
        .commands
        .iter()
        .map(|command| crate::web::gate_command(web_rules, command))
        .collect();

    // collect matches for every (command, rule) pair first; severity decides afterwards,
    // so config order can't let an ask/allow rule shadow a deny
    for (ci, command) in extraction.commands.iter().enumerate() {
        for rule in rules {
            let matched = match_command(rule, command);
            if matched == Match::No || rule.rule.action == Action::Skip {
                continue;
            }
            if (skipped[ci] || web_verdicts[ci].vetted) && rule.rule.action != Action::Deny {
                continue;
            }
            let display = command.display();
            match (rule.rule.action, matched) {
                (Action::Deny, Match::Yes) => {
                    deny_hit.get_or_insert(rule.rule.reason.clone().unwrap_or(format!(
                        "lictor: `{display}` is banned by rule `{}`",
                        rule.rule.pattern
                    )));
                    if let (Some(n), Some(w)) = (rule.rule.retry_count, rule.rule.retry_window) {
                        outcome
                            .deny_retry
                            .get_or_insert((rule.rule.pattern.clone(), n, w));
                    }
                }
                (Action::Deny | Action::Ask, Match::Unknown) => {
                    unknown_hit.get_or_insert(format!(
                        "lictor: cannot statically verify `{display}` against rule `{}`",
                        rule.rule.pattern
                    ));
                }
                (Action::Ask, Match::Yes) => {
                    ask_hit.get_or_insert(rule.rule.reason.clone().unwrap_or(format!(
                        "lictor: `{display}` matches ask rule `{}`",
                        rule.rule.pattern
                    )));
                }
                (Action::Rewrite, Match::Yes) => {
                    if command.synthetic {
                        synthetic_rewrite.get_or_insert(format!(
                            "lictor: `{display}` matches rewrite rule `{}` inside a nested shell string; rewrite it manually",
                            rule.rule.pattern
                        ));
                    } else if let Some(edit) = rewrite_edit(rule, command) {
                        outcome.edits.push(edit);
                        push_hint(&mut outcome.hints, rewrite_hint(rule, &display));
                        rewritten.push(ci);
                    }
                }
                (Action::Allow, Match::Yes) => {
                    // an output redirect turns a read-only command into a write; don't vet it
                    if !command.redirects_output {
                        allowed.push(ci);
                        if let Some(reason) = &rule.rule.reason {
                            allow_reasons.push(reason.clone());
                        }
                    }
                }
                (Action::Warn, Match::Yes) => {
                    let hint = rule.rule.hint.clone().unwrap_or(format!(
                        "lictor: `{display}` matches warn rule `{}`",
                        rule.rule.pattern
                    ));
                    push_hint(&mut outcome.hints, hint);
                }
                (Action::Log, Match::Yes) => {
                    let entry = (rule.rule.pattern.clone(), display);
                    if !outcome.logged.contains(&entry) {
                        outcome.logged.push(entry);
                    }
                }
                (Action::Rewrite | Action::Allow | Action::Warn | Action::Log, Match::Unknown) => {}
                // filtered out above (Skip never reaches here, No never survives the continue)
                (Action::Skip, _) | (_, Match::No) => unreachable!(),
            }
        }
    }

    for (ci, verdict) in web_verdicts.into_iter().enumerate() {
        if let Some(reason) = verdict.deny {
            deny_hit.get_or_insert(reason);
            continue;
        }
        if skipped[ci] {
            continue;
        }
        if let Some(reason) = verdict.ask {
            ask_hit.get_or_insert(reason);
        }
        for hint in verdict.hints {
            push_hint(&mut outcome.hints, hint);
        }
        if verdict.vetted {
            allowed.push(ci);
            allow_reasons.extend(verdict.allow_reasons);
        }
    }

    if let Some(action) = config.strip_program_paths() {
        strip_program_paths(
            extraction,
            action,
            config,
            &mut outcome,
            &mut deny_hit,
            &mut ask_hit,
        );
    }

    if let (Some(action), Some(cwd)) = (config.jail(), cwd) {
        for path in crate::modules::jail::violations(extraction, config, cwd) {
            let message = format!(
                "lictor: `{path}` is outside the project jail — stay in the repo or have the user extend settings.jail_allow"
            );
            match action {
                Action::Allow | Action::Log | Action::Skip => {}
                Action::Warn => push_hint(&mut outcome.hints, message),
                Action::Ask => {
                    ask_hit.get_or_insert(message);
                }
                // rewrite has no meaning for a jail violation; treat as deny
                Action::Deny | Action::Rewrite => {
                    deny_hit.get_or_insert(message);
                }
            }
        }
    }

    if let Some(reason) = deny_hit {
        return finish(outcome, "deny", reason);
    }
    if let Some(reason) = unknown_hit {
        return finish(outcome, "ask", reason);
    }
    if let Some(reason) = &extraction.device_write {
        return finish(outcome, "deny", format!("lictor: {reason}"));
    }
    if let Some(reason) = &extraction.obfuscation {
        let message = format!("lictor: {reason}");
        match config.on_obfuscation() {
            Action::Skip => {}
            Action::Allow | Action::Warn | Action::Log => push_hint(&mut outcome.hints, message),
            Action::Ask => return finish(outcome, "ask", message),
            _ => return finish(outcome, "deny", message),
        }
    }
    if let Some(reason) = &extraction.dangerous_env {
        let message = format!("lictor: {reason}");
        match config.on_dangerous_env() {
            Action::Skip => {}
            Action::Allow | Action::Warn | Action::Log => push_hint(&mut outcome.hints, message),
            Action::Ask => return finish(outcome, "ask", message),
            _ => return finish(outcome, "deny", message),
        }
    }
    for (ci, command) in extraction.commands.iter().enumerate() {
        let Some(inline) = &command.inline else {
            continue;
        };
        if allowed.contains(&ci) {
            continue;
        }
        let message = format!("lictor: `{}`: {inline}", command.display());
        match config.on_inline_script() {
            Action::Deny => return finish(outcome, "deny", message),
            Action::Skip => {}
            Action::Allow | Action::Warn | Action::Log => push_hint(&mut outcome.hints, message),
            _ => return finish(outcome, "ask", message),
        }
    }
    if let Some(action) = config.on_shell_write() {
        let authored = extraction.commands.iter().find(|c| {
            !c.synthetic
                && c.redirects_output
                && c.words.first().is_some_and(|w| {
                    w.text
                        .as_deref()
                        .is_some_and(|p| crate::constants::CONTENT_EMITTERS.contains(&basename(p)))
                })
        });
        if let Some(command) = authored {
            let message = format!(
                "lictor: `{}` authors a file via shell redirection — use the Write/Edit tool instead",
                command.display()
            );
            match action {
                Action::Allow | Action::Log | Action::Skip => {}
                Action::Warn => push_hint(&mut outcome.hints, message),
                Action::Ask => return finish(outcome, "ask", message),
                _ => return finish(outcome, "deny", message),
            }
        }
    }
    if let Some(reason) = &extraction.blocked_reason {
        let message = format!("lictor: {reason}");
        match config.on_unparseable() {
            Action::Deny => return finish(outcome, "deny", message),
            Action::Skip => {}
            Action::Allow | Action::Warn | Action::Log => push_hint(&mut outcome.hints, message),
            _ => return finish(outcome, "ask", message),
        }
    }
    if let Some(reason) = ask_hit {
        return finish(outcome, "ask", reason);
    }
    if let Some(reason) = synthetic_rewrite {
        return finish(outcome, "ask", reason);
    }

    outcome.vetted = rewritten;
    outcome.vetted.extend(allowed);
    let full_coverage = site_coverage(extraction, &outcome.vetted);
    if !outcome.edits.is_empty() {
        outcome.decision = Some(if full_coverage { "allow" } else { "ask" });
        outcome.reason = Some(outcome.hints.join(" | "));
    } else if full_coverage {
        outcome.decision = Some("allow");
        if !allow_reasons.is_empty() {
            outcome.reason = Some(allow_reasons.join(" | "));
        }
    }
    outcome
}

fn rewrite_edit(rule: &CompiledBashRule, command: &Command) -> Option<SpanEdit> {
    let replacement = rule.rule.rewrite.as_deref()?;
    let pattern_len = rule.patterns.first()?.words.len();
    let first = command.words.first()?;
    let last = command.words.get(pattern_len - 1)?;
    Some(SpanEdit {
        start: first.start,
        end: last.end,
        text: replacement.to_string(),
    })
}

fn rewrite_hint(rule: &CompiledBashRule, display: &str) -> String {
    rule.rule.hint.clone().unwrap_or(format!(
        "lictor: rewrote `{display}` per rule `{}` -> `{}`",
        rule.rule.pattern,
        rule.rule.rewrite.as_deref().unwrap_or("")
    ))
}

fn push_hint(hints: &mut Vec<String>, hint: String) {
    if !hints.contains(&hint) {
        hints.push(hint);
    }
}

fn strip_program_paths(
    extraction: &Extraction,
    action: Action,
    config: &Config,
    outcome: &mut GateOutcome,
    deny_hit: &mut Option<String>,
    ask_hit: &mut Option<String>,
) {
    let bin_dirs = config.bin_dirs();
    let mut seen: Vec<(usize, usize)> = Vec::new();
    for command in &extraction.commands {
        if command.synthetic {
            continue;
        }
        let Some(word) = command.words.first() else {
            continue;
        };
        let Some(program) = word.text.as_deref() else {
            continue;
        };
        let Some(base) = bin_path_basename(program, &bin_dirs) else {
            continue;
        };
        let span = (word.start, word.end);
        if seen.contains(&span) {
            continue;
        }
        seen.push(span);
        let base = base.to_string();
        match action {
            Action::Rewrite => {
                outcome.cosmetic_edits.push(SpanEdit {
                    start: word.start,
                    end: word.end,
                    text: base.clone(),
                });
                push_hint(
                    &mut outcome.hints,
                    format!("lictor: shortened `{program}` -> `{base}`"),
                );
            }
            Action::Warn => push_hint(
                &mut outcome.hints,
                format!("lictor: avoid bin-path programs like `{program}`; use `{base}`"),
            ),
            Action::Ask => {
                ask_hit.get_or_insert(format!(
                    "lictor: bin-path program `{program}` — invoke `{base}` directly"
                ));
            }
            Action::Deny => {
                deny_hit.get_or_insert(format!(
                    "lictor: bin-path program `{program}` is banned; invoke `{base}` directly"
                ));
            }
            Action::Allow | Action::Log | Action::Skip => {}
        }
    }
}

// hard verdicts drop pending edits/hints but keep audit entries
fn finish(mut outcome: GateOutcome, decision: &'static str, reason: String) -> GateOutcome {
    outcome.decision = Some(decision);
    outcome.reason = Some(reason);
    outcome.edits.clear();
    outcome.cosmetic_edits.clear();
    outcome.hints.clear();
    outcome.vetted.clear();
    outcome
}

pub fn apply_edits(source: &str, edits: &[SpanEdit]) -> String {
    let mut sorted = edits.to_vec();
    sorted.sort_by_key(|e| std::cmp::Reverse((e.start, e.end)));
    sorted.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.text == b.text);
    let mut result = source.to_string();
    for edit in sorted {
        result.replace_range(edit.start..edit.end, &edit.text);
    }
    result
}
