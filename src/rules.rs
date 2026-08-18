use crate::bash::{Command, Connector, Extraction, Word, basename, bin_path_basename};
use crate::config::{Action, BashRule, Config};
use regex::Regex;

struct Pattern {
    words: Vec<Regex>,
    // false for a bare `*` word — a wildcard captures a command's own
    // argument, it does not consume literal pattern text, so a rewrite must
    // never overwrite it
    literal: Vec<bool>,
    program_by_basename: bool,
}

pub struct CompiledBashRule<'a> {
    pub rule: &'a BashRule,
    patterns: Vec<Pattern>,
    contains: Vec<Regex>,
    only: Vec<Regex>,
    // every structural predicate on the rule, `piped_into` / `with` / `position`
    // included: they compile to graph queries here and are not evaluated
    // separately anywhere. ALL must hold.
    graph: Vec<GraphQuery>,
}

/// Which way a query walks the chain, starting from the matched command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    /// `--conn-->` — later stages
    Downstream,
    /// `<--conn--` — earlier stages
    Upstream,
    /// `<--conn-->` — either side
    Either,
}

/// Which connectors a step is allowed to cross.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnFilter {
    Only(Connector),
    Any,
}

/// One traversal: walk out from the matched command and ask whether anything
/// reached matches.
///
/// This is the single implementation issue #13's sub-task 9 asks for. Before it,
/// `piped_into`, `with` and `position` were three separate walks over the same
/// structure, each with its own idea of what "the next command" means — which is
/// how `piped_into` came to miss `a && b | c` (see [`reachable`]).
struct GraphQuery {
    dir: Dir,
    conn: ConnFilter,
    /// `+`: keep stepping while the connector still matches, instead of taking
    /// exactly one step
    transitive: bool,
    /// alternatives, OR'd — a comma-separated list in the written form
    patterns: Vec<Pattern>,
    /// `!`: the query must find nothing. `Unknown` stays `Unknown` — a
    /// neighbour we cannot read is no more disprovable than it was provable.
    negated: bool,
}

fn compile_pattern(source: &str) -> Result<Pattern, String> {
    let words = source
        .split_whitespace()
        .map(glob_to_regex)
        .collect::<Result<Vec<_>, _>>()?;
    if words.is_empty() {
        return Err("empty match pattern".to_string());
    }
    let literal = words.iter().map(|re| re.as_str() != "^.*$").collect();
    Ok(Pattern {
        words,
        literal,
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
            let graph =
                compile_graph(rule).map_err(|e| format!("bash rule '{}': {e}", rule.pattern))?;
            Ok(CompiledBashRule {
                rule,
                patterns,
                contains,
                only,
                graph,
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

/// Every structural predicate on one rule, as graph queries.
///
/// `piped_into`, `with` and `position` are kept as config spellings — they read
/// better than an arrow for the three cases they cover — but they are compiled
/// here into the same [`GraphQuery`] the written form produces, so there is one
/// traversal to get right and one place a bug in it can live.
fn compile_graph(rule: &BashRule) -> Result<Vec<GraphQuery>, String> {
    let mut out = rule
        .graph
        .iter()
        .map(|q| compile_graph_query(q))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(glob) = rule.piped_into.as_deref() {
        out.push(graph_query(
            "--pipe-->",
            vec![compile_pattern(glob)?],
            false,
        )?);
    }
    if !rule.with.is_empty() {
        let patterns = rule
            .with
            .iter()
            .map(|s| compile_pattern(s))
            .collect::<Result<Vec<_>, _>>()?;
        out.push(graph_query("<--any+-->", patterns, false)?);
    }
    match rule.position.as_deref() {
        None => {}
        // "standalone" is "nothing else in this chain", which is the negation of
        // the `with`-shaped query with a pattern that matches any command
        Some("only") => out.push(graph_query(
            "<--any+-->",
            vec![compile_pattern("*")?],
            true,
        )?),
        Some(other) => {
            return Err(format!(
                "unknown position '{other}' (only 'only' is supported)"
            ));
        }
    }
    Ok(out)
}

/// `[!]<arrow> <pattern>[, <pattern>…]`
fn compile_graph_query(source: &str) -> Result<GraphQuery, String> {
    let source = source.trim();
    let (negated, rest) = match source.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, source),
    };
    let (arrow, targets) = rest.split_once(char::is_whitespace).ok_or_else(|| {
        format!("graph query '{source}': expected `<arrow> <pattern>`, e.g. `--pipe--> head*`")
    })?;
    let patterns = split_alternatives(targets)
        .iter()
        .map(|p| compile_pattern(p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("graph query '{source}': {e}"))?;
    if patterns.is_empty() {
        return Err(format!(
            "graph query '{source}': no pattern after the arrow"
        ));
    }
    graph_query(arrow, patterns, negated)
}

/// The arrow half of a query: direction, which connectors it may cross, and
/// whether it steps once or as far as the connector holds.
fn graph_query(arrow: &str, patterns: Vec<Pattern>, negated: bool) -> Result<GraphQuery, String> {
    let upstream = arrow.starts_with('<');
    let body = arrow.strip_prefix('<').unwrap_or(arrow);
    let downstream = body.ends_with('>');
    let body = body.strip_suffix('>').unwrap_or(body);
    let dir = match (upstream, downstream) {
        (true, true) => Dir::Either,
        (true, false) => Dir::Upstream,
        (false, true) => Dir::Downstream,
        (false, false) => {
            return Err(format!(
                "graph arrow '{arrow}' points nowhere — write `--pipe-->`, `<--pipe--` or `<--pipe-->`"
            ));
        }
    };
    let name = body
        .strip_prefix("--")
        .and_then(|b| b.strip_suffix("--"))
        .ok_or_else(|| format!("unparseable graph arrow '{arrow}'"))?;
    let (name, transitive) = match name.strip_suffix('+') {
        Some(name) => (name, true),
        None => (name, false),
    };
    let conn = match name {
        "pipe" => ConnFilter::Only(Connector::Pipe),
        "and" => ConnFilter::Only(Connector::And),
        "or" => ConnFilter::Only(Connector::Or),
        "seq" => ConnFilter::Only(Connector::Seq),
        "any" => ConnFilter::Any,
        other => {
            return Err(format!(
                "unknown connector '{other}' in graph arrow '{arrow}' (pipe, and, or, seq, any)"
            ));
        }
    };
    Ok(GraphQuery {
        dir,
        conn,
        transitive,
        patterns,
        negated,
    })
}

// `,` separates alternatives; `\,` is a literal comma, the same escape
// `glob_to_regex` already understands, so a genuine comma in a word
// (`curl -H a\,b`) still reaches the glob compiler intact
fn split_alternatives(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = source.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                current.push('\\');
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ',' => out.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    out.push(current);
    out.retain(|s| !s.trim().is_empty());
    out.iter().map(|s| s.trim().to_string()).collect()
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
                if pattern.literal[i] {
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

// The connector joining position `at - 1` to position `at` in `group`. This is
// what `Command::connector` holds for every member of a chain except the first,
// which instead borrows the connector on its right (see `graph::Graph::groups`)
// — so position 0 answers `None` here and the walk below reads it as "there is
// nothing before me", which is exactly right.
fn connector_at(commands: &[Command], group: usize, at: usize) -> Option<Connector> {
    if at == 0 {
        return None;
    }
    commands
        .iter()
        .find(|c| c.group == group && c.position == at)
        .map(|c| c.connector)
}

fn crosses(filter: ConnFilter, connector: Option<Connector>) -> bool {
    match (filter, connector) {
        // Standalone is the absence of a connector, not a kind of one
        (_, None) | (_, Some(Connector::Standalone)) => false,
        (ConnFilter::Any, Some(_)) => true,
        (ConnFilter::Only(want), Some(got)) => want == got,
    }
}

/// Positions this query reaches from `command`, in its chain.
///
/// A step is taken only across a connector the query accepts, so `--pipe+-->`
/// from `a` in `a | b && c | d` stops at `b`: the `&&` is not a pipe and the
/// walk does not jump it.
///
/// Reading the connector **between** two stages, rather than the one the
/// starting command happens to carry, is what fixes `piped_into` on
/// `a && b | c`. The old check asked whether `b`'s own connector was a pipe; it
/// is `&&`, the one joining `b` to what came *before* it, so the rule silently
/// missed a pipeline that is plainly there.
fn reachable(query: &GraphQuery, commands: &[Command], command: &Command) -> Vec<usize> {
    let (group, len) = (command.group, command.group_len);
    let mut out = Vec::new();
    if query.dir != Dir::Upstream {
        let mut at = command.position;
        while at + 1 < len && crosses(query.conn, connector_at(commands, group, at + 1)) {
            at += 1;
            out.push(at);
            if !query.transitive {
                break;
            }
        }
    }
    if query.dir != Dir::Downstream {
        let mut at = command.position;
        while at > 0 && crosses(query.conn, connector_at(commands, group, at)) {
            at -= 1;
            out.push(at);
            if !query.transitive {
                break;
            }
        }
    }
    out
}

fn match_graph(query: &GraphQuery, commands: &[Command], command: &Command) -> Match {
    let mut best = Match::No;
    for position in reachable(query, commands, command) {
        // one position can hold several variants of the same site (`sudo rm` and
        // the wrapper-stripped `rm`); any of them matching is a hit
        for candidate in commands
            .iter()
            .filter(|c| c.group == command.group && c.position == position)
        {
            for pattern in &query.patterns {
                best = best.max(match_prefix(pattern, candidate));
            }
        }
    }
    if query.negated {
        match best {
            Match::Yes => Match::No,
            Match::No => Match::Yes,
            Match::Unknown => Match::Unknown,
        }
    } else {
        best
    }
}

// most-restrictive-wins rank for effect-verdict maps; mirrors the resolution
// order the gate gets for free from its collection mechanics
fn severity(action: Action) -> u8 {
    match action {
        Action::Deny => 6,
        Action::Skip => 5,
        Action::Ask => 4,
        Action::Warn => 3,
        Action::Rewrite => 2,
        Action::Log => 1,
        Action::Allow => 0,
    }
}

// what the command DOES, for `on = {...}` rules: its recipe's command-level
// effects plus the effects of every reference it makes (local and remote —
// `gh pr merge` writes a PR, `rm x` deletes a file; both count)
fn command_effects(extraction: &Extraction, command: &Command) -> Vec<crate::cmdmap::Effect> {
    let Some(start) = command.words.first().map(|w| w.start) else {
        return Vec::new();
    };
    let graph = &extraction.graph;
    let Some((id, node)) = graph
        .commands()
        .find(|(_, c)| c.spans.iter().any(|s| s.start == start))
    else {
        return Vec::new();
    };
    let mut out = node.effects.clone();
    for reference in graph.references() {
        if reference.command == id && !out.contains(&reference.effect) {
            out.push(reference.effect);
        }
    }
    out
}

// the action this rule contributes for THIS command: the effect-verdict map
// when one of the command's effects is spelled there, the flat `action`
// otherwise (also the fallback for commands the graph knows nothing about)
fn effective_action(rule: &CompiledBashRule, effects: &[crate::cmdmap::Effect]) -> Action {
    let Some(on) = &rule.rule.on else {
        return rule.rule.action;
    };
    effects
        .iter()
        .filter_map(|e| on.for_effect(*e))
        .max_by_key(|a| severity(*a))
        .unwrap_or(rule.rule.action)
}

pub fn match_command(rule: &CompiledBashRule, commands: &[Command], ci: usize) -> Match {
    let command = &commands[ci];
    let match_raw = matches!(rule.rule.action, Action::Deny)
        || rule.rule.on.as_ref().is_some_and(|on| on.any(Action::Deny));
    let mut best = Match::No;
    for pattern in &rule.patterns {
        let prefix = match_prefix(pattern, command);
        if prefix == Match::No {
            continue;
        }
        let contains = match_contains(&rule.contains, command, match_raw);
        let only = match_only(&rule.only, &command.words[pattern.words.len()..]);
        // every structural predicate the rule carries must hold
        let graph = rule
            .graph
            .iter()
            .map(|q| match_graph(q, commands, command))
            .min()
            .unwrap_or(Match::Yes);
        best = best.max(prefix.min(contains).min(only).min(graph));
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

// five rule sets plus where to evaluate them; no two travel together.
#[allow(clippy::too_many_arguments)]
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
    let skipped: Vec<bool> = (0..extraction.commands.len())
        .map(|ci| {
            rules.iter().any(|rule| {
                rule.rule.action == Action::Skip
                    && match_command(rule, &extraction.commands, ci) == Match::Yes
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
        let effects = command_effects(extraction, command);
        for rule in rules {
            let matched = match_command(rule, &extraction.commands, ci);
            if matched == Match::No || rule.rule.action == Action::Skip {
                continue;
            }
            let action = effective_action(rule, &effects);
            if (skipped[ci] || web_verdicts[ci].vetted) && action != Action::Deny {
                continue;
            }
            let display = command.display();
            match (action, matched) {
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
                    if command.synthetic || !command.rewritable {
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
    if !command.rewritable {
        return None;
    }
    let pattern = rule.patterns.first()?;
    // only the leading run of literal pattern words is safe to overwrite —
    // a wildcard captures the command's own argument and everything after
    // it (literal or not) is left verbatim in the source
    let literal_prefix_len = pattern.literal.iter().take_while(|&&lit| lit).count();
    if literal_prefix_len == 0 {
        return None;
    }
    let first = command.words.first()?;
    let last = command.words.get(literal_prefix_len - 1)?;
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

// six, three of them `&mut` out-params the caller owns.
#[allow(clippy::too_many_arguments)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;
    use crate::config::Config;

    // full rewrite pipeline: policy TOML -> gate() -> apply_edits(), asserting
    // the exact string that would land in updatedInput.command — golden tests
    // for issue #3 (wildcard-matched arguments must survive a rewrite)
    fn rewritten(policy: &str, command: &str) -> String {
        let config: Config = toml::from_str(policy).expect("test policy parses");
        let bash_rules = compile_bash_rules(&config).expect("bash rules compile");
        let web_rules = crate::web::compile(&config).expect("web rules compile");
        let extraction = bash::extract(command);
        let outcome = gate(&extraction, &bash_rules, &web_rules, &config, None);
        apply_edits(command, &outcome.edits)
    }

    #[test]
    fn rewrite_preserves_wildcard_matched_flag() {
        let policy = "[[bash]]\nmatch = \"grep *\"\naction = \"rewrite\"\nrewrite = \"rg\"\n";
        assert_eq!(
            rewritten(policy, "grep -n TODO src/main.rs"),
            "rg -n TODO src/main.rs"
        );
    }

    #[test]
    fn rewrite_preserves_wildcard_matched_pattern_arg() {
        let policy = "[[bash]]\nmatch = \"grep *\"\naction = \"rewrite\"\nrewrite = \"rg\"\n";
        assert_eq!(
            rewritten(policy, "grep TODO src/main.rs"),
            "rg TODO src/main.rs"
        );
    }

    #[test]
    fn rewrite_stops_at_first_wildcard_leaving_later_literal_words_untouched() {
        // `find` needs argument reordering to fully rewrite to `rg`, which is out of
        // scope here — phase 1 only guarantees no destruction of matched arguments
        let policy = "[[bash]]\nmatch = \"find * -name *\"\naction = \"rewrite\"\nrewrite = \"rg --files --glob\"\n";
        assert_eq!(
            rewritten(policy, "find . -name \"*.rs\""),
            "rg --files --glob . -name \"*.rs\""
        );
    }

    #[test]
    fn all_literal_pattern_rewrites_exactly_as_before() {
        let policy =
            "[[bash]]\nmatch = \"git commit\"\naction = \"rewrite\"\nrewrite = \"git ci\"\n";
        assert_eq!(rewritten(policy, "git commit"), "git ci");
    }

    #[test]
    fn find_exec_inner_command_is_not_spliced_into_the_outer_line() {
        // the inner `grep -n x {}` word spans index into the OUTER `find` source;
        // rewriting it would corrupt the enclosing command, so it must be refused
        let policy = "[[bash]]\nmatch = \"grep *\"\naction = \"rewrite\"\nrewrite = \"rg\"\n";
        let command = "find . -exec grep -n x {} \\;";
        assert_eq!(rewritten(policy, command), command);
    }

    // wraps a single predicate line in a `match = "*"` rule so the result of
    // `match_command` is driven purely by that predicate, then evaluates it
    // against the first command site extracted from `command` (the one named
    // in the issue #5 test matrix's "command" column)
    fn eval_predicate(predicate_toml: &str, command: &str) -> Match {
        eval_predicate_at(predicate_toml, command, 0)
    }

    fn eval_predicate_at(predicate_toml: &str, command: &str, ci: usize) -> Match {
        let policy = format!("[[bash]]\nmatch = \"*\"\naction = \"deny\"\n{predicate_toml}\n");
        let config: Config = toml::from_str(&policy).expect("test policy parses");
        let compiled = compile_bash_rules(&config).expect("rule compiles");
        let extraction = crate::bash::extract(command);
        match_command(&compiled[0], &extraction.commands, ci)
    }

    // the graph query is asked about a MIDDLE stage in several tests below, and
    // the extraction's index order is an implementation detail (variants, payload
    // commands); addressing by program name keeps the tests about the traversal
    fn eval_predicate_on(predicate_toml: &str, command: &str, program: &str) -> Match {
        let ci = crate::bash::extract(command)
            .commands
            .iter()
            .position(|c| c.words.first().and_then(|w| w.text.as_deref()) == Some(program))
            .unwrap_or_else(|| panic!("no `{program}` command in `{command}`"));
        eval_predicate_at(predicate_toml, command, ci)
    }

    #[test]
    fn piped_into_matches_pipe_adjacency_only() {
        let cases = [
            ("pnpm run build", Match::No),
            ("pnpm run build | head -5", Match::Yes),
            ("pnpm run build | tail -5", Match::No),
            ("git log && rm x", Match::No),
            ("git log || true", Match::No),
            // wrapper-stripped variant shares the raw variant's site, so
            // grouping survives `sudo` peeling
            ("sudo pnpm run build | head -5", Match::Yes),
        ];
        for (command, expected) in cases {
            let got = eval_predicate(r#"piped_into = "head*""#, command);
            assert_eq!(got, expected, "piped_into for `{command}`: got {got:?}");
        }
    }

    #[test]
    fn with_matches_any_other_command_in_the_chain() {
        let cases = [
            ("pnpm run build", Match::No),
            ("pnpm run build | head -5", Match::No),
            ("pnpm run build | tail -5", Match::No),
            ("git log && rm x", Match::Yes),
            ("git log || true", Match::No),
        ];
        for (command, expected) in cases {
            let got = eval_predicate(r#"with = ["rm*"]"#, command);
            assert_eq!(got, expected, "with for `{command}`: got {got:?}");
        }
    }

    #[test]
    fn position_only_matches_standalone_invocations() {
        let cases = [
            ("pnpm run build", Match::Yes),
            ("pnpm run build | head -5", Match::No),
            ("pnpm run build | tail -5", Match::No),
            ("git log && rm x", Match::No),
            ("git log || true", Match::No),
            ("sudo pnpm run build | head -5", Match::No),
        ];
        for (command, expected) in cases {
            let got = eval_predicate(r#"position = "only""#, command);
            assert_eq!(got, expected, "position=only for `{command}`: got {got:?}");
        }
    }

    #[test]
    fn absent_predicates_behave_like_before() {
        // no piped_into/with/position set -> those three axes must never
        // constrain the result; only `match`/`contains`/`only` matter
        let config: Config =
            toml::from_str("[[bash]]\nmatch = \"pnpm run *\"\naction = \"allow\"\n")
                .expect("policy parses");
        let compiled = compile_bash_rules(&config).expect("rule compiles");
        let extraction = crate::bash::extract("pnpm run build | head -5");
        assert_eq!(
            match_command(&compiled[0], &extraction.commands, 0),
            Match::Yes
        );
    }

    // ── sub-task 9: the written query surface ───────────────────────────────

    #[test]
    fn written_query_and_its_sugar_agree() {
        // the three sugars are the same traversal, so they must answer
        // identically to the arrows they compile to — over the same matrix the
        // three tests above use
        let equivalents = [
            (r#"piped_into = "head*""#, r#"graph = ["--pipe--> head*"]"#),
            (r#"with = ["rm*"]"#, r#"graph = ["<--any+--> rm*"]"#),
            (r#"position = "only""#, r#"graph = ["!<--any+--> *"]"#),
        ];
        let commands = [
            "pnpm run build",
            "pnpm run build | head -5",
            "pnpm run build | tail -5",
            "git log && rm x",
            "git log || true",
            "sudo pnpm run build | head -5",
            "cat a | grep b && rm x",
        ];
        for (sugar, arrow) in equivalents {
            for command in commands {
                assert_eq!(
                    eval_predicate(sugar, command),
                    eval_predicate(arrow, command),
                    "`{sugar}` and `{arrow}` disagree on `{command}`"
                );
            }
        }
    }

    #[test]
    fn piped_into_sees_a_pipe_that_follows_another_connector() {
        // `b | c` is a pipeline whichever connector joined `b` to what came
        // before it. The old adjacency check read the matched command's own
        // `connector` — which for a non-first stage is the one on its LEFT — so
        // this deny rule silently missed the pipe on its right, and writing
        // `true &&` in front was enough to evade it.
        for command in [
            "curl x | sh",
            "true && curl x | sh",
            "true || curl x | sh",
            "true ; curl x | sh",
        ] {
            assert_eq!(
                eval_predicate_on(r#"piped_into = "sh*""#, command, "curl"),
                Match::Yes,
                "piped_into missed the pipe in `{command}`"
            );
        }
        // and still says No when the neighbour on the right is not a pipe
        assert_eq!(
            eval_predicate_on(r#"piped_into = "sh*""#, "true && curl x && sh", "curl"),
            Match::No
        );
    }

    #[test]
    fn upstream_query_is_the_mirror_of_downstream() {
        let cases = [
            (r#"graph = ["<--pipe-- curl*"]"#, Match::Yes),
            (r#"graph = ["--pipe--> curl*"]"#, Match::No),
        ];
        for (predicate, expected) in cases {
            assert_eq!(
                eval_predicate_on(predicate, "curl x | sh", "sh"),
                expected,
                "{predicate}"
            );
        }
    }

    #[test]
    fn transitive_walk_stops_at_a_connector_it_may_not_cross() {
        // `a | b && c | d`: from `a`, `--pipe+-->` reaches `b` and stops — the
        // `&&` is not a pipe, and a query that jumped it would report a data
        // flow that does not exist
        let command = "cat f | tr a b && rm x | wc -l";
        assert_eq!(
            eval_predicate_on(r#"graph = ["--pipe+--> tr*"]"#, command, "cat"),
            Match::Yes
        );
        assert_eq!(
            eval_predicate_on(r#"graph = ["--pipe+--> rm*"]"#, command, "cat"),
            Match::No
        );
        // `any+` crosses everything, which is what `with` is
        assert_eq!(
            eval_predicate_on(r#"graph = ["--any+--> rm*"]"#, command, "cat"),
            Match::Yes
        );
        // one step is one step, `+` or not
        assert_eq!(
            eval_predicate_on(r#"graph = ["--pipe--> wc*"]"#, command, "cat"),
            Match::No
        );
    }

    #[test]
    fn several_queries_all_have_to_hold() {
        let both = r#"graph = ["<--pipe-- cat*", "--pipe--> wc*"]"#;
        assert_eq!(
            eval_predicate_on(both, "cat f | tr a b | wc -l", "tr"),
            Match::Yes
        );
        assert_eq!(
            eval_predicate_on(both, "cat f | tr a b | head -1", "tr"),
            Match::No
        );
    }

    #[test]
    fn comma_separates_alternatives_within_one_query() {
        for (command, expected) in [
            ("git log && rm x", Match::Yes),
            ("git log && dd if=/dev/zero of=x", Match::Yes),
            ("git log && true", Match::No),
        ] {
            assert_eq!(
                eval_predicate(r#"graph = ["<--any+--> rm*, dd*"]"#, command),
                expected,
                "alternatives for `{command}`"
            );
        }
    }

    #[test]
    fn a_dynamic_neighbour_is_unknown_negated_or_not() {
        // fail-closed, the `contains`/`only` convention: a stage we cannot read
        // neither proves nor disproves the query
        assert_eq!(
            eval_predicate(r#"graph = ["--pipe--> head*"]"#, "pnpm run build | $CMD"),
            Match::Unknown
        );
        assert_eq!(
            eval_predicate(r#"graph = ["!--pipe--> head*"]"#, "pnpm run build | $CMD"),
            Match::Unknown
        );
    }

    #[test]
    fn malformed_queries_are_compile_errors() {
        for bad in [
            r#"graph = ["--pipe-- head*"]"#,   // points nowhere
            r#"graph = ["--pipes--> head*"]"#, // unknown connector
            r#"graph = ["--pipe-->"]"#,        // no pattern
            r#"graph = ["head*"]"#,            // no arrow
            r#"graph = ["~~pipe~~> head*"]"#,  // not an arrow at all
        ] {
            let policy = format!("[[bash]]\nmatch = \"*\"\naction = \"deny\"\n{bad}\n");
            let config: Config = toml::from_str(&policy).expect("test policy parses");
            assert!(
                compile_bash_rules(&config).is_err(),
                "`{bad}` should not compile"
            );
        }
    }

    #[test]
    fn unknown_position_value_is_a_compile_error() {
        let config: Config =
            toml::from_str("[[bash]]\nmatch = \"*\"\naction = \"deny\"\nposition = \"first\"\n")
                .expect("policy parses");
        assert!(compile_bash_rules(&config).is_err());
    }
}
