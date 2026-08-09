use super::{ModuleCtx, Plan};
use crate::config::{Action, Config, PathRule};
use crate::modules::{jail, path_rules, recreate};

// `[[delete]]` rules: the same glob-list-to-verdict shape as `[[path]]`, but
// scoped to paths a command actually *removes*.
//
// `[[path]]` fires on any command that merely names a path, so "never delete
// `src/migrations/**`" could previously only be written as a blunt deny on `rm`
// — which also blocks `rm` everywhere else, and still misses `unlink`. Deletion
// is the case where "don't touch this" is most often meant literally, and where
// getting it wrong is least recoverable.
//
// What counts as a deletion is `recreate::deletion_targets`, shared rather than
// re-derived: `rm`, `unlink`, `rmdir` and `git rm` (not `--cached`). A dynamic
// word anywhere in the command means it abstains rather than guesses, matching
// the convention everywhere else.

pub fn compile(config: &Config) -> Result<Vec<path_rules::CompiledPathRule<'_>>, String> {
    path_rules::compile_rules(&config.delete, "delete rule")
}

/// Bash: route each deleted path's first matching rule into the plan.
pub fn plan(rules: &[path_rules::CompiledPathRule], ctx: &ModuleCtx, out: &mut Plan) {
    if rules.is_empty() {
        return;
    }
    let Some(cwd) = ctx.cwd else {
        return;
    };
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = jail::normalize(cwd, cwd, &home);

    let mut seen: Vec<String> = Vec::new();
    for command in &ctx.extraction.commands {
        // synthetic commands are re-parsed inner scripts (`bash -c 'rm x'`);
        // a deletion there is still a deletion
        for target in recreate::deletion_targets(command) {
            let resolved = jail::normalize(&target, &cwd, &home);
            if seen.contains(&resolved) {
                continue;
            }
            let Some((action, message)) = match_deleted(rules, &resolved) else {
                continue;
            };
            seen.push(resolved);
            route(action, message, out);
        }
    }
}

/// The tool side: a `Delete`-shaped tool call naming one already-known path.
pub fn check(
    rules: &[path_rules::CompiledPathRule],
    path: &str,
    cwd: &str,
) -> Option<(Action, String)> {
    if rules.is_empty() {
        return None;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = jail::normalize(cwd, cwd, &home);
    match_deleted(rules, &jail::normalize(path, &cwd, &home))
}

/// A rule's verdict for one deleted path.
///
/// Matches the path itself, and also fires when the path is a **directory whose
/// contents the rule protects** — `rm -rf src/migrations` removes everything a
/// `**/src/migrations/**` rule was written to defend, and a delete rule that
/// missed that would be defeated by the most obvious bypass there is.
///
/// globset cannot answer "could this glob match anything under X", so that
/// second case is probed with synthetic descendants. Two consequences, both
/// deliberate:
///
/// - it over-approximates, in the safe direction for a rule about deletion:
///   a glob that *could* match something beneath the path fires even if no such
///   file exists
/// - it under-approximates on contents: `rm -rf logs/` is not caught by a
///   `**/*.lock` rule even when `logs/` happens to contain one, because knowing
///   that needs the filesystem, and a rule engine that stats the disk is racy
///   and slow. Name the directory to protect it.
fn match_deleted<'a>(
    rules: &[path_rules::CompiledPathRule<'a>],
    resolved: &str,
) -> Option<(Action, String)> {
    if let Some(rule) = path_rules::find_rule(rules, resolved) {
        let message = rule
            .hint
            .clone()
            .unwrap_or_else(|| format!("lictor: deleting `{resolved}` matches a [[delete]] rule"));
        return Some((rule.action, message));
    }
    let rule = DESCENDANT_PROBES
        .iter()
        .find_map(|probe| path_rules::find_rule(rules, &format!("{resolved}/{probe}")))?;
    // the probe path is synthetic, so it must never reach the message — the
    // user's own hint is the actionable text either way
    let message = rule.hint.clone().unwrap_or_else(|| {
        format!("lictor: deleting `{resolved}` would remove paths a [[delete]] rule protects")
    });
    Some((rule.action, message))
}

// three depths is enough for the globs people actually write (`dir/**`,
// `dir/*/x`); more only costs time for no extra coverage
const DESCENDANT_PROBES: &[&str] = &["\u{1}", "\u{1}/\u{1}", "\u{1}/\u{1}/\u{1}"];

fn route(action: Action, message: String, out: &mut Plan) {
    match action {
        Action::Deny => out.denies.push(message),
        Action::Ask => out.asks.push(message),
        Action::Warn => out.hints.push(message),
        // allow: an explicit exception that matched — nothing to flag. Ordering
        // matters, so a narrow allow can precede a broad deny.
        Action::Allow | Action::Log | Action::Rewrite | Action::Skip => {}
    }
}

/// Deletion rules only make sense against paths, so reject the actions that
/// have no meaning here rather than silently ignoring them at match time.
pub fn validate(rules: &[PathRule]) -> Result<(), String> {
    for rule in rules {
        if matches!(rule.action, Action::Rewrite | Action::Skip | Action::Log) {
            return Err(format!(
                "delete rule: action `{:?}` is not supported — use deny, ask, warn or allow",
                rule.action
            ));
        }
    }
    Ok(())
}
