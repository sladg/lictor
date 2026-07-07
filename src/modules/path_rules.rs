use super::Plan;
use crate::bash::Extraction;
use crate::config::{Action, Config, PathRule};
use crate::modules::jail;
use globset::{Glob, GlobSet, GlobSetBuilder};

// user-configured [[path]] rules: a glob list -> action + hint, matched against
// the filesystem paths the agent touches (Bash args, cd-aware; Write/Edit's
// file_path). The opinion — which dirs, what message — lives in config, not in
// Rust. Each glob is tested against BOTH the lexically-resolved path and its
// canonicalized (real_path) form, so one `/tmp/**` rule covers `/tmp/x`, macOS's
// `/private/tmp/x`, and relative spellings without per-alias entries. First
// matching rule wins, so a specific `allow` exception can precede a broad deny.

pub struct CompiledPathRule<'a> {
    rule: &'a PathRule,
    globs: GlobSet,
}

pub fn compile(config: &Config) -> Result<Vec<CompiledPathRule<'_>>, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    config
        .path
        .iter()
        .map(|rule| {
            let mut builder = GlobSetBuilder::new();
            for glob in &rule.globs {
                let expanded = expand_tilde(glob, &home);
                builder.add(Glob::new(&expanded).map_err(|e| format!("path rule: {e}"))?);
            }
            let globs = builder.build().map_err(|e| format!("path rule: {e}"))?;
            Ok(CompiledPathRule { rule, globs })
        })
        .collect()
}

fn expand_tilde(glob: &str, home: &str) -> String {
    match glob.strip_prefix("~/") {
        Some(rest) => format!("{home}/{rest}"),
        None if glob == "~" => home.to_string(),
        None => glob.to_string(),
    }
}

// first rule whose globs match the resolved path (either spelling); the rule's
// action + the message to surface (its hint, or a generic fallback).
fn match_path<'a>(rules: &[CompiledPathRule<'a>], resolved: &str) -> Option<(Action, String)> {
    let real = jail::real_path(resolved);
    rules.iter().find_map(|r| {
        (r.globs.is_match(resolved) || r.globs.is_match(&real)).then(|| {
            let message = r
                .rule
                .hint
                .clone()
                .unwrap_or_else(|| format!("lictor: `{resolved}` matches a [[path]] rule"));
            (r.rule.action, message)
        })
    })
}

// Bash: walk every literal path argument (cd-aware, including nested shells) and
// route the first matching rule's verdict into the plan.
pub fn plan(
    rules: &[CompiledPathRule],
    extraction: &Extraction,
    cwd: Option<&str>,
    plan: &mut Plan,
) {
    if rules.is_empty() {
        return;
    }
    let Some(cwd) = cwd else {
        return;
    };
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = jail::normalize(cwd, cwd, &home);
    let candidate_of = |text: &str| {
        let candidate = jail::path_candidate(text);
        jail::looks_like_path(candidate).then(|| candidate.to_string())
    };
    // path args (cd-aware, including nested shells), plus the two path-bearing
    // token classes the parser split off from `words`: `NAME=val` prefix values
    // (`D=/tmp/x cmd`) and write-redirect targets (`echo x > /tmp/y`)
    let mut candidates: Vec<String> = jail::walk_words(extraction, &cwd, &home, true, candidate_of)
        .into_iter()
        .map(|(_, resolved)| resolved)
        .collect();
    for raw in extraction
        .assignments
        .iter()
        .chain(&extraction.redirect_targets)
    {
        if jail::looks_like_path(raw) {
            candidates.push(jail::normalize(raw, &cwd, &home));
        }
    }

    let mut seen: Vec<String> = Vec::new();
    for resolved in candidates {
        if seen.contains(&resolved) {
            continue;
        }
        let Some((action, message)) = match_path(rules, &resolved) else {
            continue;
        };
        seen.push(resolved);
        match action {
            Action::Deny => plan.denies.push(message),
            Action::Ask => plan.asks.push(message),
            Action::Warn => plan.hints.push(message),
            // allow: explicit exception — matched, nothing to flag
            Action::Allow | Action::Log | Action::Rewrite | Action::Skip => {}
        }
    }
}

// Write/Edit/MultiEdit/NotebookEdit: a single already-known file_path.
pub fn check(rules: &[CompiledPathRule], path: &str, cwd: &str) -> Option<(Action, String)> {
    if rules.is_empty() {
        return None;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = jail::normalize(cwd, cwd, &home);
    let resolved = jail::normalize(path, &cwd, &home);
    match_path(rules, &resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    const CWD: &str = "/Users/nobody/project";

    fn config(rules: &str) -> Config {
        toml::from_str(rules).expect("config parses")
    }

    fn plan_bash(rules_toml: &str, command: &str) -> Plan {
        let config = config(rules_toml);
        let compiled = compile(&config).expect("globs compile");
        let mut out = Plan::default();
        super::plan(&compiled, &bash::extract(command), Some(CWD), &mut out);
        out
    }

    const TEMP: &str = "[[path]]\nmatch = [\"/tmp/**\", \"/private/tmp/**\"]\naction = \"deny\"\nhint = \"use .claude/scratch/ or kv\"\n";

    #[test]
    fn temp_bash_arg_denied_with_custom_hint() {
        let plan = plan_bash(TEMP, "cp notes.txt /tmp/notes.txt");
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
        assert!(plan.denies[0].contains(".claude/scratch/"));
    }

    #[test]
    fn private_tmp_alias_matched_by_tmp_glob() {
        // `/tmp/x` canonicalizes to `/private/tmp/x` on macOS; a `/tmp/**` glob
        // still catches it because match tests both the lexical and real path
        let plan = plan_bash(
            "[[path]]\nmatch = [\"/tmp/**\"]\naction = \"deny\"\n",
            "touch /tmp/scratch",
        );
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
    }

    #[test]
    fn scratch_var_assignment_matched() {
        // the `D=/private/tmp/...` scratchpad-exploit shape (corpus §6): the path
        // is a NAME=val prefix the parser split off, not a plain arg
        let plan = plan_bash(
            TEMP,
            "D=/private/tmp/claude-501/scratchpad/exploit cargo build",
        );
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
        assert!(plan.denies[0].contains(".claude/scratch/"));
    }

    #[test]
    fn redirect_target_matched() {
        // `> /tmp/x` is a redirect target — neither a word nor an assignment
        assert_eq!(plan_bash(TEMP, "echo secret > /tmp/leak").denies.len(), 1);
        assert_eq!(
            plan_bash(TEMP, "make build >> /tmp/out.log").denies.len(),
            1
        );
        // chained: tree-sitter binds the trailing redirect to the enclosing list
        assert_eq!(
            plan_bash(TEMP, "cargo build && echo done > /tmp/done")
                .denies
                .len(),
            1
        );
    }

    #[test]
    fn harmless_redirects_not_flagged() {
        // /dev/null and fd dups (2>&1) are not scratch paths
        assert!(plan_bash(TEMP, "cmd > /dev/null 2>&1").denies.is_empty());
        // a read redirect from an unrelated path isn't a temp write
        assert!(plan_bash(TEMP, "cmd < input.txt").denies.is_empty());
    }

    #[test]
    fn nested_shell_redirect_matched() {
        // an evasion hiding the redirect inside `bash -c '...'` is still caught
        assert_eq!(
            plan_bash(TEMP, "bash -c 'echo x > /tmp/nested'")
                .denies
                .len(),
            1
        );
    }

    #[test]
    fn export_assignment_matched() {
        // `export VAR=/tmp/x` — the path rides on an assignment word
        assert_eq!(plan_bash(TEMP, "export OUT=/tmp/build").denies.len(), 1);
    }

    #[test]
    fn tilde_glob_expands_to_home() {
        let home = std::env::var("HOME").unwrap_or_default();
        let plan = plan_bash(
            "[[path]]\nmatch = [\"~/.ssh/**\"]\naction = \"ask\"\n",
            &format!("cat {home}/.ssh/id_rsa"),
        );
        assert_eq!(plan.asks.len(), 1, "{:?}", plan.asks);
    }

    #[test]
    fn first_match_wins_allow_exception_precedes_deny() {
        let rules = "[[path]]\nmatch = [\"/tmp/ok/**\"]\naction = \"allow\"\n\n[[path]]\nmatch = [\"/tmp/**\"]\naction = \"deny\"\n";
        // the allowed subdir is carved out...
        assert!(plan_bash(rules, "touch /tmp/ok/keep").denies.is_empty());
        // ...while the broad deny still covers everything else
        assert_eq!(plan_bash(rules, "touch /tmp/other").denies.len(), 1);
    }

    #[test]
    fn action_channels() {
        let warn = "[[path]]\nmatch = [\"/tmp/**\"]\naction = \"warn\"\n";
        assert_eq!(plan_bash(warn, "touch /tmp/x").hints.len(), 1);
        let ask = "[[path]]\nmatch = [\"/tmp/**\"]\naction = \"ask\"\n";
        assert_eq!(plan_bash(ask, "touch /tmp/x").asks.len(), 1);
    }

    #[test]
    fn unmatched_path_untouched() {
        let plan = plan_bash(TEMP, "cat src/main.rs");
        assert!(plan.denies.is_empty() && plan.asks.is_empty() && plan.hints.is_empty());
    }

    #[test]
    fn no_rules_is_noop() {
        let plan = plan_bash("", "touch /tmp/x");
        assert!(plan.denies.is_empty());
    }

    #[test]
    fn write_path_checked() {
        let config = config(TEMP);
        let compiled = compile(&config).expect("globs compile");
        let hit = check(&compiled, "/tmp/notes.txt", CWD);
        assert!(hit.is_some());
        let (action, message) = hit.unwrap();
        assert_eq!(action, Action::Deny);
        assert!(message.contains(".claude/scratch/"));
    }
}
