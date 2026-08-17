use super::{ModuleCtx, Plan};
use crate::cmdmap::Effect;
use crate::config::{Action, Config, JailPaths, PathRule};
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
    compile_rules(&config.path, "path rule")
}

// shared with `[[delete]]`, which is the same glob-list-to-verdict shape applied
// to a narrower set of paths. `label` names the block in error messages so a bad
// glob points at the right one.
pub(crate) fn compile_rules<'a>(
    rules: &'a [PathRule],
    label: &str,
) -> Result<Vec<CompiledPathRule<'a>>, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    rules
        .iter()
        .map(|rule| {
            if rule.on.as_deref() == Some(&[]) {
                return Err(format!(
                    "[[{label}]] rule: 'on = []' matches nothing — omit 'on' to match every effect"
                ));
            }
            let mut builder = GlobSetBuilder::new();
            for glob in &rule.globs {
                let expanded = expand_tilde(glob, &home);
                builder.add(Glob::new(&expanded).map_err(|e| format!("{label}: {e}"))?);
            }
            let globs = builder.build().map_err(|e| format!("{label}: {e}"))?;
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
// the rule itself, so callers that build their own message (delete rules, whose
// reason depends on whether the path matched directly) don't have to unpick one
pub(crate) fn find_rule<'a>(
    rules: &[CompiledPathRule<'a>],
    resolved: &str,
) -> Option<&'a PathRule> {
    let real = jail::real_path(resolved);
    rules
        .iter()
        .find(|r| r.globs.is_match(resolved) || r.globs.is_match(&real))
        .map(|r| r.rule)
}

// `candidate_effects`: what this path is known to undergo (`None` = unknown,
// i.e. a heuristic candidate). Eligibility:
//   rule.on=None       → always eligible
//   rule.on=Some(_)    + candidate None    → not eligible (on is graph-only)
//   rule.on=Some(set)  + candidate Some(e) → eligible iff the two sets intersect
fn match_path<'a>(
    rules: &[CompiledPathRule<'a>],
    resolved: &str,
    candidate_effects: Option<&[Effect]>,
) -> Option<(Action, String)> {
    let real = jail::real_path(resolved);
    rules.iter().find_map(|r| {
        let eligible = match (&r.rule.on, candidate_effects) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(rule_on), Some(candidate)) => rule_on.iter().any(|e| candidate.contains(e)),
        };
        if !eligible {
            return None;
        }
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
pub fn plan(rules: &[CompiledPathRule], ctx: &ModuleCtx, out: &mut Plan) {
    if rules.is_empty() {
        return;
    }
    let Some(cwd) = ctx.cwd else {
        return;
    };
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = jail::normalize(cwd, cwd, &home);

    // (absolute_path, effects_or_none): graph arm knows effects; heuristic doesn't
    let candidates: Vec<(String, Option<Vec<Effect>>)> = match ctx.config.jail_paths() {
        JailPaths::Graph => {
            // aggregate per-path effect sets; a path touched by multiple references
            // (e.g. mv source: Read + Delete) carries all of them
            let mut path_effects: Vec<(String, Vec<Effect>)> = Vec::new();
            for r in ctx
                .extraction
                .graph
                .resolved_references(&cwd, &|path, base| {
                    let expanded = jail::expand_env_prefix(path);
                    jail::normalize(expanded.as_deref().unwrap_or(path), base, &home)
                })
            {
                if r.reference.locality.is_remote() {
                    continue;
                }
                if r.reference.effect == Effect::Exec && !r.reference.path.contains('/') {
                    continue;
                }
                if r.absolute == "/dev/null" {
                    continue;
                }
                if let Some(entry) = path_effects.iter_mut().find(|(p, _)| *p == r.absolute) {
                    if !entry.1.contains(&r.reference.effect) {
                        entry.1.push(r.reference.effect);
                    }
                } else {
                    path_effects.push((r.absolute, vec![r.reference.effect]));
                }
            }
            path_effects
                .into_iter()
                .map(|(p, e)| (p, Some(e)))
                .collect()
        }
        // Heuristic or Compare: walk_words tracks cd-aware literal args, plus the
        // two token classes the parser split off: NAME=val prefixes and redirect
        // targets. Any word with a `/` is a candidate; non-paths just match no glob.
        // Candidates carry no effects — rules with `on` never match them.
        _ => {
            let candidate_of = |text: &str| {
                let candidate = jail::path_candidate(text);
                (jail::looks_like_path(candidate) || candidate.contains('/'))
                    .then(|| candidate.to_string())
            };
            let mut paths: Vec<String> =
                jail::walk_words(ctx.extraction, &cwd, &home, true, candidate_of)
                    .into_iter()
                    .map(|(_, resolved)| resolved)
                    .collect();
            for raw in ctx
                .extraction
                .assignments
                .iter()
                .chain(&ctx.extraction.redirect_targets)
            {
                if jail::looks_like_path(raw) || raw.contains('/') {
                    paths.push(jail::normalize(raw, &cwd, &home));
                }
            }
            paths.into_iter().map(|p| (p, None)).collect()
        }
    };

    let mut seen: Vec<String> = Vec::new();
    for (resolved, effects) in candidates {
        if seen.contains(&resolved) {
            continue;
        }
        let Some((action, message)) = match_path(rules, &resolved, effects.as_deref()) else {
            continue;
        };
        seen.push(resolved);
        match action {
            Action::Deny => out.denies.push(message),
            Action::Ask => out.asks.push(message),
            Action::Warn => out.hints.push(message),
            // allow: explicit exception — matched, nothing to flag
            Action::Allow | Action::Log | Action::Rewrite | Action::Skip => {}
        }
    }
}

// Write/Edit/MultiEdit/NotebookEdit: a single already-known file_path.
// Always passes Write+Create as the candidate effects — a read-only rule must
// not gate the edit tools.
pub fn check(rules: &[CompiledPathRule], path: &str, cwd: &str) -> Option<(Action, String)> {
    if rules.is_empty() {
        return None;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = jail::normalize(cwd, cwd, &home);
    let resolved = jail::normalize(path, &cwd, &home);
    match_path(rules, &resolved, Some(&[Effect::Write, Effect::Create]))
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
        let extraction = bash::extract(command);
        super::plan(
            &compiled,
            &ModuleCtx {
                extraction: &extraction,
                config: &config,
                cwd: Some(CWD),
            },
            &mut out,
        );
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
        // is a NAME=val prefix the parser split off, not a plain arg.
        // assignments are a heuristic-specific token class; use explicit heuristic.
        let plan = plan_bash(
            &format!("[settings]\njail_paths = \"heuristic\"\n{TEMP}"),
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
        // `export VAR=/tmp/x` — the path rides on an assignment word.
        // assignments are a heuristic-specific token class; use explicit heuristic.
        assert_eq!(
            plan_bash(
                &format!("[settings]\njail_paths = \"heuristic\"\n{TEMP}"),
                "export OUT=/tmp/build"
            )
            .denies
            .len(),
            1
        );
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
    fn relative_project_path_matched() {
        // self-protection shape: the file named relative to the repo is the same
        // file as the absolute spelling
        let rules = "[[path]]\nmatch = [\"**/.claude/settings.json\"]\naction = \"ask\"\n";
        assert_eq!(plan_bash(rules, "cat .claude/settings.json").asks.len(), 1);
        assert_eq!(
            plan_bash(rules, "sed -i '' 's/a/b/' .claude/settings.json")
                .asks
                .len(),
            1
        );
    }

    #[test]
    fn relative_redirect_target_matched() {
        let rules = "[[path]]\nmatch = [\"**/.claude/settings.json\"]\naction = \"ask\"\n";
        assert_eq!(
            plan_bash(rules, "jq . tmp.json > .claude/settings.json")
                .asks
                .len(),
            1
        );
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

    // ── effect-filter tests ────────────────────────────────────────────────

    const ETC_WRITE: &str = "[[path]]\nmatch = [\"/etc/**\"]\non = [\"write\", \"create\"]\naction = \"deny\"\nhint = \"no writing to /etc\"\n";

    #[test]
    fn on_write_ignores_reads() {
        let plan = plan_bash(ETC_WRITE, "cat /etc/hosts");
        assert!(plan.denies.is_empty(), "{:?}", plan.denies);
    }

    #[test]
    fn on_write_catches_redirect() {
        let plan = plan_bash(ETC_WRITE, "echo x > /etc/motd");
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
        assert!(plan.denies[0].contains("no writing to /etc"));
    }

    #[test]
    fn read_anywhere_write_in_project() {
        let rules = "[[path]]\nmatch = [\"/Users/nobody/project/**\"]\naction = \"allow\"\n\n[[path]]\nmatch = [\"**\"]\non = [\"write\", \"create\", \"delete\"]\naction = \"ask\"\n";
        // read outside the project: fine
        assert!(plan_bash(rules, "cat /data/in").asks.is_empty());
        // write outside the project: ask
        assert_eq!(plan_bash(rules, "echo x > /data/out").asks.len(), 1);
        // write inside the project: the allow exception matched first
        assert!(plan_bash(rules, "echo x > out.txt").asks.is_empty());
    }

    #[test]
    fn on_delete_sees_mv_source() {
        let rules = "[[path]]\nmatch = [\"/protected/**\"]\non = [\"delete\"]\naction = \"deny\"\n";
        // mv's source is read AND deleted (recipes/mv.toml) — the delete rule sees it
        assert_eq!(plan_bash(rules, "mv /protected/a /tmp/b").denies.len(), 1);
        // a plain read is not a delete
        assert!(plan_bash(rules, "cat /protected/a").denies.is_empty());
    }

    #[test]
    fn on_exec_scopes_to_program_words() {
        let rules = "[[path]]\nmatch = [\"/opt/**\"]\non = [\"exec\"]\naction = \"ask\"\n";
        assert_eq!(plan_bash(rules, "/opt/tools/run --version").asks.len(), 1);
        // reading the binary is not executing it
        assert!(plan_bash(rules, "cat /opt/tools/run").asks.is_empty());
    }

    #[test]
    fn edit_tools_are_writes() {
        let cfg = config(ETC_WRITE);
        let rules = compile(&cfg).expect("globs compile");
        assert!(check(&rules, "/etc/hosts", CWD).is_some());

        let cfg = config("[[path]]\nmatch = [\"/etc/**\"]\non = [\"read\"]\naction = \"deny\"\n");
        let rules = compile(&cfg).expect("globs compile");
        assert!(
            check(&rules, "/etc/hosts", CWD).is_none(),
            "a read-only rule must not gate Write/Edit"
        );
    }

    #[test]
    fn on_rules_inert_under_heuristic() {
        // heuristic candidates carry no effects; `on` is a graph-mode feature
        let plan = plan_bash(
            &format!("[settings]\njail_paths = \"heuristic\"\n{ETC_WRITE}"),
            "echo x > /etc/motd",
        );
        assert!(plan.denies.is_empty(), "{:?}", plan.denies);
    }

    #[test]
    fn empty_on_rejected() {
        let cfg = config("[[path]]\nmatch = [\"**\"]\non = []\naction = \"deny\"\n");
        assert!(compile(&cfg).is_err());
    }
}
