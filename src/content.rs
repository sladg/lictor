use crate::config::{Action, Config, EditRule};
use crate::rules::GateOutcome;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde_json::Value;

pub struct CompiledEditRule<'a> {
    pub rule: &'a EditRule,
    paths: Option<GlobSet>,
    pattern: Option<Regex>,
    removed_pattern: Option<Regex>,
    required_pattern: Option<Regex>,
    changed_pattern: Option<Regex>,
}

pub fn compile_edit_rules(config: &Config) -> Result<Vec<CompiledEditRule<'_>>, String> {
    config
        .edit
        .iter()
        .map(|rule| {
            let paths = if rule.paths.is_empty() {
                None
            } else {
                let mut builder = GlobSetBuilder::new();
                for glob in &rule.paths {
                    builder.add(Glob::new(glob).map_err(|e| format!("edit rule: {e}"))?);
                }
                Some(builder.build().map_err(|e| format!("edit rule: {e}"))?)
            };
            let pattern = rule
                .pattern
                .as_deref()
                .map(Regex::new)
                .transpose()
                .map_err(|e| format!("edit rule: {e}"))?;
            let removed_pattern = rule
                .removed_pattern
                .as_deref()
                .map(Regex::new)
                .transpose()
                .map_err(|e| format!("edit rule removed_pattern: {e}"))?;
            let required_pattern = rule
                .required_pattern
                .as_deref()
                .map(Regex::new)
                .transpose()
                .map_err(|e| format!("edit rule required_pattern: {e}"))?;
            let changed_pattern = rule
                .changed_pattern
                .as_deref()
                .map(Regex::new)
                .transpose()
                .map_err(|e| format!("edit rule changed_pattern: {e}"))?;
            Ok(CompiledEditRule {
                rule,
                paths,
                pattern,
                removed_pattern,
                required_pattern,
                changed_pattern,
            })
        })
        .collect()
}

// (tool_name, path_field, old_field, new_field)
// old_field = "" for tools that send no prior content (Write, NotebookEdit)
const TARGETS: &[(&str, &str, &str, &str)] = &[
    ("Edit", "file_path", "old_string", "new_string"),
    ("Write", "file_path", "", "content"),
    ("NotebookEdit", "notebook_path", "", "new_source"),
];

pub fn target_of(tool_name: &str, input: &Value) -> Option<(String, Vec<(String, String)>)> {
    if tool_name == "MultiEdit" {
        let path = input.get("file_path")?.as_str()?.to_string();
        let pairs = input
            .get("edits")?
            .as_array()?
            .iter()
            .filter_map(|e| {
                let old = e
                    .get("old_string")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let new = e.get("new_string").and_then(Value::as_str)?.to_string();
                Some((old, new))
            })
            .collect();
        return Some((path, pairs));
    }
    let (_, path_field, old_field, new_field) =
        TARGETS.iter().find(|(name, _, _, _)| *name == tool_name)?;
    let path = input.get(path_field)?.as_str()?.to_string();
    let old = if old_field.is_empty() {
        String::new()
    } else {
        input
            .get(*old_field)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let new = input.get(*new_field).and_then(Value::as_str)?.to_string();
    Some((path, vec![(old, new)]))
}

// edits: (old, new) pairs per edit entry.
// old = "" for tools with no prior content (Write, NotebookEdit).
pub fn gate_content(
    path: &str,
    edits: &[(String, String)],
    rules: &[CompiledEditRule],
) -> GateOutcome {
    let mut outcome = GateOutcome::default();
    let mut allowed = false;
    let mut skip_hit = false;
    for rule in rules {
        if rule.paths.as_ref().is_some_and(|g| !g.is_match(path)) {
            continue;
        }
        // `pattern`: fires when new content MATCHES; None = always fires
        let pattern_fires = match &rule.pattern {
            Some(re) => edits.iter().any(|(_, new)| re.is_match(new)),
            None => true,
        };
        // `removed_pattern`: fires when old content matched but new content does not; None = always fires
        let removed_fires = match &rule.removed_pattern {
            Some(re) => edits
                .iter()
                .any(|(old, new)| re.is_match(old) && !re.is_match(new)),
            None => true,
        };
        // `required_pattern`: fires when new content is MISSING the pattern; None = always fires
        let required_fires = match &rule.required_pattern {
            Some(re) => !edits.iter().any(|(_, new)| re.is_match(new)),
            None => true,
        };
        // `changed_pattern`: fires when a text matched in old no longer appears
        // verbatim in new (edited or removed); pure additions keep every old
        // match and stay silent. None = always fires
        let changed_fires = match &rule.changed_pattern {
            Some(re) => edits
                .iter()
                .any(|(old, new)| re.find_iter(old).any(|m| !new.contains(m.as_str()))),
            None => true,
        };
        if !pattern_fires || !removed_fires || !required_fires || !changed_fires {
            continue;
        }
        let message = rule.rule.hint.clone().unwrap_or_else(|| {
            if rule.rule.required_pattern.is_some() {
                format!(
                    "lictor: {path} is missing required content{}",
                    rule.rule
                        .required_pattern
                        .as_deref()
                        .map(|p| format!(" `{p}`"))
                        .unwrap_or_default()
                )
            } else if let Some(p) = rule.rule.changed_pattern.as_deref() {
                format!("lictor: {path} edits content protected by `{p}`")
            } else {
                format!(
                    "lictor: {path} matches edit rule{}",
                    rule.rule
                        .pattern
                        .as_deref()
                        .map(|p| format!(" `{p}`"))
                        .unwrap_or_default()
                )
            }
        });
        match rule.rule.action {
            Action::Deny => {
                outcome.decision = Some("deny");
                outcome.reason = Some(message);
                if let (Some(n), Some(w)) = (rule.rule.retry_count, rule.rule.retry_window) {
                    let key = rule
                        .rule
                        .pattern
                        .clone()
                        .or_else(|| rule.rule.changed_pattern.clone())
                        .unwrap_or_else(|| rule.rule.paths.join(","));
                    outcome.deny_retry = Some((key, n, w));
                }
                return outcome;
            }
            Action::Ask => {
                outcome.decision = Some("ask");
                outcome.reason = Some(message);
            }
            Action::Warn => {
                if !outcome.hints.contains(&message) {
                    outcome.hints.push(message.clone());
                }
                if let (Some(n), Some(w)) = (rule.rule.retry_count, rule.rule.retry_window) {
                    let key = rule
                        .rule
                        .removed_pattern
                        .clone()
                        .or_else(|| rule.rule.pattern.clone())
                        .or_else(|| rule.rule.changed_pattern.clone())
                        .unwrap_or_else(|| rule.rule.paths.join(","));
                    outcome.hint_retry = Some((key, n, w, message));
                }
            }
            Action::Allow => allowed = true,
            Action::Log => {
                let key = rule
                    .rule
                    .pattern
                    .clone()
                    .unwrap_or_else(|| rule.rule.paths.join(","));
                let entry = (key, path.to_string());
                if !outcome.logged.contains(&entry) {
                    outcome.logged.push(entry);
                }
            }
            Action::Rewrite => {}
            // overrides ask/warn/log/allow from every other matching rule (an
            // earlier Deny already returned above); Claude Code's own
            // permission rules decide instead
            Action::Skip => skip_hit = true,
        }
    }
    if skip_hit {
        return GateOutcome::default();
    }
    if outcome.decision.is_none() && allowed {
        outcome.decision = Some("allow");
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config(toml: &str) -> Config {
        toml::from_str(toml).expect("config parses")
    }

    // Call site for the new API: gate_content takes (old, new) pairs.
    // old = "" for Write (no prior content); old = old_string for Edit/MultiEdit.
    fn gate(rules_toml: &str, path: &str, edits: &[(&str, &str)]) -> GateOutcome {
        let config = config(rules_toml);
        let rules = compile_edit_rules(&config).expect("rules compile");
        let owned: Vec<(String, String)> = edits
            .iter()
            .map(|(o, n)| (o.to_string(), n.to_string()))
            .collect();
        gate_content(path, &owned, &rules)
    }

    // ── shared fixtures ────────────────────────────────────────────────────────

    const TSDOC_WARN: &str = r#"
[[edit]]
removed_pattern = "(?s)/\\*\\*.*?\\*/"
action = "warn"
hint = "lictor: do not remove doc-comments"
"#;

    const TSDOC_DENY: &str = r#"
[[edit]]
removed_pattern = "(?s)/\\*\\*.*?\\*/"
action = "deny"
hint = "lictor: do not remove doc-comments"
"#;

    // ── tsdoc / jsdoc — single-line ────────────────────────────────────────────

    #[test]
    fn tsdoc_single_line_removal_warns() {
        let old = "/** Returns the user by ID. */\nfunction getUser(id: string) {}";
        let new = "function getUser(id: string) {}";
        let out = gate(TSDOC_WARN, "src/api.ts", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
        assert!(out.hints[0].contains("doc-comment"));
    }

    #[test]
    fn tsdoc_still_present_no_warn() {
        // comment reformatted but the /** */ block still exists in new — not a removal
        let old = "/** Returns the user by ID. */\nfunction getUser(id: string) {}";
        let new = "/** Returns the user by ID. Updated. */\nfunction getUser(id: string) {}";
        let out = gate(TSDOC_WARN, "src/api.ts", &[(old, new)]);
        assert!(out.hints.is_empty());
    }

    #[test]
    fn no_comment_in_old_no_warn() {
        let old = "function getUser(id: string) {}";
        let new = "const getUser = (id: string) => {}";
        let out = gate(TSDOC_WARN, "src/api.ts", &[(old, new)]);
        assert!(out.hints.is_empty());
    }

    // ── tsdoc / jsdoc — multi-line ────────────────────────────────────────────

    #[test]
    fn multiline_tsdoc_removal_warns() {
        let old = "/**\n * Gets the user by ID.\n * @param id - user ID\n * @returns the user\n */\nfunction getUser(id: string) {}";
        let new = "function getUser(id: string) {}";
        let out = gate(TSDOC_WARN, "src/api.ts", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
    }

    #[test]
    fn multiline_tsdoc_with_throws_warns() {
        let old = "/**\n * Processes payment.\n * @param amount - Amount in cents\n * @param currency - ISO 4217 code\n * @throws {PaymentError} on failure\n */\nfunction processPayment(amount: number, currency: string): Promise<void> {}";
        let new = "function processPayment(amount: number, currency: string): Promise<void> {}";
        let out = gate(TSDOC_WARN, "src/payments.ts", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
    }

    #[test]
    fn tsdoc_replaced_by_inline_comment_warns() {
        // /** */ stripped and replaced with // — jsdoc block is gone
        let old = "/** Fetches data from the API. */\nasync function fetchData() {}";
        let new = "// Fetches data from the API.\nasync function fetchData() {}";
        let out = gate(TSDOC_WARN, "src/data.ts", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
    }

    #[test]
    fn multiple_tsdoc_blocks_warns_once() {
        // two /** */ blocks in old, none in new — one hint, not two
        let old = "/** First. */\nconst a = 1;\n/** Second. */\nconst b = 2;";
        let new = "const a = 1;\nconst b = 2;";
        let out = gate(TSDOC_WARN, "src/constants.ts", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
    }

    // ── action = deny ─────────────────────────────────────────────────────────

    #[test]
    fn tsdoc_removal_deny_blocks() {
        let old = "/** Core initialiser. */\nexport function init() {}";
        let new = "export function init() {}";
        let out = gate(TSDOC_DENY, "src/index.ts", &[(old, new)]);
        assert_eq!(out.decision, Some("deny"));
        assert!(out.reason.as_deref().unwrap_or("").contains("doc-comment"));
        assert!(out.hints.is_empty(), "deny should not also add a hint");
    }

    // ── rust triple-slash (//) ─────────────────────────────────────────────

    #[test]
    fn rust_triple_slash_removal_warns() {
        let rules = "[[edit]]\npaths = [\"**/*.rs\"]\nremoved_pattern = \"(?m)^///\"\naction = \"warn\"\nhint = \"lictor: rust doc-comments (///) must not be removed\"\n";
        let old = "/// Computes the factorial of n.\npub fn factorial(n: u64) -> u64 { todo!() }";
        let new = "pub fn factorial(n: u64) -> u64 { todo!() }";
        let out = gate(rules, "src/math.rs", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
        assert!(out.hints[0].contains("///"));
    }

    #[test]
    fn rust_triple_slash_kept_no_warn() {
        let rules = "[[edit]]\npaths = [\"**/*.rs\"]\nremoved_pattern = \"(?m)^///\"\naction = \"warn\"\nhint = \"lictor: rust doc-comments (///) must not be removed\"\n";
        let old = "/// Old description.\npub fn foo() {}";
        let new = "/// New description.\npub fn foo() {}";
        let out = gate(rules, "src/lib.rs", &[(old, new)]);
        assert!(out.hints.is_empty());
    }

    // ── path scoping ──────────────────────────────────────────────────────────

    #[test]
    fn removed_pattern_only_fires_on_matching_path() {
        let rules = "[[edit]]\npaths = [\"**/*.ts\", \"**/*.tsx\"]\nremoved_pattern = \"(?s)/\\\\*\\\\*.*?\\\\*/\"\naction = \"warn\"\nhint = \"lictor: do not remove doc-comments\"\n";
        let old = "/** A doc comment. */\nfn foo() {}";
        let new = "fn foo() {}";
        // .rs — rule does not apply
        assert!(gate(rules, "src/lib.rs", &[(old, new)]).hints.is_empty());
        // .ts — rule applies
        assert_eq!(gate(rules, "src/api.ts", &[(old, new)]).hints.len(), 1);
    }

    // ── MultiEdit — multiple (old, new) pairs ─────────────────────────────────

    #[test]
    fn multi_edit_one_entry_removes_comment_warns() {
        let edits: &[(&str, &str)] = &[
            ("const x = 1;", "const x = 2;"),
            (
                "/** Important public API. */\nexport function api() {}",
                "export function api() {}",
            ),
        ];
        let out = gate(TSDOC_WARN, "src/api.ts", edits);
        assert_eq!(out.hints.len(), 1);
    }

    #[test]
    fn multi_edit_no_removal_silent() {
        let edits: &[(&str, &str)] = &[
            ("const x = 1;", "const x = 2;"),
            ("const y = 'a';", "const y = 'b';"),
        ];
        let out = gate(TSDOC_WARN, "src/api.ts", edits);
        assert!(out.hints.is_empty());
    }

    // ── Write tool: no old_string (old = "") ──────────────────────────────────

    #[test]
    fn write_tool_empty_old_no_warn() {
        // Write sends no old_string; we pass "" — removed_pattern must not fire
        let out = gate(
            TSDOC_WARN,
            "src/index.ts",
            &[("", "export function init() {}")],
        );
        assert!(out.hints.is_empty());
    }

    // ── existing `pattern` (added-content matching) unaffected ────────────────

    #[test]
    fn added_pattern_still_works() {
        let rules = "[[edit]]\npattern = \"console\\\\.log\"\naction = \"warn\"\nhint = \"lictor: no console.log in production\"\n";
        let old = "function foo() {}";
        let new = "function foo() { console.log('debug'); }";
        let out = gate(rules, "src/foo.ts", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
    }

    #[test]
    fn added_pattern_does_not_fire_on_removed_content() {
        // pattern matches old but NOT new — existing `pattern` only checks new_string
        let rules = "[[edit]]\npattern = \"console\\\\.log\"\naction = \"warn\"\nhint = \"lictor: no console.log\"\n";
        let old = "function foo() { console.log('debug'); }";
        let new = "function foo() {}";
        let out = gate(rules, "src/foo.ts", &[(old, new)]);
        assert!(out.hints.is_empty());
    }

    // ── both pattern and removed_pattern on one rule ───────────────────────────

    #[test]
    fn both_conditions_must_match() {
        // rule fires only when added content matches pattern AND old had the removed_pattern
        let rules = "[[edit]]\npattern = \"TODO\"\nremoved_pattern = \"(?s)/\\\\*\\\\*.*?\\\\*/\"\naction = \"warn\"\nhint = \"lictor: replacing doc-comment with a TODO placeholder\"\n";
        let old_with_doc = "/** Real docs. */\nfunction foo() {}";
        let new_with_todo = "// TODO: add docs\nfunction foo() {}";
        let new_no_todo = "function foo() {}";
        // both conditions met → warn
        assert_eq!(
            gate(rules, "src/a.ts", &[(old_with_doc, new_with_todo)])
                .hints
                .len(),
            1
        );
        // removed_pattern matches but new has no TODO → no warn
        assert!(
            gate(rules, "src/a.ts", &[(old_with_doc, new_no_todo)])
                .hints
                .is_empty()
        );
        // new has TODO but old had no doc-comment → no warn
        assert!(
            gate(rules, "src/a.ts", &[("function foo() {}", new_with_todo)])
                .hints
                .is_empty()
        );
    }

    // ── no rules is always a noop ─────────────────────────────────────────────

    #[test]
    fn no_rules_noop() {
        let out = gate("", "src/api.ts", &[("/** doc */\nfn f() {}", "fn f() {}")]);
        assert!(out.decision.is_none() && out.hints.is_empty());
    }

    // ── hint_retry: gate_content sets the retry descriptor on the outcome ─────

    #[test]
    fn hint_retry_set_when_warn_retry_configured() {
        let rules = r#"
[[edit]]
removed_pattern = "(?s)/\\*\\*.*?\\*/"
action = "warn"
hint = "lictor: do not remove doc-comments"
retry_count = 2
retry_window = 300
"#;
        let old = "/** A doc comment. */\nfunction foo() {}";
        let new = "function foo() {}";
        let out = gate(rules, "src/api.ts", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
        let (key, count, window, message) = out.hint_retry.expect("hint_retry must be set");
        // key derives from the removed_pattern string (the compiled regex source)
        assert!(
            key.contains("(?s)"),
            "key should derive from removed_pattern: {key}"
        );
        assert_eq!(count, 2);
        assert_eq!(window, 300);
        assert!(message.contains("doc-comment"));
    }

    #[test]
    fn hint_retry_not_set_when_no_retry_count() {
        let out = gate(
            TSDOC_WARN,
            "src/api.ts",
            &[("/** doc. */\nfn f() {}", "fn f() {}")],
        );
        assert!(
            out.hint_retry.is_none(),
            "no retry_count → hint_retry must stay None"
        );
    }

    // ── required_pattern: fires when content is MISSING the pattern ───────────

    const MD_REQUIRED: &str = r#"
[[edit]]
paths = ["**/*.md"]
required_pattern = "created_at:"
action = "deny"
hint = "lictor: markdown files must include 'created_at:' frontmatter"
"#;

    #[test]
    fn required_pattern_fires_when_absent() {
        let content = "# My Note\n\nSome text here.";
        let out = gate(MD_REQUIRED, "docs/guide.md", &[("", content)]);
        assert_eq!(out.decision, Some("deny"));
        assert!(out.reason.as_deref().unwrap_or("").contains("created_at"));
    }

    #[test]
    fn required_pattern_silent_when_present() {
        let content = "---\ncreated_at: 2026-07-14\nauthor: jan\n---\n\n# My Note";
        let out = gate(MD_REQUIRED, "docs/guide.md", &[("", content)]);
        assert!(out.decision.is_none());
    }

    #[test]
    fn required_pattern_path_scoped_to_md() {
        // same content missing created_at, but .ts file — rule does not apply
        let content = "Some code without created_at.";
        let out = gate(MD_REQUIRED, "src/api.ts", &[("", content)]);
        assert!(out.decision.is_none());
    }

    #[test]
    fn required_pattern_warn_on_md_write() {
        let rules = r#"
[[edit]]
paths = ["**/*.md"]
required_pattern = "created_at:"
action = "warn"
hint = "lictor: markdown files must include 'created_at:' frontmatter"
"#;
        let content = "# Undated Note\n\nMissing frontmatter.";
        let out = gate(rules, "notes/todo.md", &[("", content)]);
        assert_eq!(out.hints.len(), 1);
        assert!(out.hints[0].contains("created_at"));
    }

    #[test]
    fn required_pattern_on_edit_checks_new_string_only() {
        // old has no created_at, new adds it — required_pattern should pass (present in new)
        let old = "# Old Note\n\nContent.";
        let new = "---\ncreated_at: 2026-07-14\n---\n\n# Old Note\n\nContent.";
        let out = gate(MD_REQUIRED, "notes/old.md", &[(old, new)]);
        assert!(
            out.decision.is_none(),
            "new content satisfies required_pattern"
        );
    }

    #[test]
    fn required_updated_at_on_edit_missing_warns() {
        // enforce that every edit to a .md also updates the updated_at field
        let rules = r#"
[[edit]]
paths = ["**/*.md"]
required_pattern = "updated_at:"
action = "warn"
hint = "lictor: include 'updated_at:' when editing markdown files"
"#;
        let old = "---\ncreated_at: 2026-07-01\n---\n\n# Note\n\nOld text.";
        let new = "---\ncreated_at: 2026-07-01\n---\n\n# Note\n\nNew text."; // updated_at missing
        let out = gate(rules, "notes/post.md", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
        assert!(out.hints[0].contains("updated_at"));
    }

    // ── changed_pattern: per-match survival ───────────────────────────────────

    const TEST_CONSULT: &str = r#"
[[edit]]
paths = ["**/*.test.ts", "**/*_test.go", "**/tests/**/*.rs"]
changed_pattern = '"[^"]*"'
action = "deny"
hint = "test expectation edited — consult the user"
"#;

    #[test]
    fn changed_pattern_fires_on_value_swap() {
        let old = r#"expect(greet()).toBe("hello")"#;
        let new = r#"expect(greet()).toBe("goodbye")"#;
        let out = gate(TEST_CONSULT, "src/api.test.ts", &[(old, new)]);
        assert_eq!(out.decision, Some("deny"));
        assert!(out.reason.as_deref().unwrap_or("").contains("consult"));
    }

    #[test]
    fn changed_pattern_fires_on_match_removal() {
        let old = r#"it("rejects empty", () => {})"#;
        let out = gate(TEST_CONSULT, "src/api.test.ts", &[(old, "")]);
        assert_eq!(out.decision, Some("deny"));
    }

    #[test]
    fn changed_pattern_silent_on_pure_addition() {
        // old matches survive verbatim; new content only adds — no fire
        let old = r#"it("adds", () => {});"#;
        let new = r#"it("adds", () => {});
it("subtracts", () => {});"#;
        let out = gate(TEST_CONSULT, "src/api.test.ts", &[(old, new)]);
        assert!(out.decision.is_none());
    }

    #[test]
    fn changed_pattern_silent_on_write_without_prior_content() {
        // Write sends old = "" — nothing matched, nothing can vanish
        let out = gate(
            TEST_CONSULT,
            "src/new.test.ts",
            &[("", r#"it("fresh", () => {})"#)],
        );
        assert!(out.decision.is_none());
    }

    #[test]
    fn changed_pattern_silent_when_no_match_in_old() {
        // anchor-only edit (closing brace), no quoted string touched
        let out = gate(TEST_CONSULT, "src/api.test.ts", &[("});", "});\n// x")]);
        assert!(out.decision.is_none());
    }

    #[test]
    fn changed_pattern_respects_path_scope() {
        let old = r#"label("hello")"#;
        let new = r#"label("goodbye")"#;
        // not a test file — rule does not apply
        let out = gate(TEST_CONSULT, "src/ui.ts", &[(old, new)]);
        assert!(out.decision.is_none());
    }

    #[test]
    fn changed_pattern_catches_single_comment_deletion_among_survivors() {
        // the removed_pattern blind spot: one comment deleted, another remains.
        // per-match survival still fires because THAT match text is gone.
        let rules = r#"
[[edit]]
changed_pattern = '(?m)[ \t]*//[^\n]*'
action = "warn"
hint = "a comment was edited or removed"
"#;
        let old = "// keep me\nconst a = 1;\n// delete me\nconst b = 2;";
        let new = "// keep me\nconst a = 1;\nconst b = 2;";
        let out = gate(rules, "src/x.ts", &[(old, new)]);
        assert_eq!(out.hints.len(), 1);
    }

    #[test]
    fn changed_pattern_combines_with_pattern_condition() {
        // both must hold: new content touches a #[test] block AND a string changed
        let rules = r#"
[[edit]]
paths = ["**/*.rs"]
pattern = '#\[test\]'
changed_pattern = '"[^"]*"'
action = "deny"
hint = "inline test expectation edited"
"#;
        let old = "#[test]\nfn t() { assert_eq!(f(), \"a\"); }";
        let new = "#[test]\nfn t() { assert_eq!(f(), \"b\"); }";
        let out = gate(rules, "src/lib.rs", &[(old, new)]);
        assert_eq!(out.decision, Some("deny"));

        // string swap in NON-test rust code: pattern condition fails, silent
        let old = "fn label() -> &'static str { \"a\" }";
        let new = "fn label() -> &'static str { \"b\" }";
        let out = gate(rules, "src/lib.rs", &[(old, new)]);
        assert!(out.decision.is_none());
    }

    #[test]
    fn changed_pattern_deny_retry_key_derives_from_it() {
        let rules = r#"
[[edit]]
paths = ["**/*.test.ts"]
changed_pattern = '"[^"]*"'
action = "deny"
hint = "consult first"
retry_count = 1
retry_window = 600
"#;
        let out = gate(rules, "src/api.test.ts", &[(r#"t("a")"#, r#"t("b")"#)]);
        assert_eq!(out.decision, Some("deny"));
        let (key, count, window) = out.deny_retry.expect("deny_retry set");
        assert_eq!(key, r#""[^"]*""#);
        assert_eq!(count, 1);
        assert_eq!(window, 600);
    }

    #[test]
    fn required_updated_at_satisfied() {
        let rules = r#"
[[edit]]
paths = ["**/*.md"]
required_pattern = "updated_at:"
action = "warn"
hint = "lictor: include 'updated_at:' when editing markdown files"
"#;
        let old = "---\ncreated_at: 2026-07-01\n---\n\n# Note\n\nOld text.";
        let new = "---\ncreated_at: 2026-07-01\nupdated_at: 2026-07-14\n---\n\n# Note\n\nNew text.";
        let out = gate(rules, "notes/post.md", &[(old, new)]);
        assert!(out.hints.is_empty());
    }
}
