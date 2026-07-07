use crate::config::{Action, Config, EditRule};
use crate::rules::GateOutcome;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde_json::Value;

pub struct CompiledEditRule<'a> {
    pub rule: &'a EditRule,
    paths: Option<GlobSet>,
    pattern: Option<Regex>,
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
            Ok(CompiledEditRule {
                rule,
                paths,
                pattern,
            })
        })
        .collect()
}

// (path field, content fields) per tool; content = text being written, not text removed
const TARGETS: &[(&str, &str, &[&str])] = &[
    ("Edit", "file_path", &["new_string"]),
    ("Write", "file_path", &["content"]),
    ("NotebookEdit", "notebook_path", &["new_source"]),
];

pub fn target_of(tool_name: &str, input: &Value) -> Option<(String, Vec<String>)> {
    if tool_name == "MultiEdit" {
        let path = input.get("file_path")?.as_str()?.to_string();
        let contents = input
            .get("edits")?
            .as_array()?
            .iter()
            .filter_map(|e| e.get("new_string").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        return Some((path, contents));
    }
    let (_, path_field, content_fields) = TARGETS.iter().find(|(name, _, _)| *name == tool_name)?;
    let path = input.get(path_field)?.as_str()?.to_string();
    let contents = content_fields
        .iter()
        .filter_map(|f| input.get(f).and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Some((path, contents))
}

pub fn gate_content(path: &str, contents: &[String], rules: &[CompiledEditRule]) -> GateOutcome {
    let mut outcome = GateOutcome::default();
    let mut allowed = false;
    let mut skip_hit = false;
    for rule in rules {
        if rule.paths.as_ref().is_some_and(|g| !g.is_match(path)) {
            continue;
        }
        let content_hit = match &rule.pattern {
            Some(re) => contents.iter().any(|c| re.is_match(c)),
            None => true,
        };
        if !content_hit {
            continue;
        }
        let message = rule.rule.hint.clone().unwrap_or(format!(
            "lictor: {path} matches edit rule{}",
            rule.rule
                .pattern
                .as_deref()
                .map(|p| format!(" `{p}`"))
                .unwrap_or_default()
        ));
        match rule.rule.action {
            Action::Deny => {
                outcome.decision = Some("deny");
                outcome.reason = Some(message);
                if let (Some(n), Some(w)) = (rule.rule.retry_count, rule.rule.retry_window) {
                    let key = rule
                        .rule
                        .pattern
                        .clone()
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
                    outcome.hints.push(message);
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
