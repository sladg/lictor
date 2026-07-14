//! [[agent]] rules: regex over a subagent's prompt (PreToolUse Task/Agent —
//! deny/ask/warn) or its returned output (PostToolUse — hint only, the work
//! already happened). E.g. flag "comprehensive analysis" fluff in results.

use crate::config::{AgentOn, AgentRule, Config};
use regex::Regex;

pub struct CompiledAgentRule<'a> {
    pub rule: &'a AgentRule,
    regex: Regex,
}

pub fn compile(config: &Config) -> Result<Vec<CompiledAgentRule<'_>>, String> {
    config
        .agent
        .iter()
        .map(|rule| {
            let regex = Regex::new(&rule.pattern)
                .map_err(|e| format!("agent rule '{}': {e}", rule.pattern))?;
            Ok(CompiledAgentRule { rule, regex })
        })
        .collect()
}

pub fn matching<'a, 'b>(
    rules: &'b [CompiledAgentRule<'a>],
    on: AgentOn,
    text: &str,
) -> Vec<&'b CompiledAgentRule<'a>> {
    rules
        .iter()
        .filter(|r| r.rule.on == on && r.regex.is_match(text))
        .collect()
}

pub fn message(rule: &AgentRule, subject: &str) -> String {
    rule.hint
        .clone()
        .or_else(|| rule.reason.clone())
        .unwrap_or(format!(
            "lictor: {subject} matches agent rule `{}`",
            rule.pattern
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Action;

    #[test]
    fn output_rule_matches_response_text() {
        let config: Config = toml::from_str(
            r#"
[[agent]]
pattern = "(?i)comprehensive analysis"
on = "output"
action = "warn"
hint = "cut the fluff"
"#,
        )
        .unwrap();
        let rules = compile(&config).unwrap();
        let hits = matching(
            &rules,
            AgentOn::Output,
            "A Comprehensive Analysis of the repo",
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(message(hits[0].rule, "output"), "cut the fluff");
        assert!(matching(&rules, AgentOn::Prompt, "comprehensive analysis").is_empty());
    }

    #[test]
    fn prompt_rule_can_deny() {
        let config: Config = toml::from_str(
            r#"
[[agent]]
pattern = "rm -rf"
on = "prompt"
action = "deny"
"#,
        )
        .unwrap();
        let rules = compile(&config).unwrap();
        let hits = matching(&rules, AgentOn::Prompt, "please run rm -rf /");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.action, Action::Deny);
    }
}
