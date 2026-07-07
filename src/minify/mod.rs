// output shaping: wrap prefixes commands with a proxy before they run,
// filter pipes/truncates captured stdout, spill offloads it to the kv store.
// Rule compilation and subprocess plumbing are shared here.
pub mod filter;
pub mod spill;
pub mod wrap;

pub use filter::{MinifyOutcome, post_minify};
pub use spill::{SpillOutcome, spill};
pub use wrap::pre_wrap;

use crate::config::{Config, MinifyRule};
use crate::rules::glob_to_regex;
use regex::Regex;
use std::io::Write;
use std::process::{Command, Stdio};

// lines matching these survive truncation unless the rule sets its own `preserve`
const DEFAULT_PRESERVE: &[&str] = &[r"(?i)\berror", r"(?i)\bwarn", r"(?i)\bfail", r"(?i)panic"];

pub struct CompiledMinifyRule<'a> {
    pub rule: &'a MinifyRule,
    words: Vec<Regex>,
    preserve: Vec<Regex>,
}

pub fn compile_minify_rules(config: &Config) -> Result<Vec<CompiledMinifyRule<'_>>, String> {
    config
        .minify
        .iter()
        .map(|rule| {
            let words = rule
                .pattern
                .split_whitespace()
                .map(glob_to_regex)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("minify rule '{}': {e}", rule.pattern))?;
            let preserve_sources: Vec<&str> = match &rule.preserve {
                Some(own) => own.iter().map(String::as_str).collect(),
                None => DEFAULT_PRESERVE.to_vec(),
            };
            let preserve = preserve_sources
                .iter()
                .map(|s| Regex::new(s).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("minify rule '{}': {e}", rule.pattern))?;
            Ok(CompiledMinifyRule {
                rule,
                words,
                preserve,
            })
        })
        .collect()
}

// distinct first-word binaries named by wrap/pipe, so `lictor check` can flag
// ones missing from PATH before a matching command fails at run time
pub fn minify_tools(config: &Config) -> Vec<&str> {
    let mut tools: Vec<&str> = Vec::new();
    for rule in &config.minify {
        for cmd in [rule.wrap.as_deref(), rule.pipe.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(program) = cmd.split_whitespace().next()
                && !tools.contains(&program)
            {
                tools.push(program);
            }
        }
    }
    tools
}

fn matches(rule: &CompiledMinifyRule, words: &[crate::bash::Word]) -> bool {
    words.len() >= rule.words.len()
        && rule.words.iter().enumerate().all(|(i, re)| {
            words[i]
                .text
                .as_deref()
                .is_some_and(|t| re.is_match(if i == 0 { crate::bash::basename(t) } else { t }))
        })
}

fn run_filter(filter: &str, input: &str) -> Option<String> {
    let out = run_piped(filter, input)?;
    String::from_utf8(out).ok()
}

fn run_store(invocation: &str, input: &str) -> bool {
    run_piped(invocation, input).is_some()
}

fn run_piped(shell_command: &str, input: &str) -> Option<Vec<u8>> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(shell_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(input.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minify_tools_dedupes_first_words_of_wrap_and_pipe() {
        let config: Config = toml::from_str(
            r#"
            [[minify]]
            match = "git log*"
            wrap = "rtk"
            [[minify]]
            match = "cargo test*"
            wrap = "tokf run"
            [[minify]]
            match = "cargo build*"
            pipe = "tokf filter"
            "#,
        )
        .expect("test policy parses");
        assert_eq!(minify_tools(&config), vec!["rtk", "tokf"]);
    }
}
