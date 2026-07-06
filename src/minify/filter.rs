use super::{CompiledMinifyRule, matches, run_filter};
use crate::bash::Extraction;
use regex::Regex;

pub struct MinifyOutcome {
    pub stdout: String,
    pub rule: String,
    pub bytes_in: usize,
    pub bytes_out: usize,
}

// squeez-style: pipe captured stdout through a filter and/or truncate
pub fn post_minify(
    extraction: &Extraction,
    stdout: &str,
    rules: &[CompiledMinifyRule],
) -> Option<MinifyOutcome> {
    let rule = rules.iter().find(|rule| {
        (rule.rule.pipe.is_some() || rule.rule.max_lines.is_some())
            && extraction.commands.iter().any(|c| matches(rule, &c.words))
    })?;
    if stdout.lines().count() < rule.rule.min_lines {
        return None;
    }
    let mut output = stdout.to_string();
    if let Some(pipe) = rule.rule.pipe.as_deref() {
        // a filter that fails or grows the output is discarded
        if let Some(filtered) = run_filter(pipe, &output).filter(|f| f.len() <= output.len()) {
            output = filtered;
        }
    }
    if let Some(max_lines) = rule.rule.max_lines {
        output = truncate_lines(&output, max_lines, &rule.preserve);
    }
    if output == stdout {
        return None;
    }
    Some(MinifyOutcome {
        bytes_in: stdout.len(),
        bytes_out: output.len(),
        stdout: output,
        rule: rule.rule.pattern.clone(),
    })
}

fn truncate_lines(text: &str, max_lines: usize, preserve: &[Regex]) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= max_lines.max(2) {
        return text.to_string();
    }
    let head = max_lines / 2;
    let tail = max_lines - head;
    let middle = &lines[head..lines.len() - tail];
    // ponytail: unbounded when the middle is all errors — errors outrank the budget
    let kept: Vec<&str> = middle
        .iter()
        .filter(|line| preserve.iter().any(|re| re.is_match(line)))
        .copied()
        .collect();
    let omitted = middle.len() - kept.len();
    let mut result: Vec<&str> = lines[..head].to_vec();
    let marker = format!("... [lictor: {omitted} lines omitted] ...");
    result.push(&marker);
    result.extend(kept);
    result.extend_from_slice(&lines[lines.len() - tail..]);
    result.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preserve() -> Vec<Regex> {
        vec![Regex::new(r"(?i)\berror").unwrap()]
    }

    #[test]
    fn truncates_middle_keeps_head_and_tail() {
        let text = (1..=20)
            .map(|i| format!("line{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let out = truncate_lines(&text, 6, &preserve());
        assert!(out.starts_with("line1\nline2\nline3\n"));
        assert!(out.ends_with("line18\nline19\nline20"));
        assert!(out.contains("14 lines omitted"));
    }

    #[test]
    fn preserved_lines_survive_the_middle() {
        let text = (1..=20)
            .map(|i| {
                if i == 10 {
                    "error: boom".into()
                } else {
                    format!("line{i}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let out = truncate_lines(&text, 6, &preserve());
        assert!(out.contains("error: boom"));
        assert!(out.contains("13 lines omitted"));
    }

    #[test]
    fn short_output_untouched() {
        assert_eq!(truncate_lines("a\nb\nc", 6, &preserve()), "a\nb\nc");
    }
}
