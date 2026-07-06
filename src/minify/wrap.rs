use super::{CompiledMinifyRule, matches};
use crate::bash::Extraction;
use crate::rules::SpanEdit;

// rtk-style: prefix matched commands with the wrap program via updatedInput;
// returns edits + indices of commands vetted by allow=true wrap rules
pub fn pre_wrap(
    extraction: &Extraction,
    rules: &[CompiledMinifyRule],
) -> (Vec<SpanEdit>, Vec<usize>) {
    let mut edits = Vec::new();
    let mut vetted = Vec::new();
    for (ci, command) in extraction.commands.iter().enumerate() {
        // wrapping `cmd > file` would send compressed output to the file
        if command.synthetic || command.redirects_output {
            continue;
        }
        let mut wrapped = false;
        let mut all_allow = true;
        for rule in rules {
            let Some(wrap) = rule.rule.wrap.as_deref() else {
                continue;
            };
            if !matches(rule, &command.words) {
                continue;
            }
            let start = command.words[0].start;
            edits.push(SpanEdit {
                start,
                end: start,
                text: format!("{wrap} "),
            });
            wrapped = true;
            all_allow &= rule.rule.allow;
        }
        if wrapped && all_allow {
            vetted.push(ci);
        }
    }
    (edits, vetted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;
    use crate::config::Config;
    use crate::minify::compile_minify_rules;
    use crate::rules::apply_edits;

    fn wrap(policy: &str, command: &str) -> (String, Vec<usize>) {
        let config: Config = toml::from_str(policy).expect("test policy parses");
        let rules = compile_minify_rules(&config).expect("rules compile");
        let extraction = bash::extract(command);
        let (edits, vetted) = pre_wrap(&extraction, &rules);
        (apply_edits(command, &edits), vetted)
    }

    const POLICY: &str = "[[minify]]\nmatch = \"git log*\"\nwrap = \"rtk\"\nallow = true";

    #[test]
    fn wraps_and_vets_matching_command() {
        let (rewritten, vetted) = wrap(POLICY, "git log --oneline -5");
        assert_eq!(rewritten, "rtk git log --oneline -5");
        assert_eq!(vetted, vec![0]);
    }

    #[test]
    fn wraps_inside_chain() {
        let (rewritten, _) = wrap(POLICY, "cd x && git log -3");
        assert_eq!(rewritten, "cd x && rtk git log -3");
    }

    #[test]
    fn skips_output_redirect() {
        let (rewritten, vetted) = wrap(POLICY, "git log > log.txt");
        assert_eq!(rewritten, "git log > log.txt");
        assert!(vetted.is_empty());
    }

    #[test]
    fn no_allow_means_no_vet() {
        let policy = "[[minify]]\nmatch = \"git log*\"\nwrap = \"rtk\"";
        let (rewritten, vetted) = wrap(policy, "git log");
        assert_eq!(rewritten, "rtk git log");
        assert!(vetted.is_empty());
    }
}
