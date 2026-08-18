use super::{CompiledMinifyRule, matches};
use crate::bash::Extraction;
use crate::rules::SpanEdit;

// rtk-style: prefix matched commands with the wrap program via updatedInput,
// or splice an `insert` stage after them when a pipe consumer follows;
// returns edits + indices of commands vetted by allow=true rules
pub fn pre_wrap(
    extraction: &Extraction,
    rules: &[CompiledMinifyRule],
) -> (Vec<SpanEdit>, Vec<usize>) {
    let mut edits = Vec::new();
    let mut vetted = Vec::new();
    for (ci, command) in extraction.commands.iter().enumerate() {
        // wrapping `cmd > file` would send compressed output to the file, and
        // a non-rewritable command ($(...) substitution, find -exec payload)
        // feeds the shell, not the model
        if command.synthetic || command.redirects_output || !command.rewritable {
            continue;
        }
        let mut edited = false;
        let mut all_allow = true;
        for rule in rules {
            if !matches(rule, &command.words) {
                continue;
            }
            let start = command.words[0].start;
            // a downstream pipe consumer means wrap would compress the wrong
            // end of the pipeline — the insert stage goes after the command
            let insert_at = rule
                .rule
                .insert
                .as_deref()
                .and_then(|_| pipe_connector_end(extraction, start));
            match (insert_at, rule.rule.wrap.as_deref()) {
                (Some(at), _) => edits.push(SpanEdit {
                    start: at,
                    end: at,
                    text: format!(" {} |", rule.rule.insert.as_deref().unwrap()),
                }),
                (None, Some(wrap)) => edits.push(SpanEdit {
                    start,
                    end: start,
                    text: format!("{wrap} "),
                }),
                (None, None) => continue,
            }
            edited = true;
            all_allow &= rule.rule.allow;
        }
        if edited && all_allow {
            vetted.push(ci);
        }
    }
    (edits, vetted)
}

// byte offset just past the `|` joining the command starting at `start` to its
// pipe consumer; None when nothing is piped into. A wrapper's stripped variant
// (`sudo cargo test | less` matched as `cargo test*`) still resolves: the
// OUTER command's spans contain the variant's first word, and the outer node
// carries the Flow edge.
fn pipe_connector_end(extraction: &Extraction, start: usize) -> Option<usize> {
    let graph = &extraction.graph;
    let (id, _) = graph
        .commands()
        .find(|(_, c)| c.spans.iter().any(|s| s.start == start))?;
    let consumer = graph.edges_from(id).find_map(|e| match e.kind {
        crate::graph::EdgeKind::Flow(crate::graph::Connector::Pipe) => Some(e.to),
        _ => None,
    })?;
    let cmd_end = graph.node(id).spans().iter().map(|s| s.end).max()?;
    let consumer_start = graph.node(consumer).spans().iter().map(|s| s.start).min()?;
    graph.nodes.iter().find_map(|node| match node {
        crate::graph::Node::Connector(c) if c.kind == crate::graph::Connector::Pipe => c
            .spans
            .iter()
            .find(|s| s.start >= cmd_end && s.end <= consumer_start)
            .map(|s| s.end),
        _ => None,
    })
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

    const INSERT_POLICY: &str =
        "[[minify]]\nmatch = \"cargo test*\"\ninsert = \"tokf run --\"\nallow = true";

    #[test]
    fn inserts_stage_after_piped_command() {
        let (rewritten, vetted) = wrap(INSERT_POLICY, "cargo test | less");
        assert_eq!(rewritten, "cargo test | tokf run -- | less");
        assert_eq!(vetted, vec![0]);
    }

    #[test]
    fn insert_without_pipe_consumer_is_inert() {
        let (rewritten, vetted) = wrap(INSERT_POLICY, "cargo test");
        assert_eq!(rewritten, "cargo test");
        assert!(vetted.is_empty());
    }

    #[test]
    fn insert_inside_chain() {
        let (rewritten, _) = wrap(INSERT_POLICY, "cd x && cargo test | head -5");
        assert_eq!(rewritten, "cd x && cargo test | tokf run -- | head -5");
    }

    #[test]
    fn wrap_and_insert_on_one_rule_pick_by_pipeline_shape() {
        let policy =
            "[[minify]]\nmatch = \"cargo test*\"\nwrap = \"tokf run --\"\ninsert = \"tokf run --\"";
        let (piped, _) = wrap(policy, "cargo test | less");
        assert_eq!(piped, "cargo test | tokf run -- | less");
        let (bare, _) = wrap(policy, "cargo test");
        assert_eq!(bare, "tokf run -- cargo test");
    }

    #[test]
    fn insert_only_touches_the_matched_stage() {
        let (rewritten, _) = wrap(INSERT_POLICY, "cargo test | grep ok | wc -l");
        assert_eq!(rewritten, "cargo test | tokf run -- | grep ok | wc -l");
    }

    #[test]
    fn no_allow_means_no_vet() {
        let policy = "[[minify]]\nmatch = \"git log*\"\nwrap = \"rtk\"";
        let (rewritten, vetted) = wrap(policy, "git log");
        assert_eq!(rewritten, "rtk git log");
        assert!(vetted.is_empty());
    }
}
