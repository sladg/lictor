//! **P1** — the merge gate for the graph IR (issue #13, sub-task 1).
//!
//! `emit(lower(s)) == s` for every string the existing test corpus knows about.
//! The corpus is harvested from the test sources themselves rather than kept as
//! a separate list, so a command string added to `tests/commands.rs` tomorrow is
//! covered by this gate automatically, with nobody having to remember.
//!
//! P1 proves the segment partition is ordered, in-bounds and non-overlapping.
//! On its own it is satisfiable by a lowering that models nothing at all, so
//! `coverage_is_not_vacuous` pins the other half: the words of a command must
//! actually be owned by nodes.
//!
//! What is left here is **properties over a corpus**, which is why it is code.
//! The one-shape-per-bug list this file used to carry lives in
//! `tests/graph_cases/shapes.toml`, where every case asserts P1 anyway and
//! states a claim as well.

use lictor::graph::{self, EdgeKind, Node};

const CORPUS: &[(&str, &str)] = &[
    ("tests/commands.rs", include_str!("commands.rs")),
    ("tests/redteam.rs", include_str!("redteam.rs")),
    ("tests/exploits.rs", include_str!("exploits.rs")),
];

#[test]
fn p1_round_trip_over_the_whole_corpus() {
    let mut checked = 0usize;
    for (file, source) in CORPUS {
        for literal in string_literals(source) {
            let g = graph::lower(&literal);
            let emitted = g.emit();
            assert_eq!(
                emitted, literal,
                "P1 violated for a literal in {file}:\n  input:   {literal:?}\n  emitted: {emitted:?}"
            );
            // round-tripping is not enough on its own: `emit` skips a segment
            // that starts before the cursor, so two nodes claiming the same
            // bytes would still round-trip while making any edit unsound
            if let Some((a, b)) = g.overlapping_segments() {
                panic!(
                    "{file}: overlapping segments {a:?} and {b:?} in {literal:?}\n  \
                     first:  {:?}\n  second: {:?}",
                    &literal[a.start..a.end.min(literal.len())],
                    &literal[b.start..b.end.min(literal.len())],
                );
            }
            checked += 1;
        }
    }
    // guard against the harvester silently matching nothing and the gate
    // passing vacuously
    assert!(
        checked > 500,
        "expected the corpus to yield a substantial number of literals, got {checked}"
    );
    println!("P1 verified over {checked} corpus literals");
}

#[test]
fn coverage_is_not_vacuous() {
    // P1 alone would pass for a lowering that owns nothing. Every word of a
    // plain command must be accounted for by some node.
    let cases: &[(&str, usize)] = &[
        ("grep -n TODO src/main.rs", "grep-nTODOsrc/main.rs".len()),
        (
            "cat notes.txt | grep secret",
            "catnotes.txt|grepsecret".len(),
        ),
        ("echo hi > out.txt", "echohi> out.txt".len()),
    ];
    for (src, expected) in cases {
        let covered = graph::lower(src).covered_bytes();
        assert_eq!(
            covered, *expected,
            "coverage for {src:?}: expected {expected} owned bytes, got {covered}"
        );
    }
}

#[test]
fn every_command_name_in_the_cst_survives_lowering() {
    // The structural check the round-trip cannot make: P1 would still hold for
    // a lowering that modelled nothing, so assert the lowering is complete
    // against the grammar itself — every `command_name` tree-sitter recognises
    // must come out as a graph `Command`.
    //
    // The oracle is the CST, deliberately NOT `bash::extract`. The existing
    // extractor also emits wrapper-stripped variants (`xargs git commit` yields
    // a synthetic `git commit`) driven by the `WRAPPERS` table in
    // `src/bash.rs:531`. The graph does not replicate that and should not: "this
    // program execs its argument" is a per-program map fact, and it becomes an
    // `Execs` edge in sub-task 5 rather than a second phantom command.
    for (file, source) in CORPUS {
        for literal in string_literals(source) {
            let expected = cst_command_names(&literal);
            if expected.is_empty() {
                continue;
            }
            let graph = graph::lower(&literal);
            let mut lowered: Vec<_> = graph
                .commands()
                .filter_map(|(_, c)| c.name.clone())
                .collect();
            for name in expected {
                match lowered.iter().position(|l| *l == name) {
                    Some(i) => {
                        lowered.remove(i);
                    }
                    None => panic!(
                        "{file}: lowering dropped command {name:?} from {literal:?}\n  lowered: {:?}",
                        graph
                            .commands()
                            .filter_map(|(_, c)| c.name.clone())
                            .collect::<Vec<_>>()
                    ),
                }
            }
        }
    }
}

/// Literal `command_name` texts in parse order, straight from the grammar.
fn cst_command_names(source: &str) -> Vec<String> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_names(tree.root_node(), source, &mut out);
    out
}

fn collect_names(node: tree_sitter::Node, source: &str, out: &mut Vec<String>) {
    if node.kind() == "command_name" {
        let inner = node.named_child(0).unwrap_or(node);
        // only literal names — a dynamic one (`$TOOL x`) lowers to `None`, and
        // asserting on it would be asserting on the resolver, not the lowering
        if matches!(inner.kind(), "word" | "number")
            && let Ok(text) = inner.utf8_text(source.as_bytes())
        {
            out.push(text.to_string());
        }
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            collect_names(child, source, out);
        }
    }
}

#[test]
fn edits_are_surgical() {
    // the #7 regression stated against the graph: replacing the program name
    // must leave flags and arguments byte-identical
    let g = graph::lower("grep -n TODO src/main.rs");
    let (cmd, _) = g.commands().next().unwrap();
    // the program name is the command's first owned span
    let name_span = match g.node(cmd) {
        Node::Command(c) => c.spans[0],
        _ => unreachable!(),
    };
    let owner = g
        .segment_owner(name_span)
        .expect("program name must be owned by a node");
    let edits = std::iter::once((owner, "rg".to_string())).collect();
    assert_eq!(g.emit_with(&edits), "rg -n TODO src/main.rs");
}

#[test]
fn no_reference_edges_are_emitted_anywhere_in_the_corpus() {
    // the inverted default, asserted globally: with no argument maps loaded,
    // the graph must make no claim about what any command reads or writes
    for (file, source) in CORPUS {
        for literal in string_literals(source) {
            let g = graph::lower(&literal);
            let leaked: Vec<_> = g
                .edges
                .iter()
                .filter(|e| {
                    matches!(
                        e.kind,
                        EdgeKind::Reads
                            | EdgeKind::Writes
                            | EdgeKind::Deletes
                            | EdgeKind::Creates
                            | EdgeKind::Execs
                            | EdgeKind::Filters(_)
                    )
                })
                .collect();
            assert!(
                leaked.is_empty(),
                "{file}: reference edges emitted without an argument map for {literal:?}"
            );
        }
    }
}

// ── harvesting Rust string literals out of the test sources ──
//
// Deliberately a small scanner rather than a regex: comments and char literals
// both contain quotes, and a regex that ignores them silently harvests garbage
// (or worse, misses real cases and lets the gate pass on an empty corpus).

fn string_literals(src: &str) -> Vec<String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                let mut depth = 1;
                while i < b.len() && depth > 0 {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            // char literal or a lifetime (`&'a str`) — skip either without
            // mistaking the tick for a string delimiter
            b'\'' => i = skip_char_literal(b, i),
            b'r' if !is_ident_byte(i.checked_sub(1).map(|p| b[p])) => match raw_string(b, i) {
                Some((text, next)) => {
                    out.push(text);
                    i = next;
                }
                None => i += 1,
            },
            b'"' => match normal_string(b, i) {
                Some((text, next)) => {
                    out.push(text);
                    i = next;
                }
                None => i += 1,
            },
            _ => i += 1,
        }
    }
    out
}

fn is_ident_byte(b: Option<u8>) -> bool {
    b.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn skip_char_literal(b: &[u8], start: usize) -> usize {
    // 'x'  '\n'  '\''  '\u{1f}'  — anything else is a lifetime, one byte
    let mut i = start + 1;
    if i < b.len() && b[i] == b'\\' {
        i += 1;
        while i < b.len() && b[i] != b'\'' && b[i] != b'\n' {
            i += 1;
        }
        return if i < b.len() { i + 1 } else { i };
    }
    // single char followed by a closing tick
    let mut chars = b[i..].iter();
    if let Some(&c) = chars.next() {
        let width = utf8_width(c);
        if b.get(i + width) == Some(&b'\'') {
            return i + width + 1;
        }
    }
    start + 1
}

fn utf8_width(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

fn raw_string(b: &[u8], start: usize) -> Option<(String, usize)> {
    let mut i = start + 1;
    let mut hashes = 0usize;
    while b.get(i) == Some(&b'#') {
        hashes += 1;
        i += 1;
    }
    if b.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    let body_start = i;
    loop {
        if i >= b.len() {
            return None;
        }
        if b[i] == b'"'
            && b[i + 1..]
                .iter()
                .take(hashes)
                .filter(|c| **c == b'#')
                .count()
                == hashes
        {
            let text = String::from_utf8_lossy(&b[body_start..i]).into_owned();
            return Some((text, i + 1 + hashes));
        }
        i += 1;
    }
}

fn normal_string(b: &[u8], start: usize) -> Option<(String, usize)> {
    let mut i = start + 1;
    let mut raw = Vec::new();
    while i < b.len() {
        match b[i] {
            b'"' => {
                let text = String::from_utf8_lossy(&raw).into_owned();
                return Some((unescape(&text), i + 1));
            }
            b'\\' if i + 1 < b.len() => {
                raw.push(b[i]);
                raw.push(b[i + 1]);
                i += 2;
            }
            _ => {
                raw.push(b[i]);
                i += 1;
            }
        }
    }
    None
}

fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                match u8::from_str_radix(&hex, 16) {
                    Ok(v) => out.push(v as char),
                    Err(_) => out.push_str(&hex),
                }
            }
            Some('u') => {
                // \u{1f600}
                let braced: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let digits = braced.trim_start_matches('{');
                if let Some(c) = u32::from_str_radix(digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(c);
                }
            }
            // a line continuation swallows the newline and following indent
            Some('\n') => {
                for c in chars.by_ref() {
                    if !c.is_whitespace() {
                        out.push(c);
                        break;
                    }
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

#[test]
fn harvester_handles_the_literal_forms_the_corpus_uses() {
    let sample = r###"
        // a comment with "quotes" and a 'tick
        let a = "plain";
        let b = "with \"escapes\" and \n newline";
        let c = r"raw \no escapes";
        let d = r#"raw with "quotes" inside"#;
        let e = 'x';
        let f = '\'';
        fn g<'a>(s: &'a str) {}
        /* block "comment" */
        let h = "after block";
    "###;
    let found = string_literals(sample);
    assert!(found.contains(&"plain".to_string()), "{found:?}");
    assert!(
        found.contains(&"with \"escapes\" and \n newline".to_string()),
        "{found:?}"
    );
    assert!(found.contains(&r"raw \no escapes".to_string()), "{found:?}");
    assert!(
        found.contains(&r#"raw with "quotes" inside"#.to_string()),
        "{found:?}"
    );
    assert!(found.contains(&"after block".to_string()), "{found:?}");
    // the comment text must not have been harvested
    assert!(
        !found.iter().any(|f| f.contains("quotes\" and a")),
        "{found:?}"
    );
}
