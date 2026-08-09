//! **P2** — edit soundness. Issue #13, sub-task 3.
//!
//! `parse(emit(g′)) ≡ g′`: apply an edit to the graph, emit the result, re-parse
//! it, and the graph you get back must make the same claims as the graph you
//! meant to produce. This is the gate the issue names as required *before* any
//! rewrite feature exists, because a rewrite that emits text which re-parses
//! into a different command is exactly the #7 bug — `grep -n TODO x` becoming
//! `rg TODO x`, one flag quietly gone.
//!
//! P1 (`emit(parse(s)) == s`) says the lowering is faithful when nothing
//! changes. It says nothing about what happens once you change something, which
//! is the only case a rewrite cares about.
//!
//! ## What "≡" means here
//!
//! [`Graph::fingerprint`] — the claims, with node ids and byte offsets removed.
//! An edit moves every span after it and a re-parse renumbers every node, so
//! comparing either would make the property trivially false while saying
//! nothing about soundness.
//!
//! ## The trap this gate is built against
//!
//! P1 was satisfiable by a lowering that modelled nothing, so it needed a
//! coverage check bolted on before it caught anything. P2 has the same shape: a
//! rewrite that changed *nothing* would round-trip perfectly. So every assertion
//! below first checks that the edit actually took effect — `edits_must_actually
//! _change_something` fails the whole gate if the corpus ever stops exercising
//! it.

use lictor::graph::{self, Graph, Node};
use std::collections::HashMap;

const CORPUS: &[(&str, &str)] = &[
    ("tests/commands.rs", include_str!("commands.rs")),
    ("tests/redteam.rs", include_str!("redteam.rs")),
    ("tests/exploits.rs", include_str!("exploits.rs")),
];

/// A benign single token. Deliberately not a real program name: it must not
/// collide with anything the corpus already contains, or a fingerprint could
/// match by accident.
const TOKEN: &str = "zqx";

#[test]
fn p2_rewriting_a_program_name_is_sound() {
    // the exact operation `action = "rewrite"` performs, over every command in
    // the corpus
    let mut checked = 0usize;
    for (file, source) in CORPUS {
        for literal in string_literals(source) {
            let g = graph::lower(&literal);
            for (ordinal, (id, _)) in g.commands().enumerate() {
                let Some(before) = renameable(&g, id) else {
                    continue;
                };
                let edits: HashMap<_, _> = std::iter::once((id, TOKEN.to_string())).collect();
                let emitted = g.emit_with(&edits);

                let expected = expect_renamed(&g, ordinal, TOKEN);
                let actual = graph::lower(&emitted).fingerprint();
                assert_eq!(
                    actual, expected,
                    "P2 violated in {file}\n  source:   {literal:?}\n  \
                     renamed:  cmd[{ordinal}] {before} -> {TOKEN}\n  emitted:  {emitted:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > 200,
        "expected the corpus to yield many renameable commands, got {checked}"
    );
    println!("P2 verified over {checked} program-name rewrites");
}

#[test]
fn p2_rewriting_an_argument_is_sound() {
    let mut checked = 0usize;
    for (file, source) in CORPUS {
        for literal in string_literals(source) {
            let g = graph::lower(&literal);
            for (id, node) in g.nodes.iter().enumerate() {
                let Node::Value(value) = node else { continue };
                // only literal, contiguous, single-token values: replacing a
                // dynamic or multi-part word changes the structure legitimately,
                // so it is not a P2 counterexample
                let Some(text) = value.text.as_deref().filter(|t| is_plain_token(t)) else {
                    continue;
                };
                if g.owned_spans(id).len() != 1 {
                    continue;
                }
                // only values bound as a positional argument: those have exactly
                // one fingerprint line, so the expected graph is unambiguous
                let Some(line) = arg_line(&g, id) else {
                    continue;
                };
                let edits: HashMap<_, _> = std::iter::once((id, TOKEN.to_string())).collect();
                let emitted = g.emit_with(&edits);
                let expected = substitute(&g.fingerprint(), &line, &replace_after_eq(&line, TOKEN));
                let actual = graph::lower(&emitted).fingerprint();
                assert_eq!(
                    actual, expected,
                    "P2 violated in {file}\n  source:  {literal:?}\n  \
                     value:   {text:?} -> {TOKEN}\n  emitted: {emitted:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > 200,
        "expected many editable values, got {checked}"
    );
    println!("P2 verified over {checked} argument rewrites");
}

#[test]
fn p2_holds_for_the_shapes_that_broke_earlier_consumers() {
    // one row per bug where an edit or a structural read went wrong
    for (src, want) in [
        // #7: the flag must survive a program-name rewrite
        ("grep -n TODO src/main.rs", "zqx -n TODO src/main.rs"),
        // `sudo` IS command[0] here: the graph has no wrapper map yet, so `grep`
        // is one of sudo's arguments rather than a command of its own. Targeting
        // the inner program needs the `Execs` edge from sub-task 5 — worth
        // knowing before `rewrite` is moved onto the graph.
        ("sudo grep foo /var/log/x", "zqx grep foo /var/log/x"),
        // #12: a heredoc must not swallow the edit or the rest of the pipeline
        (
            "cat <<EOF | grep secret\nline one\nEOF",
            "zqx <<EOF | grep secret\nline one\nEOF",
        ),
        // the discontiguous-span case: only the string's own bytes move
        ("echo \"pre $(id) post\"", "zqx \"pre $(id) post\""),
        ("a | b | c", "zqx | b | c"),
        ("a && b || c", "zqx && b || c"),
        ("cmd 2>&1 | tee log.txt", "zqx 2>&1 | tee log.txt"),
    ] {
        let g = graph::lower(src);
        let (id, _) = g.commands().next().expect("a first command");
        let edits: HashMap<_, _> = std::iter::once((id, TOKEN.to_string())).collect();
        assert_eq!(g.emit_with(&edits), want, "emit differs for {src:?}");

        // and the emitted text must re-parse to the same claims
        let after = graph::lower(&g.emit_with(&edits)).fingerprint();
        assert_eq!(
            after,
            expect_renamed(&g, 0, TOKEN),
            "P2 violated for {src:?}"
        );
    }
}

#[test]
fn edits_must_actually_change_something() {
    // The trap P1 fell into: a gate that a no-op satisfies proves nothing. If
    // `emit_with` ever silently stopped applying replacements, both properties
    // above would still pass — every fingerprint would match the unedited one.
    let g = graph::lower("grep -n TODO src/main.rs");
    let (id, _) = g.commands().next().unwrap();
    let edits: HashMap<_, _> = std::iter::once((id, TOKEN.to_string())).collect();
    let emitted = g.emit_with(&edits);
    assert_ne!(emitted, "grep -n TODO src/main.rs", "the edit did nothing");
    assert!(emitted.contains(TOKEN), "the replacement never appeared");
    assert_ne!(
        graph::lower(&emitted).fingerprint(),
        g.fingerprint(),
        "the edit did not change what the graph claims"
    );
}

#[test]
fn fingerprint_ignores_ids_and_spans_but_not_meaning() {
    // the same command written at a different offset makes the same claims...
    let a = graph::lower("grep -n TODO x");
    let b = graph::lower("  grep -n TODO x");
    assert_eq!(
        a.fingerprint(),
        b.fingerprint(),
        "leading space changed the claims"
    );

    // ...while a genuinely different command does not
    for other in [
        "grep -n TODO y",      // different argument
        "grep -m TODO x",      // different flag
        "rg -n TODO x",        // different program
        "grep -n TODO x | wc", // an extra stage
    ] {
        assert_ne!(
            a.fingerprint(),
            graph::lower(other).fingerprint(),
            "fingerprint failed to distinguish {other:?}"
        );
    }
}

// ── helpers ──

/// The command's own name span, when it is a single contiguous literal.
///
/// A name split by a substitution (`$(which git) --version`) owns several
/// segments, and replacing it would write the token into each — a real
/// limitation of the current edit API rather than a P2 counterexample, so those
/// are skipped rather than asserted on.
fn renameable(g: &Graph, id: usize) -> Option<String> {
    let Node::Command(cmd) = g.node(id) else {
        return None;
    };
    let name = cmd.name.clone()?;
    // `cmd.spans` is the union of the name AND every argument, so checking it
    // here would restrict this to argument-less commands and quietly shrink the
    // gate to a fraction of the corpus. What matters is the segments the command
    // actually owns, which is just its name.
    (g.owned_spans(id).len() == 1 && is_plain_token(&name)).then_some(name)
}

/// A single shell word with no quoting, expansion or operator in it. Replacing
/// anything else changes the parse for reasons that have nothing to do with
/// edit soundness.
fn is_plain_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
}

fn substitute(fingerprint: &[String], from: &str, to: &str) -> Vec<String> {
    let mut out: Vec<String> = fingerprint
        .iter()
        .map(|line| {
            if line == from {
                to.to_string()
            } else {
                line.clone()
            }
        })
        .collect();
    out.sort();
    out
}

fn replace_after_eq(line: &str, to: &str) -> String {
    match line.rsplit_once('=') {
        Some((head, _)) => format!("{head}={to}"),
        None => line.to_string(),
    }
}

/// The graph `g` would have if command `ordinal` were renamed to `to`.
///
/// Built by rewriting the one fingerprint line that names it, rather than by
/// mutating the graph — the point is to state the expectation independently of
/// the machinery under test.
fn expect_renamed(g: &Graph, ordinal: usize, to: &str) -> Vec<String> {
    let prefix = format!("cmd[{ordinal}] name=");
    let mut out: Vec<String> = g
        .fingerprint()
        .iter()
        .map(|line| match line.strip_prefix(&prefix) {
            // privilege is DERIVED from the name, so renaming recomputes it —
            // `sudo x` renamed to a plain token is no longer elevated, and
            // carrying the old value over would assert the wrong graph
            Some(_) => format!("{prefix}{to} priv=Normal"),
            None => line.clone(),
        })
        .collect();
    out.sort();
    out
}

/// The single fingerprint line for a value bound as a positional argument.
///
/// Values reached through a flag (`--color=auto`) or used twice in different
/// commands would need more than one line changed, so they are skipped rather
/// than approximated — an approximated expectation is not an expectation.
fn arg_line(g: &Graph, value: usize) -> Option<String> {
    let ordinal: HashMap<usize, usize> = g
        .commands()
        .enumerate()
        .map(|(i, (id, _))| (id, i))
        .collect();
    let edge = g.edges.iter().find(|e| {
        e.to == value && matches!(e.kind, lictor::graph::EdgeKind::Arg(n) if n != usize::MAX)
    })?;
    let lictor::graph::EdgeKind::Arg(slot) = edge.kind else {
        return None;
    };
    let owner = ordinal.get(&edge.from)?;
    let Node::Value(v) = g.node(value) else {
        return None;
    };
    Some(format!("cmd[{owner}] arg[{slot}]={}", v.text.as_deref()?))
}

// ── the corpus harvester, shared in spirit with tests/graph_p1.rs ──
//
// Duplicated rather than shared: integration tests are separate crates, and a
// `tests/common/` module would be pulled into every one of them.

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
    let mut i = start + 1;
    if i < b.len() && b[i] == b'\\' {
        i += 1;
        while i < b.len() && b[i] != b'\'' && b[i] != b'\n' {
            i += 1;
        }
        return if i < b.len() { i + 1 } else { i };
    }
    if let Some(&c) = b.get(i) {
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
            return Some((
                String::from_utf8_lossy(&b[body_start..i]).into_owned(),
                i + 1 + hashes,
            ));
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
                return Some((unescape(&String::from_utf8_lossy(&raw)), i + 1));
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
                let braced: String = chars.by_ref().take_while(|c| *c != '}').collect();
                if let Some(c) = u32::from_str_radix(braced.trim_start_matches('{'), 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(c);
                }
            }
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
