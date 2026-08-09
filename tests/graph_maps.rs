//! Argument maps turning into reference edges — issue #13, sub-task 5.
//!
//! The claim under test: what an argument *means* comes from a reviewed map, and
//! from nowhere else. A program with a map produces reference edges; a program
//! without one produces silence.

use lictor::cmdmap::Maps;
use lictor::graph::{self, EdgeKind, Node};

/// Every reference edge, as `verb target`, for eyeball-readable assertions.
fn refs(src: &str) -> Vec<String> {
    let maps = Maps::builtin().expect("built-in maps are valid");
    let g = graph::lower_with_maps(src, &maps);
    let text = |id| match g.node(id) {
        Node::Value(v) => v.text.clone().unwrap_or_else(|| "<dynamic>".into()),
        Node::Flag(f) => f.name.clone(),
        Node::Command(c) => c.name.clone().unwrap_or_else(|| "<dynamic>".into()),
        _ => "?".into(),
    };
    g.edges
        .iter()
        .filter_map(|e| match e.kind {
            EdgeKind::Reads => Some(format!("reads {}", text(e.to))),
            EdgeKind::Writes => Some(format!("writes {}", text(e.to))),
            EdgeKind::Deletes => Some(format!("deletes {}", text(e.to))),
            EdgeKind::Creates => Some(format!("creates {}", text(e.to))),
            EdgeKind::Execs => Some(format!("execs {}", text(e.to))),
            _ => None,
        })
        .collect()
}

fn bindings(src: &str) -> Vec<String> {
    let maps = Maps::builtin().unwrap();
    let g = graph::lower_with_maps(src, &maps);
    g.edges
        .iter()
        .filter(|e| e.kind == EdgeKind::Takes)
        .map(|e| {
            let flag = match g.node(e.from) {
                Node::Flag(f) => f.name.clone(),
                _ => "?".into(),
            };
            let value = match g.node(e.to) {
                Node::Value(v) => v.text.clone().unwrap_or_else(|| "<dynamic>".into()),
                _ => "?".into(),
            };
            format!("{flag}={value}")
        })
        .collect()
}

#[test]
fn the_false_positives_from_issue_4_produce_no_path_claims() {
    // These are the exact commands #4 reported. Previously each was denied
    // because a leading `/` was taken as proof of a filesystem path; the map
    // says the word is a regex or a script, so no read edge exists to deny.
    assert_eq!(refs("sed -n '/needle/p' README.md"), ["reads README.md"]);
    assert_eq!(refs("awk '/error/ {print $2}' log.txt"), ["reads log.txt"]);
    assert_eq!(
        refs("grep -e '/api/v1/users' src/main.rs"),
        ["reads src/main.rs"]
    );

    // and the pattern really is bound to the flag, not floating free
    assert_eq!(
        bindings("grep -e '/api/v1/users' src/main.rs"),
        ["-e=/api/v1/users"]
    );
}

#[test]
fn a_flag_argument_stops_being_a_positional() {
    // the slot shift is the whole reason `takes` is a map fact: with `-e`
    // consuming the pattern, the file is slot 0, and without it the file is
    // slot 1
    assert_eq!(refs("grep -e pat file.rs"), ["reads file.rs"]);
    assert_eq!(refs("grep pat file.rs"), ["reads file.rs"]);
    assert_eq!(bindings("grep -e pat file.rs"), ["-e=pat"]);
    assert!(bindings("grep pat file.rs").is_empty());
}

#[test]
fn a_when_guard_decides_what_slot_zero_is() {
    // `grep PATTERN file` and `grep -e PATTERN file` disagree about slot 0.
    // Without the guard one of them is wrong: either the pattern is read as a
    // path, or the file loses its read edge.
    assert_eq!(refs("grep needle notes.txt"), ["reads notes.txt"]);
    assert_eq!(refs("grep -e needle notes.txt"), ["reads notes.txt"]);
}

#[test]
fn effects_are_a_set() {
    // `mv`'s source is read AND deleted; a rule about either has to see it.
    // This is why `effect` is a list rather than one value.
    assert_eq!(
        refs("mv old.rs new.rs"),
        [
            "reads old.rs",
            "deletes old.rs",
            "writes new.rs",
            "creates new.rs"
        ]
    );
}

#[test]
fn trailing_slot_binding_splits_sources_from_the_destination() {
    assert_eq!(
        refs("cp a.txt b.txt dest/"),
        [
            "reads a.txt",
            "reads b.txt",
            "writes dest/",
            "creates dest/"
        ]
    );
    // one source, one destination — `except-last` must not swallow everything
    assert_eq!(
        refs("cp only.txt dest.txt"),
        ["reads only.txt", "writes dest.txt", "creates dest.txt"]
    );
}

#[test]
fn a_wrapper_reaches_the_program_it_runs() {
    // The gap P2 surfaced: stage 1 lowered `sudo rm -rf x` as one command with
    // `rm` as an argument, so rm's own map was never consulted.
    assert_eq!(refs("sudo rm -rf /etc/x"), ["execs rm", "deletes /etc/x"]);
    assert_eq!(refs("env cat notes.txt"), ["execs cat", "reads notes.txt"]);
    assert_eq!(
        refs("xargs rm build/out"),
        ["execs rm", "deletes build/out"]
    );

    // and the wrapper's own flags do not become the payload
    assert_eq!(
        refs("sudo -u root rm /etc/x"),
        ["execs rm", "deletes /etc/x"]
    );
}

#[test]
fn a_subcommand_selects_its_own_map() {
    assert_eq!(refs("git rm src/a.rs"), ["deletes src/a.rs"]);
    assert_eq!(
        refs("git mv old.rs new.rs"),
        [
            "reads old.rs",
            "deletes old.rs",
            "writes new.rs",
            "creates new.rs"
        ]
    );
    // a subcommand with no map claims nothing, rather than falling back to some
    // generic notion of what `git` does
    assert!(refs("git log --oneline").is_empty());
}

#[test]
fn an_unmapped_program_produces_no_claims() {
    // the inverted default, stated directly
    assert!(refs("some-tool-nobody-mapped /etc/passwd").is_empty());
    assert!(refs("frobnicate --output /etc/shadow").is_empty());
}

#[test]
fn lowering_without_maps_still_produces_no_reference_edges() {
    // `lower` stays opinion-free: every claim enters through `apply_maps`, so a
    // caller with no maps gets exactly the stage-1 graph
    let g = graph::lower("rm -rf /etc/passwd");
    assert!(!g.edges.iter().any(|e| matches!(
        e.kind,
        EdgeKind::Reads
            | EdgeKind::Writes
            | EdgeKind::Deletes
            | EdgeKind::Creates
            | EdgeKind::Execs
    )));
    // ...and with maps, the same source does make a claim, so the check above is
    // not passing for the wrong reason
    assert_eq!(refs("rm -rf /etc/passwd"), ["deletes /etc/passwd"]);
}

#[test]
fn a_dynamic_argument_makes_no_claim_about_a_path_it_cannot_know() {
    // the value is unknowable, so there is nothing to point an edge at with any
    // confidence — the existing ask-rather-than-guess convention
    let maps = Maps::builtin().unwrap();
    let g = graph::lower_with_maps("rm $TARGET", &maps);
    let deletes: Vec<_> = g
        .edges
        .iter()
        .filter(|e| e.kind == EdgeKind::Deletes)
        .collect();
    // an edge may exist, but it must point at a value the graph admits it does
    // not know
    for edge in deletes {
        let Node::Value(v) = g.node(edge.to) else {
            panic!("a reference edge must point at a value")
        };
        assert!(
            v.text.is_none() && v.facts.dynamic,
            "expected a dynamic value"
        );
    }
}

#[test]
fn applying_maps_does_not_disturb_the_round_trip() {
    // P1 must still hold: maps add claims, never text
    let maps = Maps::builtin().unwrap();
    for src in [
        "grep -e pat file.rs",
        "sudo rm -rf /etc/x",
        "cp a b c/",
        "git rm x.rs",
        "cat <<EOF | grep secret\nbody\nEOF",
    ] {
        let g = graph::lower_with_maps(src, &maps);
        assert_eq!(g.emit(), src, "maps changed the emitted text for {src:?}");
        assert!(
            g.overlapping_segments().is_none(),
            "maps introduced overlapping segments for {src:?}"
        );
    }
}
