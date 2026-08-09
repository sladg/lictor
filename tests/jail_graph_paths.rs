//! `settings.jail_paths` — where the jail's idea of "this word is a path" comes
//! from. Issue #13, sub-task 8, first piece.
//!
//! Only that one decision moves to the graph. Resolution stays where it is:
//! `walk_words` tracks `cd` across a chain, expands `~`, collapses `..` and
//! descends into nested shells, and none of that is a heuristic worth replacing.
//!
//! # The graph source is NOT strictly better
//!
//! It trades one error for the other, and this file pins both directions:
//!
//! - it **removes false positives** — every case issue #4 reported goes silent,
//!   because a reviewed recipe says the word is a regex or a script
//! - it **introduces false negatives** — a program with no recipe references no
//!   paths at all, so a real escape through one is invisible
//!
//! Which is right depends entirely on recipe coverage, which is why the default
//! is unchanged and `compare` exists: run both, decide with the old one, and
//! record where they differ against real usage before touching anything.

use lictor::bash;
use lictor::modules::jail;

fn violations(mode: &str, command: &str) -> Vec<String> {
    let config = lictor::config::from_toml(
        &format!("[settings]\njail = \"deny\"\njail_paths = \"{mode}\"\n"),
        None,
    )
    .expect("policy parses");
    jail::violations(&bash::extract(command), &config, "/repo")
}

#[test]
fn the_graph_source_silences_every_case_issue_4_reported() {
    // Each of these was denied because a leading `/` was taken as proof of a
    // filesystem path. The recipes say otherwise, so there is no path to deny.
    for command in [
        "sed -n '/needle/p' README.md",
        "awk '/error/ {print $2}' log.txt",
        "grep -e '/api/v1/users' src/main.rs",
        "kubectl -n ns exec pod -c c -- grep -c x /etc/config/config.yaml",
        "ssh host cat /etc/hosts",
    ] {
        assert!(
            !violations("heuristic", command).is_empty(),
            "{command:?} should still be a false positive under the heuristic — \
             otherwise this test proves nothing"
        );
        assert!(
            violations("graph", command).is_empty(),
            "{command:?} still flagged under the graph source: {:?}",
            violations("graph", command)
        );
    }
}

#[test]
fn real_escapes_through_mapped_programs_are_still_caught() {
    // silence about a regex must not become silence about everything
    assert_eq!(violations("graph", "cat /etc/passwd"), ["/etc/passwd"]);
    assert_eq!(violations("graph", "rm -rf /etc/x"), ["/etc/x"]);
    assert_eq!(
        violations("graph", "cp /etc/shadow /tmp/x"),
        ["/etc/shadow", "/tmp/x"]
    );
}

#[test]
fn an_unmapped_program_is_invisible_to_the_graph_source() {
    // THE trade-off, stated rather than buried. A program with no recipe
    // references no paths, so the jail cannot see an escape through it. The
    // heuristic catches these precisely because it guesses.
    //
    // This is why the default is unchanged and why `compare` exists.
    for command in ["frobnicate /etc/passwd", "unmapped-tool --out /etc/shadow"] {
        assert!(
            !violations("heuristic", command).is_empty(),
            "{command:?} must be caught by the heuristic"
        );
        assert!(
            violations("graph", command).is_empty(),
            "{command:?} — if this ever starts being caught, the trade-off has \
             changed and the docs need updating"
        );
    }
}

#[test]
fn an_in_project_path_is_flagged_by_neither() {
    for mode in ["heuristic", "graph", "compare"] {
        assert!(violations(mode, "cat README.md").is_empty());
        assert!(violations(mode, "cat src/main.rs").is_empty());
    }
}

#[test]
fn compare_decides_with_the_heuristic() {
    // `compare` must change no decision at all — it only records. If it ever
    // returns the graph's answer, enabling it to measure the switch would BE
    // the switch.
    for command in [
        "sed -n '/needle/p' README.md",
        "cat /etc/passwd",
        "frobnicate /etc/passwd",
        "cat README.md",
    ] {
        assert_eq!(
            violations("compare", command),
            violations("heuristic", command),
            "compare changed the decision for {command:?}"
        );
    }
}

#[test]
fn the_default_is_unchanged() {
    // no `jail_paths` at all behaves exactly as `heuristic`
    let config = lictor::config::from_toml("[settings]\njail = \"deny\"\n", None).unwrap();
    for command in ["sed -n '/needle/p' README.md", "cat /etc/passwd"] {
        assert_eq!(
            jail::violations(&bash::extract(command), &config, "/repo"),
            violations("heuristic", command),
            "the default drifted from the heuristic for {command:?}"
        );
    }
}

#[test]
fn the_graph_source_catches_an_escape_the_heuristic_misses() {
    // Not only fewer false positives — a real false NEGATIVE closed.
    //
    // `cd /tmp && cat passwd` reads a file outside the project, but the
    // heuristic never even looks at `passwd`: the word has no `/`, no `~` and no
    // `..`, so it is not path-SHAPED and the guess declines. The graph does not
    // guess — cat's recipe says its argument is a path, so it resolves against
    // the cd-tracked base and lands outside the repo.
    // neither the bare name nor the `./` form is path-SHAPED, so the guess
    // declines to look at either
    for escape in ["cd /tmp && cat passwd", "cd /tmp && cat ./passwd"] {
        assert_eq!(
            violations("heuristic", escape),
            ["/tmp"],
            "if the heuristic starts catching {escape:?}, this comparison is moot"
        );
        assert_eq!(
            violations("graph", escape),
            ["/tmp", "/tmp/passwd"],
            "the graph source must see the file cat actually reads"
        );
    }
}

#[test]
fn cd_tracking_survives_the_switch() {
    // the resolution machinery is deliberately untouched: only the "is this a
    // path?" predicate moved, so a path-shaped word resolves identically
    // `../` IS path-shaped, so both sources look at it and must agree
    let escape = "cd /tmp && cat ../etc/passwd";
    assert_eq!(violations("graph", escape), violations("heuristic", escape));
    assert!(
        violations("graph", escape).contains(&"/etc/passwd".to_string()),
        "the cd-tracked base must still apply: {:?}",
        violations("graph", escape)
    );
}
