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
fn a_transfer_is_judged_on_its_local_side_only() {
    // Issue #25, through the consumer that acts on it. `aws s3 cp` and `scp`
    // name both machines in one positional list, and the jail is a claim about
    // this one: the local side is a real escape, the bucket key and the far end
    // of the ssh connection are not paths here at all.
    for (command, expected) in [
        ("scp /etc/shadow host:/tmp/x", "/etc/shadow"),
        ("scp host:/etc/shadow /tmp/x", "/tmp/x"),
        ("aws s3 cp /etc/shadow s3://bucket/k", "/etc/shadow"),
        ("aws s3 sync s3://bucket /etc/cron.d", "/etc/cron.d"),
    ] {
        assert_eq!(
            violations("graph", command),
            [expected],
            "{command:?} must be judged on its local side alone"
        );
    }
    // and a transfer with no local side at all is silent, rather than claiming
    // a bucket key is a file here
    assert!(violations("graph", "aws s3 rm s3://bucket/key").is_empty());
}

#[test]
fn the_extraction_carries_the_graph_it_was_parsed_from() {
    // Sub-task 4. The jail used to re-parse the source to ask the graph
    // anything, so the two views of one command were two views of two parses.
    // Now `extract` lowers the tree it already has.
    let extraction = bash::extract("cat /etc/passwd | grep root");
    assert_eq!(
        extraction.graph.commands().count(),
        2,
        "the extraction must carry a lowered graph"
    );
    assert_eq!(
        extraction.graph.referenced_paths(),
        ["/etc/passwd"],
        "and the recipes must have been applied to it"
    );
    assert_eq!(
        extraction.graph.emit(),
        extraction.source,
        "P1 holds for the graph the extraction carries"
    );
}

#[test]
fn a_redirect_target_is_a_path_the_graph_can_see() {
    // Issue #29. A redirect target is not one of the command's WORDS, so the
    // walk the jail does never looked at it: `echo x >> /etc/hosts` writes
    // outside the project and was invisible to both sources.
    //
    // The graph models it — a redirect is shell syntax that opens a file
    // whatever the program is — and the graph source no longer lets the old
    // extractor's word list bound what it may say.
    for (command, expected) in [
        ("echo x >> /etc/hosts", "/etc/hosts"),
        ("echo x > /etc/passwd", "/etc/passwd"),
        ("cat < /etc/shadow", "/etc/shadow"),
        // an unmapped program cannot hide a write behind a redirect either
        ("frobnicate --quiet > /etc/passwd", "/etc/passwd"),
    ] {
        assert!(
            violations("heuristic", command).is_empty(),
            "{command:?} — if the heuristic starts catching this, the comparison is moot"
        );
        assert_eq!(
            violations("graph", command),
            [expected],
            "{command:?} must be caught by the graph source"
        );
    }
    // ...and a redirect inside the project is still nobody's business
    assert!(violations("graph", "echo x > ./out.txt").is_empty());
    // a descriptor dup names no file at all
    assert!(violations("graph", "cmd 2>&1").is_empty());
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

#[test]
fn a_nested_shell_payload_is_not_a_blind_spot() {
    // The gap that made the graph source unshippable as a default: a `-c` script
    // claimed NOTHING, so `bash -c 'cat /etc/passwd'` went from deny to silence
    // the moment the jail took path identity from the graph.
    //
    // It was also the one interpreter form with no backstop. `on_inline_script`
    // covers a shell reading its script from stdin or a heredoc, and it stays
    // quiet here precisely BECAUSE the payload parses.
    //
    // Asserting both sources, not just the graph, is the point: this is a
    // regression test against the graph falling behind, and comparing it to the
    // heuristic is what keeps it honest.
    for escape in [
        "bash -c 'cat /etc/passwd'",
        "sh -c 'rm -rf /etc/x'",
        "eval 'cat /etc/shadow'",
        "sudo bash -c 'cat /etc/passwd'",
        // the shells the heuristic covered via bash.rs's SHELLS table and the
        // graph did not, until they got recipes of their own
        "zsh -c 'cat /etc/passwd'",
        "dash -c 'cat /etc/passwd'",
    ] {
        assert!(
            !violations("graph", escape).is_empty(),
            "the graph source sees nothing in {escape:?} — the payload is a blind spot again"
        );
        assert!(
            !violations("heuristic", escape).is_empty(),
            "the heuristic stopped catching {escape:?}, so this comparison is moot"
        );
    }
}

#[test]
fn an_interpreter_payload_is_still_not_re_parsed_as_shell() {
    // `shell` and `code` are separate kinds so that this stays silent: lowering
    // a python payload as bash would manufacture claims about a language this
    // parser cannot read.
    //
    // NEITHER source flags it, and that is the right answer rather than a gap —
    // this is the case `on_inline_script` exists for, and it does speak ("inline
    // python script cannot be analyzed"). Asserting both are empty pins that the
    // `shell` kind did not quietly widen to every `-c` flag in every recipe.
    let payload = "python3 -c 'open(\"/etc/passwd\")'";
    assert_eq!(violations("graph", payload), Vec::<String>::new());
    assert_eq!(violations("heuristic", payload), Vec::<String>::new());
}
