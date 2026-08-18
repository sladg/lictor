//! `settings.jail_paths` — where the jail's idea of "this word is a path" comes
//! from. Issue #13, sub-task 8, first piece; the graph became the only source
//! in #59.
//!
//! Only that one decision moved to the graph. Resolution stays where it is:
//! `walk_words` tracks `cd` across a chain, expands `~`, collapses `..` and
//! descends into nested shells, and none of that is a heuristic worth replacing.
//!
//! # The graph source is NOT strictly better
//!
//! It traded one error for the other, and this file pins both directions:
//!
//! - it **removes false positives** — every case issue #4 reported is silent,
//!   because a reviewed recipe says the word is a regex or a script
//! - it **introduces false negatives** — a program with no recipe references no
//!   paths at all, so a real escape through one is invisible

use lictor::bash;
use lictor::modules::jail;

fn violations(command: &str) -> Vec<String> {
    let config =
        lictor::config::from_toml("[settings]\njail = \"deny\"\n", None).expect("policy parses");
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
            violations(command).is_empty(),
            "{command:?} still flagged under the graph source: {:?}",
            violations(command)
        );
    }
}

#[test]
fn real_escapes_through_mapped_programs_are_still_caught() {
    // silence about a regex must not become silence about everything
    assert_eq!(violations("cat /etc/passwd"), ["/etc/passwd"]);
    assert_eq!(violations("rm -rf /etc/x"), ["/etc/x"]);
    assert_eq!(
        violations("cp /etc/shadow /tmp/x"),
        ["/etc/shadow", "/tmp/x"]
    );
}

#[test]
fn an_unmapped_program_is_invisible_to_the_graph_source() {
    // THE trade-off, stated rather than buried. A program with no recipe
    // references no paths, so the jail cannot see an escape through it. The
    // accepted remedy is a recipe addition, not shape-guessing.
    for command in ["frobnicate /etc/passwd", "unmapped-tool --out /etc/shadow"] {
        assert!(
            violations(command).is_empty(),
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
            violations(command),
            [expected],
            "{command:?} must be judged on its local side alone"
        );
    }
    // and a transfer with no local side at all is silent, rather than claiming
    // a bucket key is a file here
    assert!(violations("aws s3 rm s3://bucket/key").is_empty());
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
        extraction
            .graph
            .references()
            .iter()
            .map(|r| r.path.as_str())
            .collect::<Vec<_>>(),
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
fn a_redirect_target_is_a_path_the_jail_sees() {
    // Issue #29. A redirect target is not one of the command's WORDS, so the
    // walk the jail did never looked at it: `echo x >> /etc/hosts` writes
    // outside the project and was invisible.
    //
    // apply_redirects turns every write-redirect into Writes/Creates edges, so
    // the graph sees them through resolved_references.
    for (command, expected) in [
        ("echo x >> /etc/hosts", "/etc/hosts"),
        ("echo x > /etc/passwd", "/etc/passwd"),
        // an unmapped program cannot hide a write behind a redirect either
        ("frobnicate --quiet > /etc/passwd", "/etc/passwd"),
    ] {
        assert_eq!(
            violations(command),
            [expected],
            "{command:?} must be caught by the graph source"
        );
    }
    // read redirect (`<`): a word-shape guess never saw these, the graph does
    assert_eq!(violations("cat < /etc/shadow"), ["/etc/shadow"]);
    // ...and a redirect inside the project is still nobody's business
    assert!(
        violations("echo x > ./out.txt").is_empty(),
        "redirect inside project should pass"
    );
    // a descriptor dup names no file at all
    assert!(violations("cmd 2>&1").is_empty());
}

#[test]
fn an_in_project_path_is_flagged_by_neither() {
    assert!(violations("cat README.md").is_empty());
    assert!(violations("cat src/main.rs").is_empty());
}

#[test]
fn the_default_is_graph() {
    // no `jail_paths` at all behaves as `graph`, an explicit `"graph"` is a
    // validated no-op, and every other value is a config ERROR — the heuristic
    // died in #59, and a config asking for it must say so out loud rather than
    // silently switch sources
    let explicit = lictor::config::from_toml(
        "[settings]\njail = \"deny\"\njail_paths = \"graph\"\n",
        None,
    )
    .expect("explicit graph stays valid");
    for command in ["sed -n '/needle/p' README.md", "cat /etc/passwd"] {
        assert_eq!(
            jail::violations(&bash::extract(command), &explicit, "/repo"),
            violations(command),
            "explicit \"graph\" drifted from the default for {command:?}"
        );
    }
    for value in ["heuristic", "compare", "junk"] {
        let result = lictor::config::from_toml(
            &format!("[settings]\njail = \"deny\"\njail_paths = \"{value}\"\n"),
            None,
        );
        assert!(
            result.is_err(),
            "jail_paths = {value:?} must be a config error"
        );
    }
}

#[test]
fn the_graph_source_catches_an_escape_the_heuristic_missed() {
    // Not only fewer false positives — a real false NEGATIVE closed.
    //
    // `cd /tmp && cat passwd` reads a file outside the project, but the old
    // heuristic never even looked at `passwd`: the word had no `/`, no `~` and
    // no `..`, so it was not path-SHAPED and the guess declined. The graph does
    // not guess — cat's recipe says its argument is a path, so it resolves
    // against the cd-tracked base and lands outside the repo.
    for escape in ["cd /tmp && cat passwd", "cd /tmp && cat ./passwd"] {
        assert_eq!(
            violations(escape),
            ["/tmp", "/tmp/passwd"],
            "the graph source must see the file cat actually reads"
        );
    }
}

#[test]
fn cd_tracking_survives_the_switch() {
    // the resolution machinery is deliberately untouched: only the "is this a
    // path?" predicate moved, so a path-shaped word resolves identically
    let escape = "cd /tmp && cat ../etc/passwd";
    assert!(
        violations(escape).contains(&"/etc/passwd".to_string()),
        "the cd-tracked base must still apply: {:?}",
        violations(escape)
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
    for escape in [
        "bash -c 'cat /etc/passwd'",
        "sh -c 'rm -rf /etc/x'",
        "eval 'cat /etc/shadow'",
        "sudo bash -c 'cat /etc/passwd'",
        // the shells the old heuristic covered via bash.rs's SHELLS table and
        // the graph did not, until they got recipes of their own
        "zsh -c 'cat /etc/passwd'",
        "dash -c 'cat /etc/passwd'",
    ] {
        assert!(
            !violations(escape).is_empty(),
            "the graph source sees nothing in {escape:?} — the payload is a blind spot again"
        );
    }
}

#[test]
fn a_heredoc_fed_shell_is_not_a_blind_spot() {
    // Issue #36, #13 sub-task 2's remaining half: the body IS the script, so
    // the graph grafts it like a `-c` string instead of leaving it to the
    // on_inline_script ask. Quoting the delimiter suppresses expansion, not
    // execution, so both spellings graft.
    for escape in [
        "bash <<EOF\ncat /etc/passwd\nEOF",
        "bash <<'EOF'\ncat /etc/passwd\nEOF",
        "sudo bash <<EOF\ncat /etc/passwd\nEOF",
        "sh <<EOF\nrm -rf /etc/x\nEOF",
    ] {
        assert!(
            !violations(escape).is_empty(),
            "the graph source sees nothing in {escape:?} — the heredoc body is a blind spot"
        );
    }
    // a script positional flips the heredoc from script to DATA: the body is
    // process.sh's stdin, and claiming its words would be a false positive
    assert!(
        violations("bash process.sh <<EOF\ncat /etc/passwd\nEOF").is_empty(),
        "a heredoc feeding a script's stdin must not be lowered as commands"
    );
}

#[test]
fn an_interpreter_payload_is_still_not_re_parsed_as_shell() {
    // `shell` and `code` are separate kinds so that this stays silent: lowering
    // a python payload as bash would manufacture claims about a language this
    // parser cannot read.
    //
    // Silence is the right answer rather than a gap — this is the case
    // `on_inline_script` exists for, and it does speak ("inline python script
    // cannot be analyzed"). Asserting empty pins that the `shell` kind did not
    // quietly widen to every `-c` flag in every recipe.
    let payload = "python3 -c 'open(\"/etc/passwd\")'";
    assert_eq!(violations(payload), Vec::<String>::new());
}

#[test]
fn a_program_run_from_outside_the_jail_is_an_escape() {
    // A hole that predates the graph entirely: `walk_words` skips word 0, so
    // the jail never looked at the program word until the graph's Execs
    // references got ahead of it.
    for escape in ["/tmp/exploit.sh", "../../etc/evil.sh", "/tmp/x/../evil.sh"] {
        assert!(
            !violations(escape).is_empty(),
            "the graph source sees no program in {escape:?}"
        );
    }
}
