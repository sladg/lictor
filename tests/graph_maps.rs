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
        // a set renders as its root, with `/**` when it reaches beneath it, so
        // an assertion shows whether recursion was picked up
        Node::PathSet(p) => {
            let root = p.set.roots.join(",");
            if p.set.recursive {
                format!("{root}/**")
            } else {
                root
            }
        }
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
fn the_remote_and_container_reports_from_issue_4_stay_silent() {
    // #4's opening example, verbatim. The paths after `exec ... --` are inside a
    // container; claiming them is the bug. kubectl's recipe maps only its
    // unambiguously local flags, so there is nothing to deny here.
    assert!(refs("kubectl -n ns exec pod -c c -- grep -c img /etc/config/config.yaml").is_empty());
    // ...and the same for a remote command over ssh
    assert!(refs("ssh host cat /etc/hosts").is_empty());

    // silence is not "the recipe does nothing": the local files these programs
    // really do open are still claimed
    assert_eq!(refs("kubectl apply -f deploy.yaml"), ["reads deploy.yaml"]);
    assert_eq!(
        refs("ssh -i /home/u/.ssh/id_ed25519 host uptime"),
        ["reads /home/u/.ssh/id_ed25519"]
    );
}

#[test]
fn a_first_argument_that_is_program_text_is_not_a_path() {
    // the #4 shape, across every program that has it
    assert_eq!(refs("jq '.items[] | .name' out.json"), ["reads out.json"]);
    assert_eq!(refs("find . -name '/etc/*'"), ["reads ./**"]);
    assert!(refs("sh -c 'rm -rf /tmp/x'").is_empty());
    // chmod's slot 0 is a mode, not a file called `0644`
    assert_eq!(refs("chmod 0644 src/main.rs"), ["writes src/main.rs"]);
}

#[test]
fn a_global_flag_cannot_hide_the_subcommand_behind_it() {
    // Found in real audit-log data: `git core.pager='!id'` appears as one of the
    // most frequent "subcommands" across 123k invocations, and is not a
    // subcommand at all — it is `-c`'s argument. Resolving the subcommand before
    // binding global flags picks the wrong map and silently drops every claim.
    assert_eq!(refs("git rm src/a.rs"), ["deletes src/a.rs"]);
    assert_eq!(
        refs("git -c core.pager=cat rm src/a.rs"),
        ["deletes src/a.rs"]
    );
    assert_eq!(
        refs("git -C /repo rm src/a.rs"),
        ["reads /repo", "deletes src/a.rs"]
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
    assert_eq!(
        refs("sudo rm -rf /etc/x"),
        ["execs rm", "deletes /etc/x/**"]
    );
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
fn a_wrapper_hands_its_payload_the_whole_line_including_flags() {
    // The payload used to be built from positionals only, which silently dropped
    // every flag: `sudo rm -rf x` lost the `-rf` and `sudo grep -e pat file`
    // bound nothing at all. The sharp case is a flag carrying a path —
    // `grep -f list` — where losing the binding also loses a real read edge.
    // the wrapped form adds `execs`, and is otherwise identical
    assert_eq!(
        refs("sudo grep -e pat file.rs"),
        ["execs grep", "reads file.rs"]
    );
    assert_eq!(refs("grep -e pat file.rs"), ["reads file.rs"]);
    assert_eq!(bindings("sudo grep -e pat file.rs"), ["-e=pat"]);
    assert_eq!(
        refs("sudo grep -f list.txt src.rs"),
        ["execs grep", "reads list.txt", "reads src.rs"]
    );
    // and the recursion flag survives the wrapper too
    assert_eq!(refs("sudo rm -rf build"), ["execs rm", "deletes build/**"]);
}

#[test]
fn a_recursive_flag_turns_a_path_into_a_tree() {
    // `rm build` names a file; `rm -r build` names everything beneath it, and a
    // rule about `build/**/*.o` has to be able to tell them apart
    assert_eq!(refs("rm build"), ["deletes build"]);
    assert_eq!(refs("rm -rf build"), ["deletes build/**"]);
    assert_eq!(
        refs("cp -r src dst"),
        ["reads src/**", "writes dst", "creates dst"]
    );
    // find descends by definition, with no flag to look for
    assert_eq!(refs("find . -name '*.rs'"), ["reads ./**"]);
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
fn a_nested_subcommand_selects_its_own_map() {
    // `aws s3 cp SRC DST` and `aws s3 rm KEY` share `s3` and agree about nothing
    // after it. One level of subcommand cannot tell them apart, and picking a
    // slot number that suits one is wrong for the other.
    assert_eq!(
        refs("aws s3 cp ./a.txt ./b.txt"),
        ["reads ./a.txt", "writes ./b.txt", "creates ./b.txt"]
    );
    assert_eq!(refs("aws s3 rm ./a.txt"), ["deletes ./a.txt"]);
    // a global flag still cannot hide the subcommand behind it — now for two
    // words rather than one
    assert_eq!(
        refs("aws --profile prod --region us-east-1 s3 cp ./a.txt s3://b/k"),
        ["reads ./a.txt"]
    );
    // a subcommand tree nobody mapped claims nothing
    assert!(refs("aws ec2 describe-instances --output json").is_empty());
    assert!(refs("aws s3 ls s3://bucket").is_empty());
}

#[test]
fn locality_resolves_each_side_of_one_positional_list() {
    // Issue #25. `aws s3 cp`, `kubectl cp` and `scp` all mix local and remote
    // references in ONE positional list, told apart only by a prefix. The same
    // slot is local in one spelling and remote in the other, so no map entry can
    // say which — the word has to carry it.
    assert_eq!(
        refs("aws s3 cp ./build s3://bucket/path"),
        ["reads ./build"]
    );
    assert_eq!(
        refs("aws s3 cp s3://bucket/path ./build"),
        ["writes ./build", "creates ./build"]
    );
    assert_eq!(
        refs("aws s3 mv ./a.txt s3://bucket/a.txt"),
        ["reads ./a.txt", "deletes ./a.txt"]
    );
    // `aws s3 rm s3://bucket/key` deletes nothing here, and the recipe maps the
    // slot as a delete — so the silence is locality's doing, not an absent entry
    assert!(refs("aws s3 rm s3://bucket/key").is_empty());

    // the same shape without a scheme, over ssh
    assert_eq!(refs("scp a.txt host:/tmp/"), ["reads a.txt"]);
    assert_eq!(refs("scp host:/etc/hosts ."), ["writes .", "creates ."]);
    assert_eq!(
        refs("scp user@host:/etc/shadow /tmp/x"),
        ["writes /tmp/x", "creates /tmp/x"]
    );
}

#[test]
fn a_colon_after_a_separator_is_still_a_local_path() {
    // the discriminator is a `:` BEFORE the first `/`. A path that merely
    // contains one is on this disk, and losing it would be a jail escape rather
    // than a false positive.
    assert_eq!(
        refs("cp ./a:b.txt /tmp/out"),
        ["reads ./a:b.txt", "writes /tmp/out", "creates /tmp/out"]
    );
    assert_eq!(refs("rm /var/log/a:b"), ["deletes /var/log/a:b"]);
    assert_eq!(refs("rm ~/a:b"), ["deletes ~/a:b"]);
}

#[test]
fn recursive_makes_the_local_side_a_path_set() {
    // #25's second requirement: `--recursive` names a tree, and a rule about
    // `build/**` has to be able to see the difference
    assert_eq!(
        refs("aws s3 cp ./build s3://bucket --recursive"),
        ["reads ./build/**"]
    );
    assert_eq!(refs("aws s3 cp ./build s3://bucket"), ["reads ./build"]);
    // sync always descends, with no flag to look for
    assert_eq!(refs("aws s3 sync ./dist s3://bucket"), ["reads ./dist/**"]);
    // and `--delete` on a sync DOWN removes local files the bucket does not have
    assert_eq!(
        refs("aws s3 sync s3://bucket ./dist --delete"),
        ["writes ./dist/**", "creates ./dist/**", "deletes ./dist/**"]
    );
    assert_eq!(
        refs("aws s3 sync s3://bucket ./dist"),
        ["writes ./dist/**", "creates ./dist/**"]
    );
    assert_eq!(refs("scp -r ./dir user@host:/srv"), ["reads ./dir/**"]);
}

#[test]
fn a_key_value_tool_claims_no_paths() {
    // kv's arguments are KEYS, and a key is free-form — `kv get
    // config/db/password` and `kv set /etc/thing v` name nothing on disk. It is
    // the third most-used command in the audit corpus, so getting this wrong
    // would be issue #4 at scale.
    assert!(refs("kv get config/db/password").is_empty());
    assert!(refs("kv set /etc/thing somevalue").is_empty());
    assert!(refs("kv copy a@src b@dst").is_empty());
    // `--db` consumes its value, so `mydb` is not mistaken for the subcommand
    assert!(refs("kv --db mydb get somekey").is_empty());
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
    assert_eq!(refs("rm -rf /etc/passwd"), ["deletes /etc/passwd/**"]);
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
        "aws s3 cp ./build s3://bucket/path --recursive",
        "scp -r host:/etc/ssh ./backup",
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
