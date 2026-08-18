//! Declarative graph cases — the same idea as `tests/cases.rs` (issue #10),
//! applied to the graph instead of to hook decisions.
//!
//! A graph test is a command plus what the graph should claim about it. Written
//! as Rust that was ten lines of `assert_eq!(refs(…), [...])` per behaviour,
//! with the interesting part — the command and the claim — buried in
//! boilerplate. Written as data it is two lines, and a file of them reads as a
//! table of behaviour:
//!
//! ```toml
//! [[case]]
//! command = "aws s3 cp ./build s3://bucket/path"
//! expect  = { local = ["reads ./build"], remote = ["writes s3://bucket/path"] }
//! ```
//!
//! # What every case asserts for free
//!
//! **P1.** `emit()` must reproduce the source exactly, and no two nodes may
//! claim the same bytes. Every case is therefore also a round-trip case, which
//! is why the hand-written shape list in `graph_p1.rs` could go: adding a case
//! here adds a P1 case there.
//!
//! # Fields
//!
//! | field | meaning |
//! |---|---|
//! | `command` | the source to lower, with the built-in recipes applied |
//! | `edit` | apply an edit before asserting — see below |
//! | `expect.local` | every reference **on this machine**, as `"<effect> <target>"`, exact set |
//! | `expect.remote` | every reference somewhere else, same shape |
//! | `expect.commands` | the command nodes in source order: `"ssh"`, `"cat @host"`, `"rm @remote"`, `"rm !root"` |
//! | `expect.binds` | `Takes` edges, as `"<flag>=<value>"` — `"-e=pat"`, `"Out=/etc/passwd"` |
//! | `expect.flow` | connector edges, as `"cat --pipe--> grep"` |
//! | `expect.spawns` | `Spawns` edges, as `"sudo spawns rm"` |
//! | `expect.facts` | lexical facts, as `"<word> <fact>"` — `absolute`, `relative`, `glob`, `dynamic`, `literal`, `remote` |
//! | `expect.emit` | the emitted text; required when `edit` is set, and asserts P1 otherwise |
//!
//! An empty list is a real assertion — `local = []` means *this command claims
//! nothing about this machine*, which is most of what the recipes exist to get
//! right. An omitted field asserts nothing.
//!
//! # `edit` — P2 as data
//!
//! ```toml
//! edit   = { command = "grep", to = "rg" }
//! expect = { emit = "rg -n TODO src/main.rs", local = [] }
//! ```
//!
//! The edit is applied to the graph, the result is emitted, and **the emitted
//! text is re-parsed** — every other expectation describes that re-parsed
//! graph. That is `parse(emit(g′)) ≡ g′` with the intended graph written down
//! by a person instead of derived from the graph under test, which is the
//! stronger form: a derivation shares its bugs with the thing it checks.

use lictor::cmdmap::Maps;
use lictor::graph::{self, Connector, EdgeKind, Graph, Locality, Node, NodeId, Privilege};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseFile {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    issue: Option<u64>,
    #[serde(default)]
    case: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    #[serde(default)]
    name: Option<String>,
    command: String,
    #[serde(default)]
    edit: Option<Edit>,
    #[serde(default)]
    expect: Expect,
}

/// Replace one node's text, then assert against the **re-parsed** result.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    /// the program name to rewrite (`"grep"`)
    #[serde(default)]
    command: Option<String>,
    /// the argument to rewrite (`"src/main.rs"`)
    #[serde(default)]
    value: Option<String>,
    to: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    #[serde(default)]
    local: Option<Vec<String>>,
    #[serde(default)]
    remote: Option<Vec<String>>,
    #[serde(default)]
    commands: Option<Vec<String>>,
    #[serde(default)]
    binds: Option<Vec<String>>,
    #[serde(default)]
    flow: Option<Vec<String>>,
    #[serde(default)]
    spawns: Option<Vec<String>>,
    #[serde(default)]
    facts: Option<Vec<String>>,
    #[serde(default)]
    emit: Option<String>,
}

impl Expect {
    fn is_empty(&self) -> bool {
        self.local.is_none()
            && self.remote.is_none()
            && self.commands.is_none()
            && self.binds.is_none()
            && self.flow.is_none()
            && self.spawns.is_none()
            && self.facts.is_none()
            && self.emit.is_none()
    }
}

#[test]
fn declarative_graph_cases() {
    let files = case_files();
    assert!(
        !files.is_empty(),
        "no case files in tests/graph_cases — the runner would pass vacuously"
    );

    let mut failures = Vec::new();
    let mut ran = 0usize;
    for path in &files {
        let label = path.file_name().unwrap_or_default().to_string_lossy();
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{label}: cannot be read: {e}"));
        let file: CaseFile = match toml::from_str(&text) {
            Ok(file) => file,
            Err(e) => panic!("{label}: does not parse as a graph case file: {e}"),
        };
        assert!(
            !file.case.is_empty(),
            "{label}: contains no [[case]] entries"
        );

        for (i, case) in file.case.iter().enumerate() {
            ran += 1;
            if let Err(problems) = run_case(case) {
                let name = case.name.clone().unwrap_or_else(|| case.command.clone());
                let issue = file.issue.map(|n| format!(" (#{n})")).unwrap_or_default();
                let heading = file.name.as_deref().unwrap_or(&label);
                failures.push(format!(
                    "── {label}: {heading}{issue}\n   case #{}: {name}\n   command: {:?}\n{}",
                    i + 1,
                    case.command,
                    problems
                        .iter()
                        .map(|p| format!("     - {p}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {ran} graph cases failed:\n\n{}\n",
        failures.len(),
        failures.join("\n\n")
    );
    println!("{ran} graph cases passed across {} files", files.len());
}

fn case_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/graph_cases");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();
    files
}

/// Run one case, reporting every assertion that did not hold rather than only
/// the first.
fn run_case(case: &Case) -> Result<(), Vec<String>> {
    if case.expect.is_empty() {
        return Err(vec![
            "`expect` is empty — a case that asserts nothing passes forever".to_string(),
        ]);
    }
    let maps = Maps::builtin().expect("built-in recipes are valid");
    let graph = graph::lower_with_maps(&case.command, &maps);
    let mut problems = Vec::new();

    // P1, for free, on every case: the lowering must be able to give the source
    // back byte for byte, and no two nodes may believe they own the same text
    if let Some((a, b)) = graph.overlapping_segments() {
        problems.push(format!(
            "two nodes own overlapping bytes: {:?} and {:?}",
            a.text(&graph.source),
            b.text(&graph.source)
        ));
    }

    let graph = match &case.edit {
        None => {
            if graph.emit() != case.command {
                problems.push(format!(
                    "P1: emit() gave {:?}, not the source",
                    graph.emit()
                ));
            }
            if let Some(want) = &case.expect.emit
                && want != &case.command
            {
                problems.push(format!(
                    "`expect.emit` is {want:?} but no `edit` was applied — with no edit the \
                     emitted text is the source"
                ));
            }
            graph
        }
        Some(edit) => match apply_edit(&graph, edit) {
            Err(problem) => {
                problems.push(problem);
                graph
            }
            Ok(emitted) => {
                match &case.expect.emit {
                    Some(want) if want != &emitted => {
                        problems.push(format!("emitted {emitted:?}, expected {want:?}"));
                    }
                    None => problems.push(
                        "`edit` without `expect.emit` — the emitted text is the point of an edit"
                            .to_string(),
                    ),
                    _ => {}
                }
                // P2: what the emitted text re-parses to is what the rest of the
                // case describes
                graph::lower_with_maps(&emitted, &maps)
            }
        },
    };

    let mut check = |field: &str, want: &Option<Vec<String>>, got: Vec<String>| {
        let Some(want) = want else { return };
        let mut want = want.clone();
        let mut got = got;
        want.sort();
        got.sort();
        if want != got {
            problems.push(format!("{field}: expected {want:?}, got {got:?}"));
        }
    };
    let (local, remote) = references(&graph);
    check("local", &case.expect.local, local);
    check("remote", &case.expect.remote, remote);
    check("commands", &case.expect.commands, commands(&graph));
    check("binds", &case.expect.binds, binds(&graph));
    check("flow", &case.expect.flow, flow(&graph));
    check("spawns", &case.expect.spawns, spawns(&graph));
    check("facts", &case.expect.facts, facts(&graph));

    match problems.is_empty() {
        true => Ok(()),
        false => Err(problems),
    }
}

/// Locate the node an `edit` names and emit the result of replacing it.
fn apply_edit(graph: &Graph, edit: &Edit) -> Result<String, String> {
    let owner = match (&edit.command, &edit.value) {
        (Some(name), None) => {
            let (id, _) = graph
                .commands()
                .find(|(_, c)| c.name.as_deref() == Some(name.as_str()))
                .ok_or_else(|| format!("edit: no command named {name:?}"))?;
            // a command's own node owns nothing — the program word does
            let span = *graph
                .node(id)
                .spans()
                .first()
                .ok_or_else(|| format!("edit: command {name:?} has no spans"))?;
            graph
                .segment_owner(span)
                .ok_or_else(|| format!("edit: nothing owns {name:?}'s name span"))?
        }
        (None, Some(text)) => graph
            .nodes
            .iter()
            .enumerate()
            .find(|(_, n)| matches!(n, Node::Value(v) if v.text.as_deref() == Some(text.as_str())))
            .map(|(id, _)| id)
            .ok_or_else(|| format!("edit: no value {text:?}"))?,
        _ => return Err("edit: set exactly one of `command` or `value`".to_string()),
    };
    if graph.owned_spans(owner).len() != 1 {
        return Err("edit: that node owns more than one stretch of source".to_string());
    }
    let edits: HashMap<NodeId, String> = std::iter::once((owner, edit.to.clone())).collect();
    Ok(graph.emit_with(&edits))
}

/// Every reference, split by which machine it is about.
fn references(graph: &Graph) -> (Vec<String>, Vec<String>) {
    let mut local = Vec::new();
    let mut remote = Vec::new();
    for reference in graph.references() {
        let verb = match reference.effect {
            lictor::cmdmap::Effect::Read => "reads",
            lictor::cmdmap::Effect::Write => "writes",
            lictor::cmdmap::Effect::Delete => "deletes",
            lictor::cmdmap::Effect::Create => "creates",
            lictor::cmdmap::Effect::Exec => "execs",
            lictor::cmdmap::Effect::Env => "names",
        };
        // a set renders with `/**` when it reaches beneath its root, so a case
        // shows whether recursion was picked up
        let target = match graph.node(reference.target) {
            Node::PathSet(set) if set.set.recursive => format!("{}/**", set.set.roots.join(",")),
            _ => reference.path.clone(),
        };
        let line = format!("{verb} {target}");
        match reference.locality {
            Locality::Local => local.push(line),
            Locality::Remote => remote.push(line),
        }
    }
    (local, remote)
}

fn commands(graph: &Graph) -> Vec<String> {
    graph
        .commands()
        .map(|(_, cmd)| {
            let mut out = cmd.name.clone().unwrap_or_else(|| "<dynamic>".into());
            match (cmd.locality, &cmd.host) {
                (Locality::Remote, Some(host)) => out.push_str(&format!(" @{host}")),
                (Locality::Remote, None) => out.push_str(" @remote"),
                (Locality::Local, _) => {}
            }
            if cmd.privilege == Privilege::Elevated {
                out.push_str(" !root");
            }
            out
        })
        .collect()
}

fn binds(graph: &Graph) -> Vec<String> {
    graph
        .edges
        .iter()
        .filter(|e| e.kind == EdgeKind::Takes)
        .map(|e| {
            let from = match graph.node(e.from) {
                Node::Flag(flag) => flag.name.clone(),
                // a redirect binds its file the same way a flag binds its
                // argument
                Node::Stream(stream) => format!("{:?}", stream.kind),
                other => format!("{other:?}"),
            };
            format!("{from}={}", text_of(graph, e.to))
        })
        .collect()
}

fn flow(graph: &Graph) -> Vec<String> {
    graph
        .edges
        .iter()
        .filter_map(|e| match e.kind {
            EdgeKind::Flow(kind) => {
                let arrow = match kind {
                    Connector::Pipe => "pipe",
                    Connector::And => "and",
                    Connector::Or => "or",
                    Connector::Seq => "seq",
                };
                Some(format!(
                    "{} --{arrow}--> {}",
                    text_of(graph, e.from),
                    text_of(graph, e.to)
                ))
            }
            _ => None,
        })
        .collect()
}

fn spawns(graph: &Graph) -> Vec<String> {
    graph
        .edges
        .iter()
        .filter(|e| e.kind == EdgeKind::Spawns)
        .map(|e| format!("{} spawns {}", text_of(graph, e.from), text_of(graph, e.to)))
        .collect()
}

/// The lexical facts a word carries, one line per fact that is true.
fn facts(graph: &Graph) -> Vec<String> {
    let mut out = Vec::new();
    for node in &graph.nodes {
        let Node::Value(value) = node else { continue };
        let word = value.text.clone().unwrap_or_else(|| value.raw.clone());
        for (name, held) in [
            ("absolute", value.facts.absolute),
            ("relative", value.facts.relative),
            ("glob", value.facts.glob),
            ("literal", value.facts.literal),
            ("dynamic", value.facts.dynamic),
            ("remote", value.facts.locality == Locality::Remote),
        ] {
            if held {
                out.push(format!("{word} {name}"));
            }
        }
    }
    out
}

fn text_of(graph: &Graph, id: NodeId) -> String {
    match graph.node(id) {
        Node::Command(cmd) => cmd.name.clone().unwrap_or_else(|| "<dynamic>".into()),
        Node::Value(value) => value.text.clone().unwrap_or_else(|| "<dynamic>".into()),
        Node::Flag(flag) => flag.name.clone(),
        Node::PathSet(set) => set.set.roots.join(","),
        Node::Stream(stream) => format!("{:?}", stream.kind),
        Node::Heredoc(heredoc) => format!("<<{}", heredoc.delimiter),
        Node::Connector(connector) => format!("{:?}", connector.kind),
    }
}

// ── the harness's own failure modes, pinned like `cases.rs` pins its own ──

#[test]
fn an_empty_expect_is_rejected() {
    let case = Case {
        name: None,
        command: "grep x y".into(),
        edit: None,
        expect: Expect::default(),
    };
    let problems = run_case(&case).expect_err("an empty expect must fail");
    assert!(problems[0].contains("asserts nothing"), "{problems:?}");
}

#[test]
fn an_unknown_field_is_rejected() {
    // a typo'd `expect.locl` would otherwise assert nothing while looking like
    // it asserts something
    let err = toml::from_str::<CaseFile>(
        "[[case]]\ncommand = \"ls\"\nexpect = { locl = [\"reads x\"] }\n",
    )
    .expect_err("must reject");
    assert!(err.to_string().contains("unknown field"), "{err}");
}

#[test]
fn a_wrong_expectation_actually_fails() {
    // the harness is only worth trusting if it can fail
    let case = Case {
        name: None,
        command: "cat notes.txt".into(),
        edit: None,
        expect: Expect {
            local: Some(vec!["reads something-else".into()]),
            ..Default::default()
        },
    };
    let problems = run_case(&case).expect_err("a wrong expectation must fail");
    assert!(problems[0].starts_with("local:"), "{problems:?}");
}

#[test]
fn an_edit_without_an_expected_emit_is_rejected() {
    let case = Case {
        name: None,
        command: "grep x y".into(),
        edit: Some(Edit {
            command: Some("grep".into()),
            value: None,
            to: "rg".into(),
        }),
        expect: Expect {
            local: Some(vec![]),
            ..Default::default()
        },
    };
    let problems = run_case(&case).expect_err("must fail");
    assert!(
        problems.iter().any(|p| p.contains("expect.emit")),
        "{problems:?}"
    );
}
