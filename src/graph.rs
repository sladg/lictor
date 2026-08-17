//! Typed graph IR for bash commands — issue #13, sub-task 1.
//!
//! `bash::Command` is a flat, context-free word list, so every consumer that
//! needs structure re-derives it from the CST and each one rediscovers the same
//! bugs independently (#4, #7, #8, #12). This module lowers the CST **once**
//! into a typed node/edge graph that rules can query instead.
//!
//! Stage 1 is deliberately inert: nothing here is wired into the engine and no
//! behaviour changes. It exists so the model can be proven faithful before
//! anything depends on it. The merge gate is **P1** — `emit(lower(s)) == s` for
//! every command string the test corpus knows about (see `tests/graph_p1.rs`).
//!
//! ## What is *not* populated here, on purpose
//!
//! The reference edges (`Reads`/`Writes`/`Deletes`/`Creates`/`Execs`,
//! `Filters`) and `PathSet` nodes come from hand-written per-program argument
//! maps, which are sub-tasks 5 and 6. Until a program has a map it gets no
//! reference edges, and lictor says nothing about it. That inverts today's
//! default, where every `/`-leading word is assumed to be a filesystem path —
//! the wrong default that #4 has been patched around four times.
//!
//! The same reasoning applies within a command: a flag's argument is bound with
//! a `Takes` edge only when the syntax settles it (`--color=auto`). Whether
//! `-e` in `grep -e foo` consumes the next word is a *map* question, so stage 1
//! records `foo` as a plain positional rather than guessing.

use std::collections::HashMap;
use tree_sitter::Node as TsNode;

pub type NodeId = usize;

/// A half-open byte range into [`Graph::source`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    fn of(node: TsNode) -> Self {
        let r = node.byte_range();
        Span {
            start: r.start,
            end: r.end,
        }
    }

    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        &source[self.start..self.end]
    }
}

/// How a command relates to the neighbour it is joined to.
///
/// A connector is a node rather than an edge label alone because sub-task 10
/// (`insert`) needs to *address* one — splicing a stage into `cargo test | less`
/// means naming the `|` and inserting beside it. It therefore owns its own span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    Pipe,
    And,
    Or,
    Seq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    Normal,
    /// invoked through `sudo`/`doas`/`pkexec`
    Elevated,
}

/// Whether something is on *this* machine.
///
/// On a [`ValueNode`] this is decided lexically, by [`locality_of`]: the word
/// carries a location prefix or it does not. On a [`CommandNode`] it comes from
/// the recipe — a program that names a machine and runs a nested command runs it
/// **there**, so `ssh host cat /etc/hosts` lowers `cat` as a remote command and
/// its `/etc/hosts` is a remote read.
///
/// A reference is remote if *either* end says so, which is what
/// [`Graph::references`] computes. The two are genuinely independent:
/// `ssh host cat ./notes` has a local-looking word on a remote command, and
/// `aws s3 rm s3://b/k` has a remote word on a local one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locality {
    #[default]
    Local,
    Remote,
}

impl Locality {
    /// The stronger of the two — anything touched by a remote end is remote.
    pub fn or(self, other: Locality) -> Locality {
        match (self, other) {
            (Locality::Local, Locality::Local) => Locality::Local,
            _ => Locality::Remote,
        }
    }

    pub fn is_remote(self) -> bool {
        self == Locality::Remote
    }
}

/// A reference to something that is not on this machine, split into the parts a
/// rule would want to match on.
///
/// Nothing configures these yet — there is no `[[remote]]` rule surface and this
/// PR does not add one. The graph models them anyway, because the alternative is
/// what it did before: drop the edge, and conflate *"this is somewhere else"*
/// with *"this does not happen"*. Only the first is true, and a graph that
/// cannot say `aws s3 rm s3://prod-bucket/key` deletes a key in `prod-bucket`
/// cannot ever grow a rule that cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRef {
    /// `s3` for `s3://bucket/key`; `None` for `host:/tmp`, which has no scheme
    pub scheme: Option<String>,
    /// the machine, bucket or pod: `bucket`, `user@host`, `ns/pod`
    pub authority: String,
    /// the path within it — `/key`, `/tmp`. Empty when the word named none
    /// (`scp file host:`)
    pub path: String,
}

impl RemoteRef {
    /// Split a word carrying a location prefix. `None` when it carries none, so
    /// this doubles as the locality test — one rule, not two that can drift.
    pub fn parse(word: &str) -> Option<RemoteRef> {
        // every word that can name something outside the working directory
        // starts with one of these, and a colon is legal in a filename
        if word.starts_with(['/', '~', '.']) {
            return None;
        }
        if let Some((scheme, rest)) = word.split_once("://") {
            let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
            return Some(RemoteRef {
                scheme: Some(scheme.to_string()),
                authority: authority.to_string(),
                // the `/` belongs to the path, not to the separator
                path: match path {
                    "" => String::new(),
                    p => format!("/{p}"),
                },
            });
        }
        let (authority, path) = word.split_once(':')?;
        Some(RemoteRef {
            scheme: None,
            authority: authority.to_string(),
            path: path.to_string(),
        })
    }
}

/// Redirection direction. `Heredoc` is modelled separately — it carries a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// `< file`
    In,
    /// `> file`, `N> file`
    Out,
    /// `>> file`
    Append,
    /// `&> file`, `>&`
    Both,
    /// `2>&1` and friends — a descriptor dup, not a file at all
    Dup,
    /// `<<< word`
    HereString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    Include,
    Exclude,
}

/// Lexical facts about a word, decided without touching the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ValueFacts {
    /// begins with `/`, and names a path on this machine
    pub absolute: bool,
    /// a path-shaped word on this machine that is not absolute (`src/x`,
    /// `../y`, `~/z`)
    pub relative: bool,
    /// contains an unquoted glob metacharacter
    pub glob: bool,
    /// fully static — every byte is known at parse time. Exception: `$HOME/x`
    /// is lowered to `~/x` and comes out `literal: true, dynamic: false` even
    /// though the source is a variable reference. No current consumer reads this
    /// field, so the inconsistency is latent; widen the model if one arises.
    pub literal: bool,
    /// contains an expansion or substitution, so the value is not knowable
    pub dynamic: bool,
    /// which machine's filesystem the word names, from its prefix alone —
    /// `s3://bucket/key` and `host:/tmp` are somewhere else
    pub locality: Locality,
}

#[derive(Debug, Clone)]
pub struct CommandNode {
    /// Every span this command owns, in source order. A **list**, not one
    /// range: `cat <<EOF | grep x` puts the pipeline *inside* the heredoc in
    /// the CST, so a command's text is genuinely discontiguous, and an edit to
    /// one segment must leave the others alone (the #7 failure mode).
    pub spans: Vec<Span>,
    /// resolved program name; `None` when the name itself is dynamic
    pub name: Option<String>,
    /// where this command runs. `Remote` only ever comes from a recipe — see
    /// [`Locality`]
    pub locality: Locality,
    /// the machine it runs on, when it is not this one: the host word from
    /// `ssh HOST …`, the pod from `kubectl exec POD …`
    pub host: Option<String>,
    pub privilege: Privilege,
}

#[derive(Debug, Clone)]
pub struct FlagNode {
    pub spans: Vec<Span>,
    /// `--color` for `--color=auto`; `-n` for `-n`
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ValueNode {
    pub spans: Vec<Span>,
    /// resolved text with quoting removed; `None` when dynamic
    pub text: Option<String>,
    /// source as written — deny globs match against syntax, not just value
    pub raw: String,
    pub facts: ValueFacts,
    /// the word split into machine and path, when it carries a location prefix.
    /// `Some` exactly when `facts.locality` is `Remote` — both come from
    /// [`RemoteRef::parse`], so they cannot disagree
    pub remote: Option<RemoteRef>,
}

#[derive(Debug, Clone)]
pub struct StreamNode {
    pub spans: Vec<Span>,
    pub kind: StreamKind,
}

#[derive(Debug, Clone)]
pub struct HeredocNode {
    pub spans: Vec<Span>,
    /// delimiter as written, quotes stripped: `EOF` for `<<'EOF'`
    pub delimiter: String,
    /// `<<'EOF'` / `<<"EOF"` — a quoted delimiter suppresses expansion in the
    /// body, which is what decides whether the body can be re-parsed as shell
    pub quoted: bool,
    /// `<<-` strips leading tabs from the body
    pub strip_tabs: bool,
    /// the body itself, absent for an unterminated heredoc
    pub body: Option<Span>,
}

#[derive(Debug, Clone)]
pub struct ConnectorNode {
    pub spans: Vec<Span>,
    pub kind: Connector,
}

/// A set of paths named by one argument — `rm -rf build` is not one path, it is
/// everything beneath it.
///
/// Wraps [`crate::globs::PathSet`] rather than restating its fields: the same
/// four values declared in two places is how the two drift, and asking "does
/// this set contain anything the rule cares about?" is `globs`' job.
#[derive(Debug, Clone)]
pub struct PathSetNode {
    pub spans: Vec<Span>,
    pub set: crate::globs::PathSet,
    /// carried from the word the set was built from, so a recursive transfer
    /// models both ends — `aws s3 cp s3://b/prefix ./x --recursive` is a remote
    /// tree read into a local tree
    pub locality: Locality,
    pub remote: Option<RemoteRef>,
}

#[derive(Debug, Clone)]
pub enum Node {
    Command(CommandNode),
    Flag(FlagNode),
    Value(ValueNode),
    Stream(StreamNode),
    Heredoc(HeredocNode),
    Connector(ConnectorNode),
    PathSet(PathSetNode),
}

impl Node {
    pub fn spans(&self) -> &[Span] {
        match self {
            Node::Command(n) => &n.spans,
            Node::Flag(n) => &n.spans,
            Node::Value(n) => &n.spans,
            Node::Stream(n) => &n.spans,
            Node::Heredoc(n) => &n.spans,
            Node::Connector(n) => &n.spans,
            Node::PathSet(n) => &n.spans,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// command → flag
    Has,
    /// flag → value, when the syntax binds them (`--color=auto`). Separated
    /// forms wait for the argument map — see the module note.
    Takes,
    /// command → value, positional index among non-flag words
    Arg(usize),
    /// command → command, joined by a connector (carried on the edge so a
    /// traversal can ask "piped into" without re-deriving it)
    Flow(Connector),
    /// command → command it starts in a fresh parse: a `$(…)` substitution, a
    /// wrapper's payload (`sudo rm x`), or a shell script argument re-parsed and
    /// grafted in (`bash -c '…'`, `eval '…'`). A heredoc body fed to a shell's
    /// stdin is the one form still missing — see issue #36.
    Spawns,
    /// stream/heredoc → the command it attaches to
    On,
    // ── reference edges: sub-task 5+, never emitted without an argument map ──
    Reads,
    Writes,
    Deletes,
    Creates,
    Execs,
    Filters(FilterKind),
}

#[derive(Debug, Clone, Copy)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
}

/// A command's place in its chain — what `piped_into`, `with` and `position`
/// are asking about. See [`Graph::groups`].
#[derive(Debug, Clone)]
pub struct Group {
    /// every command in the chain, in source order, this one included
    pub members: Vec<NodeId>,
    /// index of this command among them
    pub position: usize,
    /// how this command is attached to its neighbour; `None` when it stands
    /// alone
    pub connector: Option<Connector>,
}

impl Group {
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

/// One reference edge, flattened into the facts a caller asks about: what is
/// touched, how, and **where it is**.
#[derive(Debug, Clone)]
pub struct Reference {
    pub command: NodeId,
    pub target: NodeId,
    pub effect: crate::cmdmap::Effect,
    /// remote if *either* the command or the word says so
    pub locality: Locality,
    /// the path as written — the whole word, `s3://bucket/key` included
    pub path: String,
    /// the split form, when this names something on another machine
    pub remote: Option<RemoteRef>,
}

fn effect_of(kind: EdgeKind) -> Option<crate::cmdmap::Effect> {
    use crate::cmdmap::Effect;
    match kind {
        EdgeKind::Reads => Some(Effect::Read),
        EdgeKind::Writes => Some(Effect::Write),
        EdgeKind::Deletes => Some(Effect::Delete),
        EdgeKind::Creates => Some(Effect::Create),
        EdgeKind::Execs => Some(Effect::Exec),
        _ => None,
    }
}

/// A [`Reference`] placed on this machine: the same claim, plus where the path
/// actually points once the working directory in effect has been applied.
///
/// A type rather than an optional field on `Reference`, so that a caller cannot
/// hold an unresolved one and silently skip it. `reference.path` stays as
/// written — `npm` and `./npm` resolve alike, and only the written form says
/// whether the shell searches `PATH`.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub reference: Reference,
    pub absolute: String,
}

#[derive(Debug, Default, Clone)]
pub struct Graph {
    pub source: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Which node owns each stretch of source, for emission. Only *leaves* own
    /// segments — a `Command`'s span list is the union of its parts and would
    /// double-cover them.
    segments: Vec<(Span, NodeId)>,
}

impl Graph {
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    /// Every command, **in source order**.
    ///
    /// Node ids alone would not give that: a wrapper's payload is minted while
    /// the maps are applied, so `sudo rm x | grep y` allocates `grep` before
    /// `rm`. Ordering by position keeps `cmd[1]` meaning the second command on
    /// the line, which is what the fingerprint's ordinals and every failure
    /// message assume.
    pub fn commands(&self) -> impl Iterator<Item = (NodeId, &CommandNode)> {
        let mut out: Vec<(NodeId, &CommandNode)> = self
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| match n {
                Node::Command(c) => Some((i, c)),
                _ => None,
            })
            .collect();
        out.sort_by_key(|(id, c)| (c.spans.first().map_or(usize::MAX, |s| s.start), *id));
        out.into_iter()
    }

    pub fn edges_from(&self, id: NodeId) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.from == id)
    }

    /// Reconstruct the source. With no replacements this is the P1 identity;
    /// the gaps between owned segments (whitespace, quotes, keywords, `(`/`)`)
    /// are copied through untouched, which is what makes an edit surgical
    /// instead of the byte-span surgery that ate `grep`'s flag in #7.
    pub fn emit(&self) -> String {
        self.emit_with(&HashMap::new())
    }

    pub fn emit_with(&self, replacements: &HashMap<NodeId, String>) -> String {
        let mut out = String::with_capacity(self.source.len());
        let mut cursor = 0usize;
        for (span, id) in &self.segments {
            // segments are sorted and non-overlapping; a violation would show
            // up as a P1 failure rather than silently corrupting the output
            if span.start < cursor {
                continue;
            }
            out.push_str(&self.source[cursor..span.start]);
            match replacements.get(id) {
                Some(text) => out.push_str(text),
                None => out.push_str(&self.source[span.start..span.end]),
            }
            cursor = span.end;
        }
        out.push_str(&self.source[cursor..]);
        out
    }

    /// Everything the graph claims about the command, with node ids and byte
    /// offsets removed.
    ///
    /// This is the equivalence **P2** needs. An edit moves every span after it,
    /// and a re-parse renumbers every node, so comparing either would make the
    /// property trivially false while saying nothing about whether the edit was
    /// sound. Commands are identified by their ordinal instead, which survives
    /// both.
    ///
    /// Sorted, so it compares as a set: the order edges happen to be inserted in
    /// is an implementation detail, while the ordinals already carry the
    /// ordering that matters.
    pub fn fingerprint(&self) -> Vec<String> {
        let ordinal: HashMap<NodeId, usize> = self
            .commands()
            .enumerate()
            .map(|(i, (id, _))| (id, i))
            .collect();
        let name_of = |id: NodeId| match self.node(id) {
            Node::Flag(f) => f.name.clone(),
            Node::Value(v) => v.text.clone().unwrap_or_else(|| "<dynamic>".into()),
            Node::Command(c) => c.name.clone().unwrap_or_else(|| "<dynamic>".into()),
            Node::Heredoc(h) => format!("<<{}{}", if h.quoted { "'" } else { "" }, h.delimiter),
            Node::Stream(s) => format!("{:?}", s.kind),
            Node::Connector(c) => format!("{:?}", c.kind),
            Node::PathSet(p) => match p.set.recursive {
                true => format!("{}/**", p.set.roots.join(",")),
                false => p.set.roots.join(","),
            },
        };
        let mut out = Vec::new();
        for (i, (id, cmd)) in self.commands().enumerate() {
            out.push(format!(
                "cmd[{i}] name={} priv={:?} at={}",
                cmd.name.as_deref().unwrap_or("<dynamic>"),
                cmd.privilege,
                match (&cmd.locality, &cmd.host) {
                    (Locality::Local, _) => "local".to_string(),
                    (Locality::Remote, Some(host)) => format!("remote:{host}"),
                    (Locality::Remote, None) => "remote".to_string(),
                }
            ));
            for edge in self.edges_from(id) {
                match edge.kind {
                    EdgeKind::Has => {
                        out.push(format!("cmd[{i}] flag={}", name_of(edge.to)));
                        // a flag's bound argument belongs with the flag
                        for bound in self
                            .edges_from(edge.to)
                            .filter(|e| e.kind == EdgeKind::Takes)
                        {
                            out.push(format!(
                                "cmd[{i}] flag={} takes={}",
                                name_of(edge.to),
                                name_of(bound.to)
                            ));
                        }
                    }
                    EdgeKind::Arg(n) => {
                        let slot = if n == usize::MAX {
                            "env".to_string()
                        } else {
                            n.to_string()
                        };
                        out.push(format!("cmd[{i}] arg[{slot}]={}", name_of(edge.to)));
                    }
                    EdgeKind::Flow(kind) => out.push(format!(
                        "cmd[{i}] --{kind:?}--> cmd[{}]",
                        ordinal.get(&edge.to).map_or("?".into(), |o| o.to_string())
                    )),
                    EdgeKind::Spawns => out.push(format!(
                        "cmd[{i}] spawns cmd[{}]",
                        ordinal.get(&edge.to).map_or("?".into(), |o| o.to_string())
                    )),
                    _ => {}
                }
            }
        }
        // Reference edges, with the locality that decides whether they are about
        // this machine. Included because P2 is the gate on EDITS, and an edit
        // that quietly moved a delete from one path to another — or from the
        // local side of a transfer to the remote one — would otherwise round-
        // trip clean.
        for reference in self.references() {
            let Some(i) = ordinal.get(&reference.command) else {
                continue;
            };
            out.push(format!(
                "cmd[{i}] {:?}={} {}",
                reference.effect,
                match self.node(reference.target) {
                    // a set is not the word it was built from
                    Node::PathSet(_) => name_of(reference.target),
                    _ => reference.path.clone(),
                },
                match reference.locality {
                    Locality::Local => "local",
                    Locality::Remote => "remote",
                }
            ));
        }
        // streams and heredocs point AT their command, so they are walked from
        // the other end
        for edge in self.edges.iter().filter(|e| e.kind == EdgeKind::On) {
            out.push(format!(
                "cmd[{}] on={}",
                ordinal.get(&edge.to).map_or("?".into(), |o| o.to_string()),
                name_of(edge.from)
            ));
        }
        // a value spawning a command (`echo "$(id)"`) is not reachable from a
        // command's own edges
        for edge in self.edges.iter().filter(|e| e.kind == EdgeKind::Spawns) {
            if !matches!(self.node(edge.from), Node::Command(_)) {
                out.push(format!(
                    "value spawns cmd[{}]",
                    ordinal.get(&edge.to).map_or("?".into(), |o| o.to_string())
                ));
            }
        }
        out.sort();
        out
    }

    /// The segments this node owns — the bytes an edit to it would replace.
    ///
    /// Distinct from [`Node::spans`], which for a `Command` is the union of its
    /// name *and* its arguments (a summary for reporting). Only the name is
    /// owned, so an editor asking "can I replace this node with one token?"
    /// must ask here.
    pub fn owned_spans(&self, id: NodeId) -> Vec<Span> {
        self.segments
            .iter()
            .filter(|(_, owner)| *owner == id)
            .map(|(span, _)| *span)
            .collect()
    }

    /// Which node owns the segment at `span`, if any. The addressing step an
    /// edit needs: locate the node, then hand its id to [`Graph::emit_with`].
    pub fn segment_owner(&self, span: Span) -> Option<NodeId> {
        self.segments
            .iter()
            .find(|(s, _)| *s == span)
            .map(|(_, id)| *id)
    }

    /// Which chain each command belongs to, and where in it — the structure
    /// `piped_into`, `with` and `position` are asking about.
    ///
    /// A chain is a run of commands joined by written connectors. Two things
    /// follow from taking that from the graph rather than from the CST, and both
    /// are fixes:
    ///
    /// - **`ls; git stash` is a chain.** The CST puts a top-level `;` straight
    ///   under `program` rather than in a `list`, so a walk looking for the
    ///   nearest `pipeline`/`list` ancestor found none and called both commands
    ///   standalone — a `with` rule that fires on `ls && git stash` and
    ///   `ls | git stash` was evadable by writing `;`. The #12 shape, one
    ///   separator over.
    /// - **`a && b || c` is one chain of three.** The grammar nests binary
    ///   lists, so the nearest-ancestor walk saw `[list(a && b), c]` — two
    ///   members, with `a` and `c` in different groups.
    ///
    /// A payload command (`rm` in `sudo rm x`) joins the chain of the command
    /// that spawned it: it is a view of the same stage, not another one.
    pub fn groups(&self) -> HashMap<NodeId, Group> {
        let commands: Vec<NodeId> = self.commands().map(|(id, _)| id).collect();
        let mut root: HashMap<NodeId, NodeId> = commands.iter().map(|id| (*id, *id)).collect();
        let find = |root: &mut HashMap<NodeId, NodeId>, id: NodeId| {
            let mut at = id;
            while root.get(&at).copied().unwrap_or(at) != at {
                at = root[&at];
            }
            at
        };
        let union = |root: &mut HashMap<NodeId, NodeId>, a: NodeId, b: NodeId| {
            let (a, b) = (find(root, a), find(root, b));
            if a != b {
                root.insert(a, b);
            }
        };
        for edge in &self.edges {
            if let EdgeKind::Flow(_) = edge.kind {
                union(&mut root, edge.from, edge.to);
            }
        }

        // A payload command is a VIEW of the stage that spawned it, not another
        // stage. It shares that stage's group entry outright rather than joining
        // the chain as a member: appending it would push `head` from position 1
        // to position 2 in `sudo pnpm build | head`, and `piped_into` reads the
        // next position.
        let payloads: Vec<(NodeId, NodeId)> = self
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Spawns && self.owned_spans(e.to).is_empty())
            .map(|e| (e.to, e.from))
            .collect();

        let mut chains: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for id in &commands {
            if payloads.iter().any(|(payload, _)| payload == id) {
                continue;
            }
            chains.entry(find(&mut root, *id)).or_default().push(*id);
        }
        let mut out: HashMap<NodeId, Group> = HashMap::new();
        for members in chains.values_mut() {
            members.sort_by_key(|id| {
                self.nodes[*id]
                    .spans()
                    .first()
                    .map_or(usize::MAX, |s| s.start)
            });
            for (position, id) in members.iter().enumerate() {
                out.insert(
                    *id,
                    Group {
                        members: members.clone(),
                        position,
                        // the connector that joined this command to the one
                        // before it; for the first, the one joining it to the
                        // next. Uniform chains answer the same either way, and a
                        // mixed one says how THIS stage is attached.
                        connector: self
                            .connector_into(*id)
                            .or_else(|| self.connector_out_of(*id)),
                    },
                );
            }
        }
        // resolved after the chains exist, and repeatedly: `ssh host sudo rm x`
        // is a payload of a payload
        for _ in 0..payloads.len() {
            for (payload, spawner) in &payloads {
                if let Some(group) = out.get(spawner).cloned() {
                    out.insert(*payload, group);
                }
            }
        }
        out
    }

    fn connector_into(&self, id: NodeId) -> Option<Connector> {
        self.edges.iter().find_map(|e| match e.kind {
            EdgeKind::Flow(kind) if e.to == id => Some(kind),
            _ => None,
        })
    }

    fn connector_out_of(&self, id: NodeId) -> Option<Connector> {
        self.edges.iter().find_map(|e| match e.kind {
            EdgeKind::Flow(kind) if e.from == id => Some(kind),
            _ => None,
        })
    }

    /// Every reference this command line makes, according to the recipes.
    ///
    /// The inverted default made concrete: a word is a path because a reviewed
    /// recipe said so, not because it starts with `/`. A program with no recipe
    /// contributes nothing, which is why an unmapped command cannot produce a
    /// false positive here.
    ///
    /// **Remote references are included.** A reference edge says what the
    /// command does to what it names; [`Reference::locality`] says where that
    /// thing is. Dropping the edge instead would conflate "elsewhere" with
    /// "does not happen", and only the first is true — `aws s3 rm s3://b/key`
    /// really does delete a key. Callers that mean *this* filesystem ask
    /// [`Graph::referenced_paths`].
    ///
    /// Paths come back as written. Resolution — `~`, `..`, the cd-tracked base
    /// — stays with the caller, which already does it.
    pub fn references(&self) -> Vec<Reference> {
        let mut out: Vec<Reference> = Vec::new();
        for edge in &self.edges {
            let Some(effect) = effect_of(edge.kind) else {
                continue;
            };
            let here = match self.node(edge.from) {
                Node::Command(cmd) => cmd.locality,
                _ => Locality::Local,
            };
            let (path, locality, remote) = match self.node(edge.to) {
                Node::Value(value) => (
                    value.text.clone(),
                    value.facts.locality,
                    value.remote.clone(),
                ),
                Node::PathSet(set) => (
                    set.set.roots.first().cloned(),
                    set.locality,
                    set.remote.clone(),
                ),
                // an `Execs` edge points at a command, which is a reference to a
                // program rather than to a path
                Node::Command(cmd) => (cmd.name.clone(), cmd.locality, None),
                _ => (None, Locality::Local, None),
            };
            let Some(path) = path else { continue };
            out.push(Reference {
                command: edge.from,
                target: edge.to,
                effect,
                locality: here.or(locality),
                path,
                remote,
            });
        }
        out
    }

    /// Every reference, with each path resolved against the working directory in
    /// effect **where that reference appears**.
    ///
    /// The whole query: callers ask once and filter [`Reference`] by their own
    /// policy, rather than the graph growing an accessor per caller.
    ///
    /// `cd` needs no special machinery — it is a command like any other, its
    /// recipe says slot 0 is a path, and [`Graph::commands`] is already in source
    /// order.
    ///
    /// `resolve` maps `(path, base)` to an absolute path. A parameter because
    /// expanding `~` needs the environment: the graph says what is referenced
    /// from where, the caller says what that means on this machine.
    pub fn resolved_references(
        &self,
        base: &str,
        resolve: &dyn Fn(&str, &str) -> String,
    ) -> Vec<Resolved> {
        let references = self.references();
        let mut cwd_at: HashMap<NodeId, String> = HashMap::new();
        let mut cwd = base.to_string();
        for (id, command) in self.commands() {
            cwd_at.insert(id, cwd.clone());
            if command.name.as_deref().map(basename) != Some("cd") {
                continue;
            }
            // `cd`'s own argument resolves against the base BEFORE it runs,
            // which is why that is recorded above first. A dynamic target or
            // `cd -` yields no reference here, so the base simply freezes.
            if let Some(target) = references
                .iter()
                .find(|r| r.command == id && r.locality == Locality::Local)
            {
                cwd = resolve(&target.path, &cwd);
            }
        }
        references
            .into_iter()
            .map(|reference| {
                let at = cwd_at.get(&reference.command).map_or(base, |s| s.as_str());
                let absolute = resolve(&reference.path, at);
                Resolved {
                    reference,
                    absolute,
                }
            })
            .collect()
    }

    /// Byte count covered by owned segments — the completeness half of P1.
    /// `emit` alone only proves the segments are ordered and non-overlapping;
    /// a lowering that dropped every word would still round-trip.
    pub fn covered_bytes(&self) -> usize {
        self.segments.iter().map(|(s, _)| s.end - s.start).sum()
    }

    /// First pair of segments that claim the same bytes, if any.
    ///
    /// This is the failure `emit` cannot surface on its own: it skips a segment
    /// that starts before the cursor, so an overlap still round-trips while
    /// leaving two nodes believing they own the same text — and an edit to
    /// either would corrupt the other. The P1 gate asserts this is `None`.
    pub fn overlapping_segments(&self) -> Option<(Span, Span)> {
        self.segments
            .windows(2)
            .find(|p| p[1].0.start < p[0].0.end)
            .map(|p| (p[0].0, p[1].0))
    }

    fn push(&mut self, node: Node) -> NodeId {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn own(&mut self, span: Span, id: NodeId) {
        if span.end > span.start {
            self.segments.push((span, id));
        }
    }

    // `self` counts toward the total, so this three-argument method trips a
    // threshold of 3.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn link(&mut self, from: NodeId, to: NodeId, kind: EdgeKind) {
        self.edges.push(Edge { from, to, kind });
    }
}

/// Lower a bash source string into the graph.
///
/// Constructs this stage does not model semantically (`if`, `for`, `case`,
/// function bodies) still parse: their commands are lowered, and the keywords
/// around them fall through as unowned gaps. P1 holds regardless, which is what
/// keeps the stage tractable without pretending to more coverage than it has.
pub fn lower(source: &str) -> Graph {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return Graph {
            source: source.to_string(),
            ..Default::default()
        };
    }
    match parser.parse(source, None) {
        Some(tree) => lower_from(&tree, source),
        None => Graph {
            source: source.to_string(),
            ..Default::default()
        },
    }
}

/// Lower a tree somebody else already parsed.
///
/// `bash::extract` parses the source for its own walk; without this it would
/// parse a second time to get a graph, and the two views of one command would
/// be two views of two parses. Sub-task 4 is about removing that gap, and this
/// is where it starts: **one parse, one tree**.
pub fn lower_from(tree: &tree_sitter::Tree, source: &str) -> Graph {
    let mut graph = Graph {
        source: source.to_string(),
        ..Default::default()
    };
    let mut ctx = Lowering {
        graph: &mut graph,
        source,
    };
    ctx.walk(tree.root_node(), None);
    graph.segments.sort_by_key(|(s, _)| (s.start, s.end));
    graph
}

struct Lowering<'a> {
    graph: &'a mut Graph,
    source: &'a str,
}

impl Lowering<'_> {
    fn walk(&mut self, node: TsNode, enclosing: Option<NodeId>) {
        match node.kind() {
            "command" => {
                let id = self.lower_command(node);
                if let Some(prev) = enclosing {
                    // a command nested inside another's argument list (`find
                    // -exec`) is spawned by it, not sequenced with it
                    self.graph.link(prev, id, EdgeKind::Spawns);
                }
                return;
            }
            // `program` is a group too: tree-sitter puts a top-level `a ; c`
            // straight under it rather than in a `list`, so without this the
            // `;` is not a node and the two commands are unrelated — the same
            // blindness #12 was about, one level up.
            "program" | "pipeline" | "list" => {
                let children: Vec<_> = (0..node.child_count())
                    .filter_map(|i| node.child(i))
                    .collect();
                self.lower_group(&children);
                return;
            }
            // `cmd > file` / `cmd <<EOF`: the redirect is a SIBLING of the
            // command, not one of its children
            "redirected_statement" => {
                self.lower_redirected(node);
                return;
            }
            // `[ -f x ] && cat y` — the grammar calls this a `test_command`, not
            // a `command`, but it IS one (`/usr/bin/[`) and it is a stage of the
            // chain. Without a node for it the chain looks one member short, and
            // `cat` reads as standalone.
            "test_command" => {
                self.lower_test(node);
                return;
            }
            _ => {}
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.walk(child, enclosing);
            }
        }
    }

    /// Lower a run of siblings joined by connector tokens: mint a `Connector`
    /// node per operator and join adjacent members with a `Flow` edge.
    ///
    /// Takes a child slice rather than a node because the members of a group are
    /// not always the children of one `pipeline`/`list`: in `cat <<EOF && rm x`
    /// the `&&` and `rm x` are direct children of the *heredoc redirect*.
    fn lower_group(&mut self, children: &[TsNode]) -> Vec<NodeId> {
        // Each member is (head, tail): a connector joins the END of the group on
        // its left to the START of the group on its right. Linking heads alone
        // gets `a || b ; c` wrong — the command before the `;` is `b`, while the
        // member's head is `a`.
        //
        // A connector must have been WRITTEN to join two members. `program` is
        // lowered as a group so a top-level `a ; c` gets its `;`, but two
        // statements on separate lines have no operator between them and are not
        // one chain — inventing a `Seq` edge there would put every command in a
        // multi-line script into one group, and `position = "only"` would stop
        // matching anything.
        let mut members: Vec<(NodeId, NodeId)> = Vec::new();
        let mut pending: Option<Connector> = None;
        for child in children {
            if child.is_named() {
                let Some(ends) = self.walk_capturing_ends(*child) else {
                    continue;
                };
                if let (Some(kind), Some(previous)) = (pending.take(), members.last()) {
                    self.graph.link(previous.1, ends.0, EdgeKind::Flow(kind));
                }
                members.push(ends);
                continue;
            }
            let kind = match child.utf8_text(self.source.as_bytes()).unwrap_or("") {
                "|" | "|&" => Connector::Pipe,
                "&&" => Connector::And,
                "||" => Connector::Or,
                ";" | ";;" | "&" => Connector::Seq,
                _ => continue,
            };
            let span = Span::of(*child);
            let id = self.graph.push(Node::Connector(ConnectorNode {
                spans: vec![span],
                kind,
            }));
            self.graph.own(span, id);
            pending = Some(kind);
        }
        members.into_iter().map(|(head, _)| head).collect()
    }

    /// Walk a subtree and report the first and last `Command` it minted.
    ///
    /// A member of a group is not always one command: in `a || b ; c` the first
    /// member is a whole `list`. Its *head* is what a connector on its left
    /// points at, and its *tail* is what a connector on its right comes from.
    fn walk_capturing_ends(&mut self, node: TsNode) -> Option<(NodeId, NodeId)> {
        let before = self.graph.nodes.len();
        self.walk(node, None);
        let mut commands = (before..self.graph.nodes.len())
            .filter(|&i| matches!(self.graph.nodes[i], Node::Command(_)));
        let head = commands.next()?;
        Some((head, commands.next_back().unwrap_or(head)))
    }

    fn lower_redirected(&mut self, node: TsNode) {
        let children: Vec<TsNode> = (0..node.child_count())
            .filter_map(|i| node.child(i))
            .collect();
        let body: Vec<TsNode> = children
            .iter()
            .copied()
            .filter(|c| !is_redirect(*c))
            .collect();
        // the body may be a single command or a whole pipeline
        let before = self.graph.nodes.len();
        let mut members = self.lower_group(&body);
        let head = members.first().copied();
        // The command a nested pipeline flows OUT of is the last one the body
        // lowered, not the head of its last member: in
        // `echo a | cat <<EOF | grep x` the body is one `pipeline` member whose
        // head is `echo`, while the stage feeding `grep` is `cat`.
        let tail = (before..self.graph.nodes.len())
            .rfind(|i| matches!(self.graph.nodes[*i], Node::Command(_)));

        for redirect in children.iter().copied().filter(|c| is_redirect(*c)) {
            if redirect.kind() != "heredoc_redirect" {
                let id = self.lower_stream(redirect);
                if let Some(head) = head {
                    self.graph.link(id, head, EdgeKind::On);
                }
                continue;
            }
            let (id, nested, connector) = self.lower_heredoc(redirect);
            if let Some(head) = head {
                self.graph.link(id, head, EdgeKind::On);
            }
            // Re-parenting (#12): the commands the grammar buried inside the
            // redirect are logically siblings of the command that owns it, so
            // the last body member flows into the first of them. Without this
            // edge the two ends of `cat <<EOF | grep x` are unrelated in the
            // graph, exactly as they were unrelated in the CST.
            if let (Some(previous), Some(first)) = (tail.or(head), nested.first().copied()) {
                self.graph.link(previous, first, EdgeKind::Flow(connector));
            }
            members.extend(nested);
        }
    }

    /// `<<EOF` / `<<-EOF` / `<<'EOF'`, body and terminator.
    ///
    /// tree-sitter nests **the rest of the pipeline inside this node**: in
    /// `cat <<EOF | grep x` the `| grep x` is a child here, not a sibling of
    /// `cat`. Stage 1 lowers those commands so they exist in the graph, but
    /// does not yet re-parent them to their logical position — that is
    /// sub-task 2, and it is what closes #12 for every consumer at once.
    fn lower_heredoc(&mut self, node: TsNode) -> (NodeId, Vec<NodeId>, Connector) {
        let mut spans = Vec::new();
        let mut delimiter = String::new();
        let mut quoted = false;
        let mut strip_tabs = false;
        let mut body = None;
        let mut body_node = None;
        let mut interior = Vec::new();

        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else { continue };
            let span = Span::of(child);
            match child.kind() {
                "<<" | "<<-" => {
                    strip_tabs = child.kind() == "<<-";
                    spans.push(span);
                }
                "heredoc_start" => {
                    let raw = span.text(self.source);
                    quoted = raw.starts_with('\'') || raw.starts_with('"');
                    delimiter = raw.trim_matches(['\'', '"']).to_string();
                    spans.push(span);
                }
                "heredoc_body" => {
                    body = Some(span);
                    body_node = Some(child);
                }
                "heredoc_end" => spans.push(span),
                _ => interior.push(child),
            }
        }

        let id = self.graph.push(Node::Heredoc(HeredocNode {
            spans: Vec::new(),
            delimiter,
            quoted,
            strip_tabs,
            body,
        }));
        for span in &spans {
            self.graph.own(*span, id);
        }
        // An *unquoted* delimiter leaves the body subject to expansion, and the
        // grammar reflects it: `<<EOF` gives the body a `command_substitution`
        // child, `<<'EOF'` gives it none. So a heredoc body can contain live
        // commands, and dropping them would leave a rule blind to
        // `cat <<EOF … $(rm -rf /) … EOF`.
        if let (Some(node), Some(span)) = (body_node, body) {
            spans.extend(self.own_around_substitutions(node, span, id));
        }
        if let Node::Heredoc(h) = &mut self.graph.nodes[id] {
            spans.sort();
            h.spans = spans;
        }
        let connector = interior_connector(&interior, self.source);
        let nested = self.lower_group(&interior);
        (id, nested, connector)
    }

    /// `[ -f x ]` / `[[ -z $a ]]`.
    ///
    /// The opening bracket is the program name — that is literally what it is —
    /// and each operand of the expression becomes one argument. Not word for
    /// word: a test expression is an expression, not a word list, so
    /// `unary_expression` lowers as one operand rather than as `-f` plus `x`.
    /// Nothing reads the operands; what this node exists for is to be a *member
    /// of its chain*.
    fn lower_test(&mut self, node: TsNode) -> NodeId {
        let id = self.graph.push(Node::Command(CommandNode {
            spans: Vec::new(),
            name: None,
            locality: Locality::Local,
            host: None,
            privilege: Privilege::Normal,
        }));
        let mut spans = Vec::new();
        let mut name = None;
        let mut positional = 0usize;
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else { continue };
            let span = Span::of(child);
            if !child.is_named() {
                // `[` opens it, `]` closes it; only the opener is the name
                if name.is_none() {
                    name = Some(span.text(self.source).to_string());
                    self.graph.own(span, id);
                    spans.push(span);
                }
                continue;
            }
            let value = self.lower_value(child);
            spans.extend(self.graph.nodes[value].spans().iter().copied());
            self.graph.link(id, value, EdgeKind::Arg(positional));
            positional += 1;
        }
        if let Node::Command(cmd) = &mut self.graph.nodes[id] {
            cmd.name = name;
            cmd.spans = spans;
        }
        id
    }

    fn lower_command(&mut self, node: TsNode) -> NodeId {
        let id = self.graph.push(Node::Command(CommandNode {
            spans: Vec::new(),
            name: None,
            locality: Locality::Local,
            host: None,
            privilege: Privilege::Normal,
        }));
        let mut spans = Vec::new();
        let mut name = None;
        let mut positional = 0usize;

        for i in 0..node.named_child_count() {
            let Some(child) = node.named_child(i) else {
                continue;
            };
            match child.kind() {
                "command_name" => {
                    let inner = child.named_child(0).unwrap_or(child);
                    let span = Span::of(inner);
                    name = resolve_text(inner, self.source);
                    // `$(which git) --version` — even the program name can be
                    // a substitution, and its payload is a command of its own
                    spans.extend(self.own_around_substitutions(inner, span, id));
                }
                // `LD_PRELOAD=x cmd` — a prefix assignment, not an argument
                "variable_assignment" => {
                    let value = self.lower_value(child);
                    spans.extend(self.graph.nodes[value].spans().iter().copied());
                    self.graph.link(id, value, EdgeKind::Arg(usize::MAX));
                }
                "file_redirect" | "herestring_redirect" => {
                    let stream = self.lower_stream(child);
                    spans.extend(self.graph.nodes[stream].spans().iter().copied());
                    self.graph.link(stream, id, EdgeKind::On);
                }
                // `diff <(a) <(b)` and the `(1)` in `print(1)`: the payload is
                // a command, not an argument's text
                _ if is_nested_command_region(child) => {
                    spans.extend(self.own_around_substitutions(child, Span::of(child), id));
                }
                _ => {
                    let (kind, node_id) = self.lower_word(child, id);
                    spans.extend(self.graph.nodes[node_id].spans().iter().copied());
                    match kind {
                        WordKind::Flag => self.graph.link(id, node_id, EdgeKind::Has),
                        WordKind::Value => {
                            self.graph.link(id, node_id, EdgeKind::Arg(positional));
                            positional += 1;
                        }
                    }
                }
            }
        }

        if let Node::Command(cmd) = &mut self.graph.nodes[id] {
            cmd.privilege = match name.as_deref().is_some_and(elevates) {
                true => Privilege::Elevated,
                false => Privilege::Normal,
            };
            cmd.name = name;
            cmd.spans = spans;
        }
        id
    }

    /// A word is a flag when it is written like one. `-` alone is a stdin
    /// placeholder and `--` is a separator, so both stay values.
    fn lower_word(&mut self, node: TsNode, _owner: NodeId) -> (WordKind, NodeId) {
        let span = Span::of(node);
        let text = resolve_text(node, self.source);
        let looks_like_flag = text
            .as_deref()
            .is_some_and(|t| t.starts_with('-') && t.len() > 1 && t != "--");
        if !looks_like_flag {
            return (WordKind::Value, self.lower_value(node));
        }
        let raw = span.text(self.source);
        // `--color=auto` binds its argument syntactically, so it is the one
        // case stage 1 can emit a `Takes` edge for without an argument map
        let Some(eq) = raw.find('=').filter(|_| raw.starts_with('-')) else {
            let id = self.graph.push(Node::Flag(FlagNode {
                spans: vec![span],
                name: text.unwrap_or_else(|| raw.to_string()),
            }));
            self.graph.own(span, id);
            return (WordKind::Flag, id);
        };
        let flag_span = Span {
            start: span.start,
            end: span.start + eq,
        };
        let value_span = Span {
            start: span.start + eq + 1,
            end: span.end,
        };
        let flag = self.graph.push(Node::Flag(FlagNode {
            spans: vec![flag_span],
            name: flag_span.text(self.source).to_string(),
        }));
        self.graph.own(flag_span, flag);
        let value_text = value_span.text(self.source);
        let value = self.graph.push(Node::Value(ValueNode {
            spans: vec![value_span],
            text: Some(value_text.to_string()),
            raw: value_text.to_string(),
            facts: facts_for(value_text, Some(value_text)),
            remote: RemoteRef::parse(value_text),
        }));
        self.graph.own(value_span, value);
        self.graph.link(flag, value, EdgeKind::Takes);
        (WordKind::Flag, flag)
    }

    fn lower_value(&mut self, node: TsNode) -> NodeId {
        let span = Span::of(node);
        let raw = span.text(self.source).to_string();
        let text = resolve_text(node, self.source);
        let id = self.graph.push(Node::Value(ValueNode {
            spans: Vec::new(),
            facts: facts_for(&raw, text.as_deref()),
            remote: RemoteRef::parse(text.as_deref().unwrap_or(&raw)),
            text,
            raw,
        }));
        let spans = self.own_around_substitutions(node, span, id);
        if let Node::Value(v) = &mut self.graph.nodes[id] {
            v.spans = spans;
        }
        id
    }

    /// Own `span` for `owner`, minus any `$(…)` it encloses, and lower those
    /// substitutions as spawned commands.
    ///
    /// `echo "pre $(id) post"` is one string word whose text is *not*
    /// contiguous: the middle belongs to another command entirely. Without
    /// carving it out, the string and the inner `id` both claim those bytes,
    /// and rewriting either corrupts the other — a span-surgery bug of exactly
    /// the shape that ate `grep`'s flag in #7. This is the concrete reason
    /// nodes own a span *list*.
    // `self` counts toward the total, so this three-argument method trips a
    // threshold of 3.
    #[allow(clippy::too_many_arguments)]
    fn own_around_substitutions(&mut self, node: TsNode, span: Span, owner: NodeId) -> Vec<Span> {
        let holes = substitution_spans(node);
        let mut kept = Vec::new();
        let mut cursor = span.start;
        for hole in &holes {
            if hole.start > cursor {
                let piece = Span {
                    start: cursor,
                    end: hole.start,
                };
                self.graph.own(piece, owner);
                kept.push(piece);
            }
            cursor = cursor.max(hole.end);
        }
        if cursor < span.end {
            let piece = Span {
                start: cursor,
                end: span.end,
            };
            self.graph.own(piece, owner);
            kept.push(piece);
        }
        for hole in holes {
            if let Some(sub) = node_at(node, hole) {
                self.walk_substitution(sub, owner);
            }
        }
        kept
    }

    fn walk_substitution(&mut self, node: TsNode, owner: NodeId) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.walk(child, Some(owner));
            }
        }
    }

    /// `> file`, `>> file`, `< file`, `2>&1`, `<<< word`.
    ///
    /// The **destination is lowered as its own `Value`**, and the stream owns
    /// only the operator. `echo hi > /etc/passwd` used to be one opaque node
    /// covering `> /etc/passwd`, so the file the shell truncates was not a node
    /// at all and no rule could see it (#29). Splitting it also keeps an edit
    /// surgical: rewriting the destination must not touch the `>`.
    ///
    /// A descriptor dup (`2>&1`, `>&2`) names no file — the grammar says so by
    /// giving it a `number` destination rather than a word, which is a better
    /// oracle than reading the operator, since `2>&1`'s operator is `>&` and
    /// `&>file`'s is too.
    fn lower_stream(&mut self, node: TsNode) -> NodeId {
        let span = Span::of(node);
        let raw = span.text(self.source);
        let operator = raw.trim_start_matches(|c: char| c.is_ascii_digit());
        let target = redirect_target(node);
        let dup = target.is_some_and(|t| t.kind() == "number");
        let kind = if node.kind() == "herestring_redirect" || operator.starts_with("<<<") {
            StreamKind::HereString
        } else if dup {
            StreamKind::Dup
        } else if operator.starts_with(">>") {
            StreamKind::Append
        } else if operator.starts_with("&>") || operator.starts_with(">&") {
            StreamKind::Both
        } else if operator.starts_with('>') {
            StreamKind::Out
        } else {
            StreamKind::In
        };
        // the operator, and any leading descriptor: everything up to the
        // destination word
        let operator_span = Span {
            start: span.start,
            end: target.map_or(span.end, |t| Span::of(t).start),
        };
        let id = self.graph.push(Node::Stream(StreamNode {
            spans: vec![operator_span],
            kind,
        }));
        self.graph.own(operator_span, id);
        if let Some(target) = target {
            let value = self.lower_value(target);
            let spans = self.graph.nodes[value].spans().to_vec();
            if let Node::Stream(stream) = &mut self.graph.nodes[id] {
                stream.spans.extend(spans);
            }
            // `Takes` means "this is the file the stream is bound to". A
            // here-string's word is DATA and a dup's operand is a descriptor, so
            // neither gets one — `cmd <<< /etc/passwd` must not look like a read
            // of that file. The value node still exists and still owns its
            // bytes, so P1 holds either way.
            if kind != StreamKind::HereString && !dup {
                self.graph.link(id, value, EdgeKind::Takes);
            }
        }
        id
    }
}

enum WordKind {
    Flag,
    Value,
}

/// A region whose bytes are another command rather than text.
///
/// `subshell` is here because tree-sitter can put one directly in a command's
/// argument list — `print(1)` lowers to `command_name print` plus a `subshell`
/// holding the command `1`. Treating that as a word would make the inner
/// command invisible to every rule, which is precisely the class of blindness
/// the graph exists to remove.
fn is_redirect(node: TsNode) -> bool {
    matches!(
        node.kind(),
        "file_redirect" | "herestring_redirect" | "heredoc_redirect"
    )
}

/// The connector joining a heredoc's owner to the commands nested inside it.
///
/// A nested `pipeline`/`list` carries it (`<<EOF | grep x`); otherwise the
/// operator sits as a bare token among the redirect's children, because
/// `<<EOF && rm x` gets no `list` wrapper at all.
fn interior_connector(interior: &[TsNode], source: &str) -> Connector {
    for node in interior {
        match node.kind() {
            "pipeline" => return Connector::Pipe,
            "list" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(c) = connector_token(child, source) {
                        return c;
                    }
                }
            }
            _ => {
                if let Some(c) = connector_token(*node, source) {
                    return c;
                }
            }
        }
    }
    Connector::Seq
}

fn connector_token(node: TsNode, source: &str) -> Option<Connector> {
    match node.utf8_text(source.as_bytes()).unwrap_or("") {
        "|" | "|&" => Some(Connector::Pipe),
        "&&" => Some(Connector::And),
        "||" => Some(Connector::Or),
        ";" => Some(Connector::Seq),
        _ => None,
    }
}

/// The destination of a redirect: its last named child.
///
/// `2>&1` names `file_descriptor 2` first and `number 1` last; `> out.txt` names
/// only the word. Reading the grammar beats reading the operator text, which
/// cannot tell `2>&1` from `&>file` — both spell `>&`.
fn redirect_target(node: TsNode) -> Option<TsNode> {
    let last = node.named_child(node.named_child_count().checked_sub(1)?)?;
    (last.kind() != "file_descriptor").then_some(last)
}

fn is_nested_command_region(node: TsNode) -> bool {
    matches!(
        node.kind(),
        "command_substitution" | "process_substitution" | "subshell"
    )
}

/// Spans of the outermost nested-command regions inside `node`, in source
/// order. Their payloads run as their own commands, so the enclosing word must
/// not claim those bytes as its own text.
fn substitution_spans(node: TsNode) -> Vec<Span> {
    if is_nested_command_region(node) {
        return vec![Span::of(node)];
    }
    let mut out = Vec::new();
    collect_substitutions(node, &mut out);
    out.sort();
    out
}

fn collect_substitutions(node: TsNode, out: &mut Vec<Span>) {
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        if is_nested_command_region(child) {
            // outermost only — a nested `$(a $(b))` is lowered when the outer
            // payload is walked, not carved out twice here
            out.push(Span::of(child));
        } else {
            collect_substitutions(child, out);
        }
    }
}

/// The descendant of `node` occupying exactly `span`.
fn node_at(node: TsNode, span: Span) -> Option<TsNode> {
    if Span::of(node) == span && is_nested_command_region(node) {
        return Some(node);
    }
    (0..node.named_child_count())
        .filter_map(|i| node.named_child(i))
        .find_map(|c| node_at(c, span))
}

fn facts_for(raw: &str, text: Option<&str>) -> ValueFacts {
    let dynamic = text.is_none();
    let value = text.unwrap_or(raw);
    let locality = locality_of(value);
    ValueFacts {
        // `absolute` and `relative` describe a path on THIS machine, so a word
        // naming another one is neither. Without that, `s3://bucket/path` reads
        // as a relative path — it contains a `/` and does not start with one —
        // and any consumer resolving relative words against the cwd would
        // happily turn a bucket key into `$PWD/s3:/bucket/path`.
        absolute: !locality.is_remote() && value.starts_with('/'),
        relative: !locality.is_remote()
            && !value.starts_with('/')
            && (value.contains('/') || value == "." || value == ".."),
        // metacharacters in the *resolved* text: `'*'` is a literal asterisk
        glob: text.is_some_and(|t| t.contains(['*', '?'])) || raw.contains('['),
        literal: !dynamic,
        dynamic,
        locality,
    }
}

/// Which machine a word names a path on, from its prefix alone.
///
/// `aws s3 cp`, `kubectl cp` and `scp` all mix local and remote references in
/// **one positional list**, distinguished only by a prefix:
///
/// ```text
/// aws s3 cp ./build s3://bucket/path   slot 0 here, slot 1 elsewhere
/// aws s3 cp s3://bucket/path ./build   the reverse
/// scp host:/etc/hosts .                the same shape, no scheme
/// ```
///
/// So the discriminator is syntactic and shared: a location prefix is a `:` in a
/// word that does not begin at a filesystem root. `s3://bucket/key`,
/// `user@host:/tmp`, `pod:/etc` and kubectl's `ns/pod:/etc` all have one.
///
/// The `/`, `~` and `.` exemption is what keeps this from eating real paths: a
/// colon is legal in a filename, and `/var/log/build:2024.log` must stay local —
/// losing it would be a jail escape, the one direction this codebase treats as
/// dangerous. Every word that can name something *outside* the current directory
/// starts with one of those three characters, so the exemption costs nothing
/// that matters.
///
/// The residue is a relative name below the cwd carrying a colon and no leading
/// `./` (`notes:2024.txt`, `logs/build:1`), read here as remote. That direction
/// costs **silence** on a file inside the working directory. The loud direction
/// would be claiming `s3://bucket/key` is a path on this disk — the #4 shape
/// this design exists to remove.
pub fn locality_of(word: &str) -> Locality {
    match RemoteRef::parse(word) {
        Some(_) => Locality::Remote,
        None => Locality::Local,
    }
}

fn basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Whether running this program raises privilege.
fn elevates(program: &str) -> bool {
    matches!(basename(program), "sudo" | "doas" | "pkexec")
}

/// Quoting removed, `None` when any part of the word is an expansion whose
/// value is not knowable at parse time. Deliberately diverges from
/// `bash::resolve_text`: `$HOME` maps to `~` here so the graph can emit path
/// references for `$HOME/…` words. `bash::resolve_text` must stay `None` for
/// those words — `resolve_word` uses `text.is_none()` to populate `word.raw`,
/// and `match_contains` relies on `raw` for deny-only glob matching.
fn resolve_text(node: TsNode, source: &str) -> Option<String> {
    let text = node.utf8_text(source.as_bytes()).ok()?;
    match node.kind() {
        "word" | "number" | "string_content" => Some(text.to_string()),
        "raw_string" => Some(text.trim_matches('\'').to_string()),
        "string" | "translated_string" | "concatenation" => {
            let mut parts = Vec::new();
            for i in 0..node.named_child_count() {
                parts.push(resolve_text(node.named_child(i)?, source)?);
            }
            Some(parts.join(""))
        }
        // $HOME and ${HOME} are knowable: map to ~ so the existing normalize
        // path handles expansion. All other variables remain dynamic (None).
        "simple_expansion" => {
            let name = node.named_child(0)?.utf8_text(source.as_bytes()).ok()?;
            (name == "HOME").then_some("~".to_string())
        }
        "expansion" => {
            // ponytail: HOME only; operators (${#HOME}, ${!HOME}, ${HOME:-x})
            // are anonymous in tree-sitter-bash so named_child_count is always
            // 1 — check the operator field instead.
            if node.child_by_field_name("operator").is_some() {
                return None;
            }
            let name = node.named_child(0)?.utf8_text(source.as_bytes()).ok()?;
            (name == "HOME").then_some("~".to_string())
        }
        _ => None,
    }
}

// ── applying argument maps (sub-task 5) ──

/// Lower `source`, then let the maps say what each argument means.
///
/// Kept separate from [`lower`] on purpose: the lowering stays a faithful,
/// opinion-free view of the syntax, and every claim about *meaning* enters here,
/// from a reviewed map. A caller with no maps gets exactly the stage-1 graph.
pub fn lower_with_maps(source: &str, maps: &crate::cmdmap::Maps) -> Graph {
    let mut graph = lower(source);
    apply_maps(&mut graph, maps);
    graph
}

/// Attach reference edges to every command the maps know about.
///
/// Three things happen per command, in order, because each depends on the last:
///
/// 1. **Flag arguments are bound.** A flag the map says consumes the next word
///    gets a `Takes` edge to it, and that word stops being a positional. This
///    has to come first: it changes the slot numbers everything else is keyed
///    to. `grep -e pat file` has *one* positional, not two.
/// 2. **Positionals are matched to slots** and turned into reference edges.
/// 3. **A wrapper's payload is followed.** `sudo grep -e x f` applies grep's map
///    to the words after `sudo`, so the inner program's arguments mean what
///    *it* says they mean.
pub fn apply_maps(graph: &mut Graph, maps: &crate::cmdmap::Maps) {
    apply_maps_at(graph, &Mapping { maps, depth: 0 });
    // after the traversal, so a command grafted in from a `-c` script during it
    // is covered by the same single pass
    apply_programs(graph);
}

/// The recipes plus how deep the re-parse already is — they travel together
/// through the whole traversal, the context-struct convention from #19.
struct Mapping<'a> {
    maps: &'a crate::cmdmap::Maps,
    depth: usize,
}

/// `bash -c 'bash -c "bash -c …"'` terminates on its own — each inner string is
/// strictly shorter — but the cost is exponential in the nesting, so it is
/// capped the way `bash::MAX_DEPTH` caps the word-level re-parse.
const MAX_SCRIPT_DEPTH: usize = 5;

fn apply_maps_at(graph: &mut Graph, ctx: &Mapping) {
    let commands: Vec<NodeId> = graph.commands().map(|(id, _)| id).collect();
    for id in commands {
        let Node::Command(cmd) = &graph.nodes[id] else {
            continue;
        };
        let Some(name) = cmd.name.clone() else {
            continue;
        };
        promote_plus_flags(graph, id, &name, ctx.maps);
        let words = ordered_words(graph, id);
        apply_program(graph, id, &name, &words, ctx);
    }
    apply_redirects(graph);
}

/// Promote `+name` value nodes to flags when the recipe for this program
/// declares them. `+` is not a universal flag sigil — this is opt-in per
/// program, so `date +%s` is unaffected (no `+` entries in date's recipe).
///
/// Runs before `apply_program` so `ordered_words` already sees the promoted
/// nodes as flags, and the existing flag-argument binding machinery handles
/// the rest with no changes. `Arg(n)` edges are renumbered to close the gap
/// left by the promotion so dense-index consumers (#34, #39) stay correct.
///
/// Note: an undeclared `+` flag (e.g. `bash +x script.sh`) stays a
/// positional and pushes the script out of slot 0. This is the intended
/// trade-off — programs with no `+` entries in their recipe keep today's
/// behaviour exactly.
// graph, the command id, its name and the maps: four unrelated inputs,
// no natural struct to bundle them into.
#[allow(clippy::too_many_arguments)]
fn promote_plus_flags(graph: &mut Graph, command: NodeId, name: &str, maps: &crate::cmdmap::Maps) {
    let Some(program) = maps.lookup(name, &[]) else {
        return;
    };
    if !program.flags.keys().any(|k| k.starts_with('+')) {
        return;
    }

    // Collect edge indices and target node ids for all promotable words.
    let candidates: Vec<(usize, NodeId, String)> = graph
        .edges
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            if e.from != command {
                return None;
            }
            // usize::MAX marks a NAME=val prefix — not a positional
            let EdgeKind::Arg(n) = e.kind else {
                return None;
            };
            if n == usize::MAX {
                return None;
            }
            let flag_name = match &graph.nodes[e.to] {
                Node::Value(v) => v.text.clone()?,
                _ => return None,
            };
            if !flag_name.starts_with('+') || !program.flags.contains_key(&flag_name) {
                return None;
            }
            Some((i, e.to, flag_name))
        })
        .collect();

    for (edge_idx, node_id, flag_name) in candidates {
        // Re-read the current Arg number; a previous iteration may have
        // renumbered it already.
        let EdgeKind::Arg(promoted_n) = graph.edges[edge_idx].kind else {
            continue;
        };
        graph.edges[edge_idx].kind = EdgeKind::Has;

        let spans = graph.nodes[node_id].spans().to_vec();
        graph.nodes[node_id] = Node::Flag(FlagNode {
            spans,
            name: flag_name,
        });

        // Close the gap in Arg(n) numbering so dense-index consumers
        // see a contiguous sequence.
        for edge in graph.edges.iter_mut() {
            if edge.from != command {
                continue;
            }
            if let EdgeKind::Arg(ref mut m) = edge.kind
                && *m > promoted_n
                && *m != usize::MAX
            {
                *m -= 1;
            }
        }
    }
}

/// Turn every redirect into a reference edge on the command it attaches to.
///
/// **This one needs no recipe**, and that is not a hole in the inverted default.
/// The default exists because "what does this word mean to *this program*" is
/// unknowable without a map — but `> file` is not a program's argument, it is
/// shell syntax, and it truncates that file whatever the program is. `echo hi >
/// /etc/passwd` produced nothing at all before (#29): the jail saw a command
/// that references no paths, so a write outside the project was invisible.
///
/// It still runs in `apply_maps` rather than in `lower`, because `lower` stays
/// opinion-free — every claim the graph makes enters through one door.
fn apply_redirects(graph: &mut Graph) {
    let streams: Vec<(NodeId, StreamKind)> = graph
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(id, node)| match node {
            Node::Stream(stream) => Some((id, stream.kind)),
            _ => None,
        })
        .collect();
    for (stream, kind) in streams {
        let Some(command) = graph
            .edges_from(stream)
            .find(|e| e.kind == EdgeKind::On)
            .map(|e| e.to)
        else {
            continue;
        };
        let Some(target) = graph
            .edges_from(stream)
            .find(|e| e.kind == EdgeKind::Takes)
            .map(|e| e.to)
        else {
            continue;
        };
        // `>` and `>>` both create the file if it is missing; `>` additionally
        // destroys what was there, which `Writes` covers for now — the graph has
        // no truncate/append distinction and `StreamKind` already carries it
        let effects: &[EdgeKind] = match kind {
            StreamKind::In => &[EdgeKind::Reads],
            StreamKind::Out | StreamKind::Append | StreamKind::Both => {
                &[EdgeKind::Writes, EdgeKind::Creates]
            }
            StreamKind::Dup | StreamKind::HereString => continue,
        };
        for effect in effects {
            graph.link(command, target, *effect);
        }
    }
}

/// Every command references the program it runs, when that program is named by
/// a pathname.
///
/// Needs no recipe, like `apply_redirects`: the program word is not a program's
/// argument, it is what the shell resolves and executes whatever the program is.
///
/// The `/` test is the shell's rule, not the shape heuristic returning — a name
/// containing a slash is executed as a pathname, one without is searched for on
/// `PATH` (POSIX XCU 2.9.1.1). `looks_like_path` was wrong because shape stood
/// in for *meaning*, which only a recipe can give; nothing is being guessed
/// here, which is also why a bare `npm` mints nothing.
///
/// A wrapper's payload (`sudo /tmp/x.sh`) already has an `Execs` edge and owns
/// no bytes — the span test is what tells it from a command written in source.
fn apply_programs(graph: &mut Graph) {
    let named: Vec<NodeId> = graph
        .commands()
        .filter(|(_, cmd)| cmd.name.as_deref().is_some_and(|n| n.contains('/')))
        .map(|(id, _)| id)
        .filter(|id| !graph.owned_spans(*id).is_empty())
        .collect();
    for id in named {
        graph.link(id, id, EdgeKind::Execs);
    }
}

/// A command's flags and values in source order — the sequence a map is written
/// against.
fn ordered_words(graph: &Graph, command: NodeId) -> Vec<(NodeId, bool)> {
    let mut out: Vec<(NodeId, bool, usize)> = Vec::new();
    for edge in graph.edges_from(command) {
        let is_flag = match edge.kind {
            EdgeKind::Has => true,
            // `NAME=val` prefixes are not arguments and never occupy a slot
            EdgeKind::Arg(n) if n != usize::MAX => false,
            _ => continue,
        };
        let start = graph.nodes[edge.to]
            .spans()
            .first()
            .map_or(usize::MAX, |s| s.start);
        out.push((edge.to, is_flag, start));
    }
    out.sort_by_key(|(_, _, start)| *start);
    out.into_iter().map(|(id, flag, _)| (id, flag)).collect()
}

// graph, the command being mapped, its name, its words and the maps: five
// unrelated inputs to one traversal, with no two travelling together
#[allow(clippy::too_many_arguments)]
fn apply_program(
    graph: &mut Graph,
    command: NodeId,
    name: &str,
    words: &[(NodeId, bool)],
    ctx: &Mapping,
) {
    let maps = ctx.maps;
    // Finding the subcommand needs the global flags, because a flag that takes
    // an argument hides the subcommand behind it: in `git -c core.pager=x rm f`
    // the first *word* is `core.pager=x`, not `rm`. Real audit-log data shows
    // this misfiring — `git core.pager='!id'` appears as one of the most
    // frequent "subcommands" in a corpus of 123k invocations, and it is not a
    // subcommand at all.
    //
    // So: resolve the bare entry first for its flags, use those to skip flag
    // arguments, and only then decide which map applies.
    let global = maps.lookup(name, &[]);
    let leading = leading_positionals(graph, words, global);
    let Some(program) = maps.lookup(name, &leading) else {
        // no map, no claims — the inverted default
        return;
    };

    // 1. bind flag arguments, which is what makes the slot numbers below mean
    //    anything
    //
    // Each positional is kept with WHERE IT SITS in `words`, so a wrapper's
    // payload can be taken as the rest of the line rather than as the
    // positionals alone — `sudo grep -e pat file` must hand grep its `-e`, not
    // just `pat` and `file`.
    let mut positionals: Vec<(NodeId, usize)> = Vec::new();
    let mut pending_flag: Option<NodeId> = None;
    for (index, (id, is_flag)) in words.iter().enumerate() {
        if let Some(flag) = pending_flag.take() {
            graph.link(flag, *id, EdgeKind::Takes);
            if let Some(spec) = flag_spec(graph, program, flag)
                .or_else(|| global.and_then(|g| flag_spec(graph, g, flag)))
            {
                emit_effects(graph, command, *id, spec.kind, &spec.effect, ctx);
            }
            continue;
        }
        if *is_flag {
            // a subcommand entry inherits the program's global flags: `-c` is
            // git's, `--cached` is `git rm`'s, and both apply to `git -c x rm f`
            let takes = flag_spec(graph, program, *id)
                .or_else(|| global.and_then(|g| flag_spec(graph, g, *id)))
                .is_some_and(|f| f.takes);
            if takes {
                pending_flag = Some(*id);
            }
            continue;
        }
        positionals.push((*id, index));
    }

    // 2. the subcommand occupies the leading slots without being an argument to
    //    anything — two of them for `aws s3 cp`
    let offset = program.subcommand_depth();
    let slotted: Vec<(NodeId, usize)> = positionals.iter().skip(offset).copied().collect();

    // 3. the payload of a wrapper is another program, running under its own map
    //    and — for `ssh` and friends — on another machine
    //
    // A literal `--` at the payload boundary is the POSIX end-of-options
    // marker, not part of the payload — `kubectl exec pod -- cat /etc/config`
    // and `sudo -- rm -rf /` both use it to separate the wrapper's own flags
    // from the command that follows. It still occupies a positional slot, so
    // skip it before reading the slot after it as the program word (#24).
    let payload_at = program
        .nested_command()
        .and_then(|nested| nested.slots.payload_start())
        .map(|at| match slotted.get(at) {
            Some(&(id, _)) if value_text(graph, id).as_deref() == Some("--") => at + 1,
            _ => at,
        });
    if let Some(nested) = program.nested_command()
        && let Some(at) = payload_at
        && let Some(&(program_word, index)) = slotted.get(at)
        && let Some(payload_name) = value_text(graph, program_word)
    {
        // the machine, when the recipe names one. `ssh HOST cmd` says slot 0 is
        // a host and the rest is a command, and those two statements together
        // already say the command runs there.
        let machine = program
            .machine_slot()
            .and_then(|n| slotted.get(n))
            .and_then(|(id, _)| value_text(graph, *id));
        let payload = spawn_payload(
            graph,
            command,
            Payload {
                program_word,
                name: payload_name.clone(),
                machine,
            },
        );
        graph.link(command, payload, EdgeKind::Spawns);
        if nested.effect.contains(&crate::cmdmap::Effect::Exec) {
            graph.link(command, payload, EdgeKind::Execs);
        }
        // The payload is everything after the program word, IN SOURCE ORDER and
        // including flags. Taking only the positionals dropped them: `sudo rm -rf
        // x` lost the `-rf`, and `sudo grep -e pat file` never bound `-e` at all,
        // so a flag carrying a path (`grep -f list`) lost its read edge too.
        let inner: Vec<(NodeId, bool)> = words[index + 1..].to_vec();
        apply_program(graph, payload, &payload_name, &inner, ctx);
        return;
    }
    let slotted: Vec<NodeId> = slotted.into_iter().map(|(id, _)| id).collect();

    // the flags actually present, which is what a `when` guard is checked
    // against
    let present: Vec<String> = words
        .iter()
        .filter(|(_, is_flag)| *is_flag)
        .filter_map(|(id, _)| match &graph.nodes[*id] {
            Node::Flag(f) => Some(f.name.clone()),
            _ => None,
        })
        .collect();
    let total = slotted.len();
    for (slot, value) in slotted.iter().enumerate() {
        let Some(arg) = program.arg_for(slot, total, &present) else {
            continue;
        };
        let target = match arg.kind {
            // a set is its own node: the effects point at everything beneath the
            // root, not at the word that named it
            crate::cmdmap::Kind::PathSet => {
                let recursive = arg.recursive
                    || arg
                        .recursive_with
                        .iter()
                        .any(|flag| present.iter().any(|p| p == flag));
                path_set_node(graph, *value, recursive).unwrap_or(*value)
            }
            _ => *value,
        };
        emit_effects(graph, command, target, arg.kind, &arg.effect, ctx);
    }
}

/// The leading positionals that are not some flag's argument — the words a
/// subcommand path is matched against.
///
/// Uses the program's global flags, which is the only way to tell a subcommand
/// from a value the shell put in the same position. Returns a run rather than a
/// single word because a subcommand can be a tree: `aws s3 cp` needs two words
/// resolved before the right entry can be chosen, and `git rm` needs one.
fn leading_positionals(
    graph: &Graph,
    words: &[(NodeId, bool)],
    global: Option<&crate::cmdmap::Program>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for (id, is_flag) in words {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *is_flag {
            skip_next = global
                .and_then(|g| flag_spec(graph, g, *id))
                .is_some_and(|f| f.takes);
            continue;
        }
        // a dynamic word is a subcommand nobody can name, and every word after
        // it sits at an unknown depth — stop rather than match the wrong entry
        let Node::Value(v) = &graph.nodes[*id] else {
            break;
        };
        let Some(text) = v.text.clone() else { break };
        out.push(text);
    }
    out
}

/// A `PathSet` node for the path `value` names, sharing its spans so an edit
/// still knows which bytes to touch.
///
/// Built for a remote root too — `aws s3 cp s3://b/prefix ./x --recursive` names
/// a tree at each end, and the set carries which end it is.
fn path_set_node(graph: &mut Graph, value: NodeId, recursive: bool) -> Option<NodeId> {
    let Node::Value(node) = &graph.nodes[value] else {
        return None;
    };
    // a dynamic word names a set nobody can enumerate, so there is nothing to
    // build a root from — the existing abstain-rather-than-guess convention
    let root = node.text.clone()?;
    let spans = node.spans.clone();
    let locality = node.facts.locality;
    let remote = node.remote.clone();
    let set = crate::globs::PathSet {
        roots: vec![root],
        recursive,
        ..Default::default()
    };
    Some(graph.push(Node::PathSet(PathSetNode {
        spans,
        set,
        locality,
        remote,
    })))
}

fn value_text(graph: &Graph, id: NodeId) -> Option<String> {
    match &graph.nodes[id] {
        Node::Value(value) => value.text.clone(),
        _ => None,
    }
}

/// Mint a `Command` node for a wrapper's payload.
///
/// `sudo rm -rf x` used to be one command called `sudo` with rm's delete edge
/// hanging off it — the graph literally claimed *sudo* deletes the file, and a
/// rewrite could not target the inner program at all (COMMAND-GRAPH's "nothing
/// about a wrapper's payload creates a `Command` node yet").
///
/// Three facts travel down into the payload, and each is the answer to a
/// question somebody asks:
///
/// - **locality** — `ssh host cat /etc/hosts` reads a file, on another machine.
///   Without a command to hang that on there is no way to say it, which is why
///   ssh's positionals were left unmapped and #4 was "fixed" by silence.
/// - **privilege** — `sudo rm x` runs *rm* as root. The elevation belonged to
///   the `sudo` node, where nothing that cares could reach it.
/// - **host** — which machine, not just "not this one".
///
/// The node owns **no segments**: the program word is already owned by the
/// `Value` it was lowered as, and two owners for one stretch of source is the
/// span-surgery bug (#7) by construction. It borrows that word's spans as its
/// own for reporting, and an edit still addresses the `Value`.
/// The three things that describe a wrapper's payload, which travel together
/// and mean nothing apart — the context-struct convention from #19.
struct Payload {
    /// the `Value` the program name was lowered as
    program_word: NodeId,
    name: String,
    /// the machine the recipe named, if it named one
    machine: Option<String>,
}

fn spawn_payload(graph: &mut Graph, outer: NodeId, payload: Payload) -> NodeId {
    let Payload {
        program_word,
        name,
        machine,
    } = payload;
    let (locality, host, privilege) = match &graph.nodes[outer] {
        Node::Command(cmd) => (cmd.locality, cmd.host.clone(), cmd.privilege),
        _ => (Locality::Local, None, Privilege::Normal),
    };
    let spans = graph.nodes[program_word].spans().to_vec();
    graph.push(Node::Command(CommandNode {
        spans,
        name: Some(name.clone()),
        // a machine named here wins; otherwise a remote wrapper keeps its
        // payload remote, so `ssh host sudo rm x` is remote all the way down
        locality: match machine.is_some() {
            true => Locality::Remote,
            false => locality,
        },
        host: machine.or(host),
        // elevation is inherited (`sudo rm` runs rm as root) but can also start
        // here — `ssh host sudo rm x` elevates on the far side
        privilege: match elevates(&name) {
            true => Privilege::Elevated,
            false => privilege,
        },
    }))
}

/// Re-parse a shell script argument and graft what it says onto `outer`.
///
/// `bash -c 'cat /etc/passwd'` used to claim **nothing**. `Kind::Code` produces
/// no edges by design, and the `Spawns` edge this doc has always promised for
/// `bash -c` was never minted, so the classic jail-escape vector was the one
/// interpreter form with no backstop: `on_inline_script` stays quiet precisely
/// *because* the payload parses.
///
/// The grafted nodes **own no bytes**. The script's text is already owned by the
/// `Value` holding it, and two owners for one stretch of source is the
/// span-surgery bug (#7) by construction — so the inner nodes borrow the
/// holder's spans for ordering and reporting, and the segment table is left
/// bit-identical. That is what keeps both merge gates out of the blast radius:
/// P1 and P2 run on the bare lowering, and this is `apply_maps`.
///
/// Borrowed rather than empty spans because [`Graph::commands`] and
/// [`Graph::groups`] both sort on the first span: at the holder's offset,
/// `bash -c 'rm x' | grep y` orders `bash`, `rm`, `grep`; at `usize::MAX` the
/// payload would sort after every outer command.
/// The two ends of a script argument: the command that will run it, and the
/// `Value` holding its text. Neither means anything without the other — the
/// context-struct convention from #19, same as [`Payload`].
struct Script {
    outer: NodeId,
    holder: NodeId,
}

fn spawn_script(graph: &mut Graph, script_arg: Script, ctx: &Mapping) {
    let Script { outer, holder } = script_arg;
    if ctx.depth >= MAX_SCRIPT_DEPTH {
        return;
    }
    // a dynamic script (`bash -c "$CMD"`) has no text to read, and abstaining is
    // the documented convention for one
    let Some(script) = value_text(graph, holder) else {
        return;
    };
    if script.trim().is_empty() {
        return;
    }
    let inner = lower(&script);
    if inner.nodes.is_empty() {
        return;
    }
    let base = graph.nodes.len();
    let spans = graph.nodes[holder].spans().to_vec();
    let (locality, host, privilege) = match &graph.nodes[outer] {
        Node::Command(cmd) => (cmd.locality, cmd.host.clone(), cmd.privilege),
        _ => (Locality::Local, None, Privilege::Normal),
    };
    // segments are deliberately NOT copied: the inner offsets index the script
    // string, not this graph's source, and nothing may own bytes twice
    for node in inner.nodes {
        graph.nodes.push(match node {
            Node::Command(cmd) => Node::Command(CommandNode {
                spans: spans.clone(),
                // where the script runs is where its shell runs — `ssh h bash -c
                // 'rm x'` is remote all the way down, and `sudo bash -c 'rm x'`
                // is root all the way down
                locality: cmd.locality.or(locality),
                host: cmd.host.clone().or_else(|| host.clone()),
                privilege: match cmd.privilege {
                    Privilege::Elevated => Privilege::Elevated,
                    _ => privilege,
                },
                ..cmd
            }),
            Node::Flag(n) => Node::Flag(FlagNode {
                spans: spans.clone(),
                ..n
            }),
            Node::Value(n) => Node::Value(ValueNode {
                spans: spans.clone(),
                ..n
            }),
            Node::Stream(n) => Node::Stream(StreamNode {
                spans: spans.clone(),
                ..n
            }),
            Node::Heredoc(n) => Node::Heredoc(HeredocNode {
                spans: spans.clone(),
                ..n
            }),
            Node::Connector(n) => Node::Connector(ConnectorNode {
                spans: spans.clone(),
                ..n
            }),
            Node::PathSet(n) => Node::PathSet(PathSetNode {
                spans: spans.clone(),
                ..n
            }),
        });
    }
    for edge in inner.edges {
        graph.edges.push(Edge {
            from: edge.from + base,
            to: edge.to + base,
            kind: edge.kind,
        });
    }
    // the script's top-level commands are what this one starts. Every command in
    // the inner graph is top-level for this purpose: an inner pipeline's stages
    // are all spawned by the same `-c`.
    let inner_commands: Vec<NodeId> = (base..graph.nodes.len())
        .filter(|id| matches!(graph.nodes[*id], Node::Command(_)))
        .collect();
    for id in &inner_commands {
        graph.link(outer, *id, EdgeKind::Spawns);
        graph.link(outer, *id, EdgeKind::Execs);
    }
    // and now the inner commands get their own recipes applied, one level down
    let deeper = Mapping {
        maps: ctx.maps,
        depth: ctx.depth + 1,
    };
    for id in inner_commands {
        let Node::Command(cmd) = &graph.nodes[id] else {
            continue;
        };
        let Some(name) = cmd.name.clone() else {
            continue;
        };
        let words = ordered_words(graph, id);
        apply_program(graph, id, &name, &words, &deeper);
    }
}

fn flag_spec<'a>(
    graph: &Graph,
    program: &'a crate::cmdmap::Program,
    flag: NodeId,
) -> Option<&'a crate::cmdmap::Flag> {
    let Node::Flag(node) = &graph.nodes[flag] else {
        return None;
    };
    program.flags.get(&node.name)
}

// the same: a target, what it is, and what happens to it
#[allow(clippy::too_many_arguments)]
fn emit_effects(
    graph: &mut Graph,
    command: NodeId,
    value: NodeId,
    kind: crate::cmdmap::Kind,
    effects: &[crate::cmdmap::Effect],
    ctx: &Mapping,
) {
    use crate::cmdmap::Effect;
    // a script is not a target to point an edge at, it is a command line to
    // read: re-parse it and graft what it says onto this command
    if kind == crate::cmdmap::Kind::Shell {
        spawn_script(
            graph,
            Script {
                outer: command,
                holder: value,
            },
            ctx,
        );
        return;
    }
    // only kinds that name something the graph can point at produce edges; the
    // rest are recorded in the map for later stages
    if !kind.is_path() {
        return;
    }
    // Locality is NOT checked here. An edge says what the command does to what
    // it names; where that thing lives is a fact of the target node, and
    // `Graph::references` combines the two. Dropping the edge instead would say
    // `aws s3 rm s3://b/key` deletes nothing, which is false — it deletes a key
    // in a bucket. Callers that mean this filesystem ask `referenced_paths`.
    for effect in effects {
        let edge = match effect {
            Effect::Read => EdgeKind::Reads,
            Effect::Write => EdgeKind::Writes,
            Effect::Delete => EdgeKind::Deletes,
            Effect::Create => EdgeKind::Creates,
            // exec is checked against `cmd`, never a path
            Effect::Exec => continue,
        };
        graph.link(command, value, edge);
    }
}

#[cfg(test)]
mod tests {
    //! What examples of graph behaviour look like lives in
    //! `tests/graph_cases/*.toml` — a command and what the graph should claim
    //! about it, as data. What stays here is what a case file has no way to
    //! say: pure functions, and the span bookkeeping that is expressed in node
    //! ids rather than in text.

    use super::*;

    #[test]
    fn a_location_prefix_makes_a_word_remote() {
        // the discriminator shared by `aws s3 cp`, `kubectl cp` and `scp`: a
        // `:` in a word that does not begin at a filesystem root
        for word in [
            "s3://bucket/key",
            "host:/tmp/x",
            "user@host:notes.txt",
            "pod:/etc/config",
            "ns/pod:/etc/config",
        ] {
            assert_eq!(locality_of(word), Locality::Remote, "{word}");
        }
        // ...and everything that could name something outside this directory
        // starts with a separator or a dot, so it cannot be mistaken for one
        for word in [
            "/var/log/a:b",
            "./a:b",
            "../a:b",
            "~/a:b",
            "src/main.rs",
            "README.md",
            "-",
            "",
        ] {
            assert_eq!(locality_of(word), Locality::Local, "{word}");
        }
    }

    #[test]
    fn a_remote_reference_splits_into_machine_and_path() {
        // the split nothing configures yet, and the reason the graph carries it
        // anyway: `s3://prod-bucket/key` is a key in a NAMED bucket, and a rule
        // that cannot see the bucket can never be written
        let s3 = RemoteRef::parse("s3://prod-bucket/data/x.csv").expect("remote");
        assert_eq!(s3.scheme.as_deref(), Some("s3"));
        assert_eq!(s3.authority, "prod-bucket");
        assert_eq!(s3.path, "/data/x.csv");

        let scp = RemoteRef::parse("user@host:/etc/shadow").expect("remote");
        assert_eq!(scp.scheme, None);
        assert_eq!(scp.authority, "user@host");
        assert_eq!(scp.path, "/etc/shadow");

        // a bucket with no key, and a host with no path
        assert_eq!(RemoteRef::parse("s3://bucket").unwrap().path, "");
        assert_eq!(RemoteRef::parse("host:").unwrap().path, "");
        // kubectl's namespaced form: the machine is `ns/pod`
        assert_eq!(
            RemoteRef::parse("ns/pod:/etc/x").unwrap().authority,
            "ns/pod"
        );

        assert_eq!(RemoteRef::parse("/var/log/a:b"), None);
        assert_eq!(RemoteRef::parse("src/main.rs"), None);
    }

    #[test]
    fn lowering_alone_makes_no_claims() {
        // `lower` stays opinion-free: every claim enters through `apply_maps`,
        // so a caller with no recipes gets exactly the stage-1 graph. The case
        // files all run WITH recipes, so this is the one direction they cannot
        // check.
        let g = lower("rm -rf /etc/passwd > /tmp/log");
        assert!(!g.edges.iter().any(|e| matches!(
            e.kind,
            EdgeKind::Reads
                | EdgeKind::Writes
                | EdgeKind::Deletes
                | EdgeKind::Creates
                | EdgeKind::Execs
        )));
        assert!(g.references().is_empty());
    }

    #[test]
    fn emit_with_replaces_only_the_named_node() {
        // the #7 regression in graph form: rewriting the program name must
        // leave every flag and argument exactly where it was. Expressed in node
        // ids, which is why it is here and not in a case file.
        let g = lower("grep -n TODO src/main.rs");
        let (cmd, _) = g.commands().next().unwrap();
        let name_span = g.nodes[cmd].spans()[0];
        let owner = g.segment_owner(name_span).expect("the name span is owned");
        let mut edits = HashMap::new();
        edits.insert(owner, "rg".to_string());
        assert_eq!(g.emit_with(&edits), "rg -n TODO src/main.rs");
    }

    #[test]
    fn a_minted_payload_command_owns_no_bytes() {
        // Two owners for one stretch of source is the span-surgery bug (#7) by
        // construction, and a wrapper's payload is what invites it: `rm` is
        // already a `Value` of `sudo`, and the `Command` minted for it borrows
        // those spans for reporting without claiming them. An edit still
        // addresses the `Value`, which is what `edits.toml` exercises.
        let maps = crate::cmdmap::Maps::builtin().expect("recipes");
        let g = lower_with_maps("sudo rm -rf /etc/x", &maps);
        assert!(g.overlapping_segments().is_none());
        let (payload, node) = g
            .commands()
            .find(|(_, c)| c.name.as_deref() == Some("rm"))
            .expect("the payload is a command of its own");
        assert!(g.owned_spans(payload).is_empty());
        let owner = g
            .segment_owner(node.spans[0])
            .expect("the program word is owned by something");
        assert!(matches!(g.node(owner), Node::Value(_)), "{owner:?}");
    }

    #[test]
    fn a_grafted_script_owns_no_bytes() {
        // The same invariant, one level harder: a re-parsed `-c` script's nodes
        // carry spans that index the SCRIPT STRING, not this source, so copying
        // them into the segment table would corrupt every offset after the
        // graft. They borrow the holder `Value`'s spans for ordering and own
        // nothing, which is what keeps P1 and P2 out of the blast radius — both
        // gates run on the bare lowering, and this happens in `apply_maps`.
        let maps = crate::cmdmap::Maps::builtin().expect("recipes");
        let source = "bash -c 'cat /etc/passwd'";
        let g = lower_with_maps(source, &maps);
        assert!(g.overlapping_segments().is_none());
        assert_eq!(g.emit(), source, "the graft must not disturb emission");
        let (grafted, _) = g
            .commands()
            .find(|(_, c)| c.name.as_deref() == Some("cat"))
            .expect("the script's command is grafted in");
        assert!(g.owned_spans(grafted).is_empty());
        // and the same for everything the graft brought with it, not just the
        // command node — a `Value` claiming inner offsets is the dangerous one
        assert!(
            g.segments.iter().all(|(span, _)| span.end <= source.len()),
            "a grafted node claimed bytes outside the source"
        );
    }

    #[test]
    fn a_grafted_script_sorts_at_its_holder() {
        // `commands()` and `groups()` both order by first span. Empty spans
        // would sort to `usize::MAX` and put the payload after every outer
        // command; borrowing the holder's spans keeps source order.
        let maps = crate::cmdmap::Maps::builtin().expect("recipes");
        let g = lower_with_maps("bash -c 'rm x' | grep y", &maps);
        let names: Vec<&str> = g
            .commands()
            .filter_map(|(_, c)| c.name.as_deref())
            .collect();
        assert_eq!(names, ["bash", "rm", "grep"]);
    }
}
