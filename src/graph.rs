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

/// Whether a command's arguments name things on *this* filesystem.
///
/// Populated by the locality map in sub-task 5. Stage 1 has no map, so
/// everything is `Local` — the field exists to fix the shape, not to be trusted
/// yet. Note this is the fact `walk_words` needs in order to stop flagging
/// `kubectl exec … -- cat /etc/config` as a local path escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    Local,
    Remote,
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
    /// begins with `/`
    pub absolute: bool,
    /// a path-shaped word that is not absolute (`src/x`, `../y`, `~/z`)
    pub relative: bool,
    /// contains an unquoted glob metacharacter
    pub glob: bool,
    /// fully static — every byte is known at parse time
    pub literal: bool,
    /// contains an expansion or substitution, so the value is not knowable
    pub dynamic: bool,
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
    pub locality: Locality,
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
    /// command → command it starts in a fresh parse (`bash -c '…'`, and in
    /// sub-task 2 an unquoted heredoc body)
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

    pub fn commands(&self) -> impl Iterator<Item = (NodeId, &CommandNode)> {
        self.nodes.iter().enumerate().filter_map(|(i, n)| match n {
            Node::Command(c) => Some((i, c)),
            _ => None,
        })
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
            Node::PathSet(_) => "<pathset>".into(),
        };
        let mut out = Vec::new();
        for (i, (id, cmd)) in self.commands().enumerate() {
            out.push(format!(
                "cmd[{i}] name={} priv={:?}",
                cmd.name.as_deref().unwrap_or("<dynamic>"),
                cmd.privilege
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
    let mut graph = Graph {
        source: source.to_string(),
        ..Default::default()
    };
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return graph;
    }
    let Some(tree) = parser.parse(source, None) else {
        return graph;
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
            "pipeline" | "list" => {
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
        let mut members: Vec<NodeId> = Vec::new();
        let mut connectors: Vec<Connector> = Vec::new();
        for child in children {
            if child.is_named() {
                if let Some(head) = self.walk_capturing_head(*child) {
                    members.push(head);
                }
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
            connectors.push(kind);
        }
        for (i, pair) in members.windows(2).enumerate() {
            let kind = connectors.get(i).copied().unwrap_or(Connector::Seq);
            self.graph.link(pair[0], pair[1], EdgeKind::Flow(kind));
        }
        members
    }

    /// Walk a subtree and report the first `Command` it minted — the member's
    /// "head", which is what connector edges attach to.
    fn walk_capturing_head(&mut self, node: TsNode) -> Option<NodeId> {
        let before = self.graph.nodes.len();
        self.walk(node, None);
        (before..self.graph.nodes.len()).find(|&i| matches!(self.graph.nodes[i], Node::Command(_)))
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
        let mut members = self.lower_group(&body);
        let head = members.first().copied();

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
            if let (Some(previous), Some(first)) =
                (members.last().copied(), nested.first().copied())
            {
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

    fn lower_command(&mut self, node: TsNode) -> NodeId {
        let id = self.graph.push(Node::Command(CommandNode {
            spans: Vec::new(),
            name: None,
            locality: Locality::Local,
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
            cmd.privilege = match name.as_deref().map(basename) {
                Some("sudo") | Some("doas") | Some("pkexec") => Privilege::Elevated,
                _ => Privilege::Normal,
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

    fn lower_stream(&mut self, node: TsNode) -> NodeId {
        let span = Span::of(node);
        let raw = span.text(self.source);
        let operator = raw.trim_start_matches(|c: char| c.is_ascii_digit());
        let kind = if node.kind() == "herestring_redirect" || operator.starts_with("<<<") {
            StreamKind::HereString
        } else if operator.starts_with(">>") {
            StreamKind::Append
        } else if operator.starts_with("&>") || operator.starts_with(">&") {
            StreamKind::Both
        } else if raw.contains(">&") || raw.contains("<&") {
            StreamKind::Dup
        } else if operator.starts_with('>') {
            StreamKind::Out
        } else {
            StreamKind::In
        };
        let id = self.graph.push(Node::Stream(StreamNode {
            spans: vec![span],
            kind,
        }));
        self.graph.own(span, id);
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
    ValueFacts {
        absolute: value.starts_with('/'),
        relative: !value.starts_with('/') && (value.contains('/') || value == "." || value == ".."),
        // metacharacters in the *resolved* text: `'*'` is a literal asterisk
        glob: text.is_some_and(|t| t.contains(['*', '?'])) || raw.contains('['),
        literal: !dynamic,
        dynamic,
    }
}

fn basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Mirrors `bash::resolve_text` — quoting removed, `None` when any part of the
/// word is an expansion whose value is not knowable at parse time.
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
    let commands: Vec<NodeId> = graph.commands().map(|(id, _)| id).collect();
    for id in commands {
        let Node::Command(cmd) = &graph.nodes[id] else {
            continue;
        };
        let Some(name) = cmd.name.clone() else {
            continue;
        };
        let words = ordered_words(graph, id);
        apply_program(graph, id, &name, &words, maps);
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
    maps: &crate::cmdmap::Maps,
) {
    // Finding the subcommand needs the global flags, because a flag that takes
    // an argument hides the subcommand behind it: in `git -c core.pager=x rm f`
    // the first *word* is `core.pager=x`, not `rm`. Real audit-log data shows
    // this misfiring — `git core.pager='!id'` appears as one of the most
    // frequent "subcommands" in a corpus of 123k invocations, and it is not a
    // subcommand at all.
    //
    // So: resolve the bare entry first for its flags, use those to skip flag
    // arguments, and only then decide which map applies.
    let global = maps.lookup(name, None);
    let first_positional = first_positional_after_flags(graph, words, global);
    let Some(program) = maps.lookup(name, first_positional.as_deref()) else {
        // no map, no claims — the inverted default
        return;
    };

    // 1. bind flag arguments, which is what makes the slot numbers below mean
    //    anything
    let mut positionals: Vec<NodeId> = Vec::new();
    // where the first positional sits in `words`, so a wrapper's payload can be
    // taken as the REST OF THE LINE rather than as the positionals alone —
    // `sudo grep -e pat file` must hand grep its `-e`, not just `pat` and `file`
    let mut payload_start: Option<usize> = None;
    let mut pending_flag: Option<NodeId> = None;
    for (index, (id, is_flag)) in words.iter().enumerate() {
        if let Some(flag) = pending_flag.take() {
            graph.link(flag, *id, EdgeKind::Takes);
            if let Some(spec) = flag_spec(graph, program, flag)
                .or_else(|| global.and_then(|g| flag_spec(graph, g, flag)))
            {
                emit_effects(graph, command, *id, spec.kind, &spec.effect);
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
        if payload_start.is_none() {
            payload_start = Some(index);
        }
        positionals.push(*id);
    }

    // 2. a subcommand occupies slot 0 without being an argument to anything
    let offset = usize::from(program.subcommand.is_some());
    let slotted: Vec<NodeId> = positionals.iter().skip(offset).copied().collect();

    // 3. the payload of a wrapper is another program, mapped by its own rules
    if let Some(nested) = program.nested_command()
        && let Some(start) = payload_start
        && let Some((payload_name, _)) = payload(graph, &slotted)
    {
        if nested.effect.contains(&crate::cmdmap::Effect::Exec) {
            graph.link(command, slotted[0], EdgeKind::Execs);
        }
        // The payload is everything after the program word, IN SOURCE ORDER and
        // including flags. Taking only the positionals dropped them: `sudo rm -rf
        // x` lost the `-rf`, and `sudo grep -e pat file` never bound `-e` at all,
        // so a flag carrying a path (`grep -f list`) lost its read edge too.
        //
        // Reference edges still land on the OUTER command node: there is no node
        // for the payload yet, and "what does this command line delete?" is the
        // question rules actually ask.
        let inner: Vec<(NodeId, bool)> = words[start + 1..].to_vec();
        apply_program(graph, command, &payload_name, &inner, maps);
        return;
    }

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
        emit_effects(graph, command, target, arg.kind, &arg.effect);
    }
}

/// The first positional that is not some flag's argument.
///
/// Uses the program's global flags, which is the only way to tell a subcommand
/// from a value the shell put in the same position.
fn first_positional_after_flags(
    graph: &Graph,
    words: &[(NodeId, bool)],
    global: Option<&crate::cmdmap::Program>,
) -> Option<String> {
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
        if let Node::Value(v) = &graph.nodes[*id] {
            return v.text.clone();
        }
    }
    None
}

/// A `PathSet` node for the path `value` names, sharing its spans so an edit
/// still knows which bytes to touch.
fn path_set_node(graph: &mut Graph, value: NodeId, recursive: bool) -> Option<NodeId> {
    let Node::Value(node) = &graph.nodes[value] else {
        return None;
    };
    // a dynamic word names a set nobody can enumerate, so there is nothing to
    // build a root from — the existing abstain-rather-than-guess convention
    let root = node.text.clone()?;
    let spans = node.spans.clone();
    let set = crate::globs::PathSet {
        roots: vec![root],
        recursive,
        ..Default::default()
    };
    Some(graph.push(Node::PathSet(PathSetNode { spans, set })))
}

/// The payload of a wrapper: its program name, and the words that follow.
fn payload(graph: &Graph, slotted: &[NodeId]) -> Option<(String, Vec<NodeId>)> {
    let first = *slotted.first()?;
    let Node::Value(value) = &graph.nodes[first] else {
        return None;
    };
    let name = value.text.clone()?;
    Some((name, slotted[1..].to_vec()))
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
) {
    use crate::cmdmap::Effect;
    // only kinds that name something the graph can point at produce edges; the
    // rest are recorded in the map for later stages
    if !kind.is_path() {
        return;
    }
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
    use super::*;

    fn names(graph: &Graph) -> Vec<String> {
        graph
            .commands()
            .map(|(_, c)| c.name.clone().unwrap_or_else(|| "<dynamic>".into()))
            .collect()
    }

    #[test]
    fn round_trips_a_simple_command() {
        let g = lower("grep -n TODO src/main.rs");
        assert_eq!(g.emit(), "grep -n TODO src/main.rs");
        assert_eq!(names(&g), vec!["grep"]);
    }

    #[test]
    fn flag_and_positional_are_distinguished() {
        let g = lower("grep -n TODO src/main.rs");
        let (cmd, _) = g.commands().next().unwrap();
        let flags: Vec<_> = g
            .edges_from(cmd)
            .filter(|e| e.kind == EdgeKind::Has)
            .collect();
        let args: Vec<_> = g
            .edges_from(cmd)
            .filter(|e| matches!(e.kind, EdgeKind::Arg(_)))
            .collect();
        assert_eq!(flags.len(), 1);
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn inline_flag_argument_is_bound_by_takes() {
        let g = lower("ls --color=auto");
        let takes: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.kind == EdgeKind::Takes)
            .collect();
        assert_eq!(takes.len(), 1, "--color=auto should bind its own argument");
        let Node::Value(v) = g.node(takes[0].to) else {
            panic!("Takes target must be a Value")
        };
        assert_eq!(v.text.as_deref(), Some("auto"));
        assert_eq!(g.emit(), "ls --color=auto");
    }

    #[test]
    fn separated_flag_argument_is_left_unbound() {
        // whether `-e` consumes the next word is a map question (sub-task 5);
        // guessing here is exactly the class of bug #4 kept re-patching
        let g = lower("grep -e foo bar");
        assert!(!g.edges.iter().any(|e| e.kind == EdgeKind::Takes));
    }

    #[test]
    fn pipeline_members_are_joined_by_a_flow_edge() {
        let g = lower("cat notes.txt | grep secret");
        assert_eq!(names(&g), vec!["cat", "grep"]);
        let flow: Vec<_> = g
            .edges
            .iter()
            .filter(|e| matches!(e.kind, EdgeKind::Flow(Connector::Pipe)))
            .collect();
        assert_eq!(flow.len(), 1);
        assert_eq!(g.emit(), "cat notes.txt | grep secret");
    }

    #[test]
    fn chain_connectors_are_typed_and_addressable() {
        let g = lower("make build && make test");
        let connectors: Vec<_> = g
            .nodes
            .iter()
            .filter_map(|n| match n {
                Node::Connector(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(connectors.len(), 1);
        assert_eq!(connectors[0].kind, Connector::And);
        // own span: sub-task 10's `insert` splices relative to this
        assert_eq!(connectors[0].spans[0].text(&g.source), "&&");
    }

    #[test]
    fn heredoc_nested_pipeline_is_reparented() {
        // #12: the grammar buries `| grep secret` inside the heredoc redirect,
        // so without re-parenting `cat` and `grep` are unrelated in the graph
        let g = lower("cat <<EOF | grep secret\nline one\nEOF");
        assert_eq!(names(&g), vec!["cat", "grep"]);
        let flow: Vec<_> = g
            .edges
            .iter()
            .filter(|e| matches!(e.kind, EdgeKind::Flow(Connector::Pipe)))
            .collect();
        assert_eq!(flow.len(), 1, "cat must flow into grep across the heredoc");
        let Node::Command(from) = g.node(flow[0].from) else {
            unreachable!()
        };
        let Node::Command(to) = g.node(flow[0].to) else {
            unreachable!()
        };
        assert_eq!(from.name.as_deref(), Some("cat"));
        assert_eq!(to.name.as_deref(), Some("grep"));
    }

    #[test]
    fn heredoc_nested_chain_carries_its_own_connector() {
        // `<<EOF && rm x` gets no `list` wrapper — the `&&` is a bare token
        // among the redirect's children
        let g = lower("cat <<EOF && rm x\nbody\nEOF");
        assert_eq!(names(&g), vec!["cat", "rm"]);
        assert!(
            g.edges
                .iter()
                .any(|e| matches!(e.kind, EdgeKind::Flow(Connector::And))),
            "expected an And flow edge, got {:?}",
            g.edges.iter().map(|e| e.kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn reparenting_does_not_disturb_the_round_trip() {
        for src in [
            "cat <<EOF | grep secret\nline one\nEOF",
            "cat <<-EOF | grep x\n\tbody\nEOF",
            "cat <<'EOF' | grep x\nbody\nEOF",
            "cat <<EOF && rm x\nbody\nEOF",
            "echo a | cat <<EOF | grep x\nbody\nEOF",
        ] {
            let g = lower(src);
            assert_eq!(g.emit(), src, "P1 violated for {src:?}");
            assert!(
                g.overlapping_segments().is_none(),
                "overlapping segments for {src:?}"
            );
        }
    }

    #[test]
    fn redirect_becomes_a_stream_attached_to_its_command() {
        let g = lower("echo hi > out.txt");
        let stream = g
            .nodes
            .iter()
            .enumerate()
            .find_map(|(i, n)| matches!(n, Node::Stream(_)).then_some(i))
            .expect("stream node");
        assert!(g.edges_from(stream).any(|e| e.kind == EdgeKind::On));
        assert_eq!(g.emit(), "echo hi > out.txt");
    }

    #[test]
    fn dynamic_word_is_marked_and_not_resolved() {
        let g = lower("cat $TARGET");
        let values: Vec<_> = g
            .nodes
            .iter()
            .filter_map(|n| match n {
                Node::Value(v) => Some(v),
                _ => None,
            })
            .collect();
        let dynamic = values
            .iter()
            .find(|v| v.facts.dynamic)
            .expect("dynamic value");
        assert!(dynamic.text.is_none());
        assert!(!dynamic.facts.literal);
    }

    #[test]
    fn absolute_and_relative_are_distinguished() {
        let g = lower("cp src/a.txt /etc/b.txt");
        let mut facts: Vec<_> = g
            .nodes
            .iter()
            .filter_map(|n| match n {
                Node::Value(v) => Some(v.facts),
                _ => None,
            })
            .collect();
        facts.retain(|f| f.absolute || f.relative);
        assert_eq!(facts.len(), 2);
        assert!(facts.iter().any(|f| f.absolute));
        assert!(facts.iter().any(|f| f.relative));
    }

    #[test]
    fn command_substitution_payload_is_spawned() {
        let g = lower("grep pattern $(cat list.txt)");
        assert!(names(&g).contains(&"cat".to_string()));
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::Spawns));
        assert_eq!(g.emit(), "grep pattern $(cat list.txt)");
    }

    #[test]
    fn no_reference_edges_without_an_argument_map() {
        // the inverted default: an unmapped program produces no claims at all
        let g = lower("rm -rf /etc/passwd");
        assert!(!g.edges.iter().any(|e| matches!(
            e.kind,
            EdgeKind::Reads
                | EdgeKind::Writes
                | EdgeKind::Deletes
                | EdgeKind::Creates
                | EdgeKind::Execs
        )));
    }

    #[test]
    fn unmodelled_constructs_still_round_trip() {
        // `if`/`for` are not modelled in stage 1; their keywords fall through
        // as gaps, and the commands inside them are still lowered
        for src in [
            "if [ -f x ]; then cat x; fi",
            "for f in *.rs; do rustfmt $f; done",
            "while read l; do echo $l; done",
        ] {
            assert_eq!(lower(src).emit(), src, "round-trip failed for {src}");
        }
    }

    #[test]
    fn emit_with_replaces_only_the_named_node() {
        // the #7 regression in graph form: rewriting the program name must
        // leave every flag and argument exactly where it was
        let g = lower("grep -n TODO src/main.rs");
        let (cmd, _) = g.commands().next().unwrap();
        let name_span = g.nodes[cmd].spans()[0];
        let owner = g
            .segments
            .iter()
            .find(|(s, _)| *s == name_span)
            .map(|(_, id)| *id)
            .unwrap();
        let mut edits = HashMap::new();
        edits.insert(owner, "rg".to_string());
        assert_eq!(g.emit_with(&edits), "rg -n TODO src/main.rs");
    }
}
