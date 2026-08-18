use std::collections::HashMap;
use tree_sitter::Node;

const MAX_DEPTH: usize = 5;

// how a command relates to its neighbours in the same pipeline/list — the
// structural context #5's `piped_into` / `with` / `position` predicates key off
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    Pipe,
    And,
    Or,
    Seq,
    Standalone,
}

#[derive(Debug, Clone)]
pub struct Word {
    pub text: Option<String>,
    // raw source of a dynamic word (`"EXIT: $?"`), so deny globs can match syntax
    pub raw: Option<String>,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct Command {
    pub words: Vec<Word>,
    // extracted from a re-parsed inner string (bash -c / eval); spans not valid in original source
    pub synthetic: bool,
    // approval site: flag-normalized variants share their base's site (same privilege),
    // wrapper-stripped variants get their own (sudo git != git)
    pub site: usize,
    // interpreter invocation whose payload we can't parse (python -c, curl | sh, ...)
    pub inline: Option<String>,
    // command writes to a file via redirection; blocks auto-allow and wrap
    pub redirects_output: bool,
    // false for `find -exec` inner commands: their word spans index into the
    // OUTER command's source, so a rewrite here would splice text into the
    // middle of the enclosing `find` line. Security rules still see them
    // (this is distinct from `synthetic`); only rewriting is refused.
    pub rewritable: bool,
    // pipeline/chain id — shared by every command in the same enclosing
    // pipeline/list node; assigned per site (see push_variant), not per variant
    pub group: usize,
    // index of this command's site within `group`
    pub position: usize,
    pub group_len: usize,
    pub connector: Connector,
}

impl Command {
    pub fn display(&self) -> String {
        self.words
            .iter()
            .map(|w| w.text.as_deref().unwrap_or("<dynamic>"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Default)]
pub struct Extraction {
    pub commands: Vec<Command>,
    // the original top-level command text; word start/end index into it (non-synthetic
    // commands only). Lets the jail recover $HOME/... paths that resolve to dynamic words.
    pub source: String,
    pub blocked_reason: Option<String>,
    // structural obfuscation signal (invisible chars, fork bomb); settings.on_obfuscation
    pub obfuscation: Option<String>,
    // a code-execution env var was assigned (LD_PRELOAD, BASH_ENV, ...); on_dangerous_env
    pub dangerous_env: Option<String>,
    // write redirect to a raw disk device (> /dev/sda); unconditional deny
    pub device_write: Option<String>,
    // literal values of `NAME=val` command prefixes (D=/tmp/x cmd) — dropped from
    // `words`, kept here so path-hygiene modules can see the scratch/abs path
    pub assignments: Vec<String>,
    // names of functions defined in the source; path_check must not flag their calls
    pub functions: Vec<String>,
    // The typed graph for this command line, lowered from the SAME tree this
    // walk uses (issue #13, sub-task 4). Two views of one command, not two
    // views of two parses: before this, a consumer that wanted the graph had to
    // re-parse the source, and anything the graph knew that `words` did not was
    // unreachable — which is how a redirect target stayed invisible in #29.
    //
    // Empty for a synthetic (re-parsed) extraction: its spans index the inner
    // string, not `source`.
    pub graph: crate::graph::Graph,
    // monotonic counter minting fresh Command::group ids across the whole
    // extraction, including nested re-parses (bash -c, eval) so ids never collide
    next_group: usize,
}

impl Extraction {
    fn next_group_id(&mut self) -> usize {
        let id = self.next_group;
        self.next_group += 1;
        id
    }
}

fn is_device_write_target(dest: &str) -> bool {
    crate::constants::DEVICE_WRITE_GLOBS
        .iter()
        .any(|d| dest.starts_with(d))
}

fn function_name<'a>(node: Node, source: &'a str) -> Option<&'a str> {
    (0..node.named_child_count())
        .filter_map(|i| node.named_child(i))
        .find(|c| c.kind() == "word")
        .and_then(|c| c.utf8_text(source.as_bytes()).ok())
}

// classic fork bomb `:(){ :|:& };:` and variants: a function whose body pipes
// its own name into itself. Requires the self-pipe, so legit funcs don't trip it.
fn fork_self_pipe(node: Node, source: &str, name: &str) -> bool {
    if node.kind() == "pipeline" {
        let self_calls = (0..node.named_child_count())
            .filter_map(|i| node.named_child(i))
            .filter(|c| command_name_is(*c, source, name))
            .count();
        if self_calls >= 2 {
            return true;
        }
    }
    (0..node.named_child_count())
        .filter_map(|i| node.named_child(i))
        .any(|c| fork_self_pipe(c, source, name))
}

fn command_name_is(node: Node, source: &str, name: &str) -> bool {
    if node.kind() != "command" {
        return false;
    }
    node.named_child(0)
        .filter(|c| c.kind() == "command_name")
        .map(|c| c.named_child(0).unwrap_or(c))
        .and_then(|c| c.utf8_text(source.as_bytes()).ok())
        .is_some_and(|t| basename(t) == name)
}

fn flag_dangerous_env(text: &str, out: &mut Extraction) {
    if out.dangerous_env.is_some() {
        return;
    }
    let Some((name, _)) = text.split_once('=') else {
        return;
    };
    let name = name.trim_start_matches("export ").trim();
    if crate::constants::DANGEROUS_ENV.contains(&name) || name.starts_with("BASH_FUNC") {
        out.dangerous_env = Some(format!("code-execution env var `{name}` assigned"));
    }
}

/// State that is the same for the whole parse of one source string.
///
/// `source`, `synthetic` and `depth` never change once a parse starts, and
/// `groups` is scoped to it. Threading them positionally meant every new piece
/// of parse state was a breaking change to four signatures *and* every
/// recursive call in the chain — `groups` itself cost exactly that when
/// pipeline matching was added.
struct ParseCtx<'a> {
    source: &'a str,
    /// extracted from a re-parsed inner string (bash -c / eval); spans are not
    /// valid in the original source
    synthetic: bool,
    depth: usize,
    /// chain root (a graph node id) -> minted group id, scoped to THIS parse. A
    /// fresh map per parse means nested re-parses cannot collide with the outer
    /// parse's ids.
    groups: HashMap<usize, usize>,
    /// The graph for THIS parse — the structure `group_info` reads.
    ///
    /// Sub-task 4: `group`, `position`, `group_len` and `connector` used to be
    /// re-derived here by climbing the CST, which is the second implementation
    /// of something the graph already models, bugs included. A nested re-parse
    /// (`bash -c …`) gets its own, because its spans index its own string.
    graph: crate::graph::Graph,
    /// every command's place in its chain, computed once per parse
    chains: HashMap<usize, crate::graph::Group>,
}

impl<'a> ParseCtx<'a> {
    fn new(source: &'a str, synthetic: bool, depth: usize) -> Self {
        Self {
            source,
            synthetic,
            depth,
            groups: HashMap::new(),
            graph: crate::graph::Graph::default(),
            chains: HashMap::new(),
        }
    }
}

/// Which flavour of a command site a variant is.
///
/// Grouped because three adjacent bools at a call site is a transposition
/// waiting to happen and the compiler cannot catch it — the same argument #11
/// makes about two adjacent `Option<&str>` in the module layer.
#[derive(Clone, Copy)]
struct Variant {
    /// share the previous variant's approval site (flag-normalized forms) instead
    /// of minting a fresh one (wrapper-stripped forms: `sudo git` != `git`)
    share_site: bool,
    redirects_output: bool,
    rewritable: bool,
    /// a static heredoc body was re-parsed as this shell's script, so the
    /// inline "reads its script from stdin/heredoc" ask is covered by analysis
    stdin_script: bool,
}

pub fn extract(source: &str) -> Extraction {
    let mut out = Extraction::default();
    extract_into(&mut ParseCtx::new(source, false, 0), &mut out);
    out.source = source.to_string();
    out
}

fn extract_into(ctx: &mut ParseCtx, out: &mut Extraction) {
    if ctx.depth > MAX_DEPTH {
        block(out, "shell nesting too deep to analyze");
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("bash grammar");
    let Some(tree) = parser.parse(ctx.source, None) else {
        block(out, "bash parse failed");
        return;
    };
    if tree.root_node().has_error() {
        block(out, "command could not be parsed as valid bash");
    }
    // one parse, one tree: the graph is lowered from the same syntax this walk
    // reads. Every parse gets one — `group_info` reads it — and the top-level
    // one is handed to the extraction so consumers stop re-parsing the source.
    ctx.graph = crate::graph::lower_from(&tree, ctx.source);
    crate::graph::apply_maps(&mut ctx.graph, crate::cmdmap::Maps::shipped());
    ctx.chains = ctx.graph.groups();
    walk(tree.root_node(), ctx, out);
    if ctx.depth == 0 && !ctx.synthetic {
        out.graph = std::mem::take(&mut ctx.graph);
    }
}

fn walk(node: Node, ctx: &mut ParseCtx, out: &mut Extraction) {
    if node.kind() == "command" {
        collect_command(node, ctx, out);
    }
    // `export/declare/local/readonly VAR=/path` parses as a declaration_command,
    // not a plain command, so collect_command never sees it — capture the
    // assigned path the same way a `NAME=val cmd` prefix is captured
    if !ctx.synthetic && node.kind() == "declaration_command" {
        for i in 0..node.named_child_count() {
            if let Some(child) = node.named_child(i)
                && child.kind() == "variable_assignment"
            {
                if let Ok(text) = child.utf8_text(ctx.source.as_bytes()) {
                    flag_dangerous_env(text, out);
                }
                if let Some(value) = child
                    .child_by_field_name("value")
                    .and_then(|v| resolve_text(v, ctx.source))
                {
                    out.assignments.push(value);
                }
            }
        }
    }
    if node.kind() == "function_definition"
        && let Some(name) = function_name(node, ctx.source)
    {
        if fork_self_pipe(node, ctx.source, name) && out.obfuscation.is_none() {
            out.obfuscation = Some("fork bomb: function recursively pipes into itself".to_string());
        }
        out.functions.push(name.to_string());
    }
    // catch bare redirects too (`> /dev/sda` has no command node)
    if node.kind() == "file_redirect" && out.device_write.is_none() {
        let dest = node
            .named_child(node.named_child_count().saturating_sub(1))
            .and_then(|d| d.utf8_text(ctx.source.as_bytes()).ok());
        if let Some(dest) = dest.filter(|d| is_device_write_target(d)) {
            out.device_write = Some(format!("write to raw device `{dest}`"));
        }
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            walk(child, ctx, out);
        }
    }
}

fn collect_command(node: Node, ctx: &mut ParseCtx, out: &mut Extraction) {
    let mut words = Vec::new();
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        match child.kind() {
            // NAME=val prefix (LD_PRELOAD=x cmd) — not a word, but the name matters
            "variable_assignment" => {
                if let Ok(text) = child.utf8_text(ctx.source.as_bytes()) {
                    flag_dangerous_env(text, out);
                }
                if !ctx.synthetic
                    && let Some(value) = child
                        .child_by_field_name("value")
                        .and_then(|v| resolve_text(v, ctx.source))
                {
                    out.assignments.push(value);
                }
            }
            "command_name" => {
                let inner = child.named_child(0).unwrap_or(child);
                words.push(resolve_word(inner, ctx.source));
            }
            _ => words.push(resolve_word(child, ctx.source)),
        }
    }
    if words.is_empty() {
        return;
    }
    if words[0].text.is_none() {
        block(out, "command program name is dynamic");
    }
    let invisible = words.iter().any(|w| {
        w.text
            .as_deref()
            .is_some_and(|t| t.chars().any(is_invisible_char))
    });
    if invisible && out.obfuscation.is_none() {
        out.obfuscation = Some("command contains invisible characters".to_string());
    }
    // env/sudo word-form assignments (env LD_PRELOAD=x ls) survive as plain words
    for word in &words {
        if let Some(text) = word.text.as_deref() {
            flag_dangerous_env(text, out);
        }
    }
    // variants: raw, wrapper-stripped, global-flag-normalized (git -C x commit -> git commit);
    // deny/ask rules check every variant, allow coverage is computed per site
    let stripped = graph_stripped(&ctx.graph, &words);
    let effective = stripped.as_ref().unwrap_or(&words);
    let flag_normalized = graph_flag_normalized(effective);

    derive_nested(&words, ctx.depth, out);
    if let Some(stripped) = &stripped {
        derive_nested(stripped, ctx.depth, out);
    }

    // `bash <<EOF … EOF`: a shell with no positional reads the heredoc as its
    // script — re-parse the body so rules see its commands instead of the
    // blanket inline-script ask (issue #36); the graph-side stdin = "shell"
    // graft carries the matching reference edges
    let stdin_body = (shell_reads_stdin(&words)
        || stripped.as_deref().is_some_and(shell_reads_stdin))
    .then(|| heredoc_stdin_body(node, ctx.source))
    .flatten();
    if let Some(body) = &stdin_body {
        extract_into(&mut ParseCtx::new(body, true, ctx.depth + 1), out);
    }

    let redirects_output = writes_via_redirect(node, ctx.source);
    // computed once per SITE (from the real tree-sitter node), not per variant —
    // otherwise `position = "only"` would never match anything, since a wrapped
    // command (sudo x) always produces >= 2 variants sharing one site
    let group_info = group_info(node, ctx, out);
    // the raw form, then the wrapper-stripped form (its own approval site:
    // `sudo git` is not `git`), then the flag-normalized form (shares the site
    // it normalizes, same privilege)
    let base = Variant {
        share_site: false,
        redirects_output,
        // a command inside $(...)/<(...) produces DATA the shell consumes, not
        // output the model reads — a minify wrap/insert or rewrite there would
        // corrupt the substituted value, so rewriting is refused like find -exec
        rewritable: !in_substitution(node),
        stdin_script: stdin_body.is_some(),
    };
    push_variant(out, words, ctx.synthetic, base, group_info);
    if let Some(stripped) = stripped {
        push_variant(out, stripped, ctx.synthetic, base, group_info);
    }
    if let Some(flag_normalized) = flag_normalized {
        push_variant(
            out,
            flag_normalized,
            ctx.synthetic,
            Variant {
                share_site: true,
                ..base
            },
            group_info,
        );
    }
}

// the shell would read its script from stdin: a shell program word and no
// positional (mirrors detect_inline's trigger — a positional means the heredoc
// feeds the SCRIPT's stdin, not the shell's)
fn shell_reads_stdin(words: &[Word]) -> bool {
    words
        .first()
        .and_then(|w| w.text.as_deref())
        .is_some_and(|p| interpreter_language(basename(p)) == Some("shell"))
        && !words.iter().skip(1).any(|w| match w.text.as_deref() {
            Some(text) => !text.starts_with('-'),
            None => true,
        })
}

// the body of a heredoc attached to this command (`bash <<EOF … EOF`), raw text
fn heredoc_stdin_body(node: Node, source: &str) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "redirected_statement" {
        return None;
    }
    for i in 0..parent.named_child_count() {
        let Some(redirect) = parent.named_child(i) else {
            continue;
        };
        if redirect.kind() != "heredoc_redirect" {
            continue;
        }
        for j in 0..redirect.named_child_count() {
            if let Some(body) = redirect.named_child(j)
                && body.kind() == "heredoc_body"
            {
                return body.utf8_text(source.as_bytes()).ok().map(str::to_string);
            }
        }
    }
    None
}

fn in_substitution(node: Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "command_substitution" | "process_substitution"
        ) {
            return true;
        }
        current = parent.parent();
    }
    false
}

#[derive(Clone, Copy)]
struct GroupInfo {
    group: usize,
    position: usize,
    group_len: usize,
    connector: Connector,
}

// ── structure comes from the graph (#13, sub-task 4) ──
//
// `group`, `position`, `group_len` and `connector` used to be re-derived here by
// climbing the CST for the nearest `pipeline`/`list` ancestor, with a second
// implementation on top of that for the heredoc shape the grammar hides (#12).
// That is the same structure `graph.rs` already models, maintained twice, and
// the duplicate carried two bugs of its own:
//
//   ls; git stash                 a top-level `;` is not a `list`, so both
//                                 commands looked standalone and a `with` rule
//                                 that fires on `&&` and `|` was evadable
//   curl x && grep a b && git c   binary lists nest, so `git c` was position 1
//                                 of 2 rather than 2 of 3
//
// Both are fixed by asking the graph, and ~125 lines of CST climbing went with
// them — including this file's copy of the heredoc re-parenting.
fn group_info(node: Node, ctx: &mut ParseCtx, out: &mut Extraction) -> GroupInfo {
    let standalone = |out: &mut Extraction| GroupInfo {
        group: out.next_group_id(),
        position: 0,
        group_len: 1,
        connector: Connector::Standalone,
    };
    let Some(id) = graph_command_at(&ctx.graph, node) else {
        return standalone(out);
    };
    let Some(chain) = ctx.chains.get(&id) else {
        return standalone(out);
    };
    // the first member is a stable name for the chain within this parse, so two
    // commands in one chain mint one group id
    let Some(&key) = chain.members.first() else {
        return standalone(out);
    };
    let (position, group_len, connector) = (chain.position, chain.len(), chain.connector);
    let group = *ctx.groups.entry(key).or_insert_with(|| out.next_group_id());
    GroupInfo {
        group,
        position,
        group_len,
        connector: match connector {
            Some(crate::graph::Connector::Pipe) => Connector::Pipe,
            Some(crate::graph::Connector::And) => Connector::And,
            Some(crate::graph::Connector::Or) => Connector::Or,
            Some(crate::graph::Connector::Seq) => Connector::Seq,
            None => Connector::Standalone,
        },
    }
}

/// The graph command this CST command was lowered into.
///
/// Both come from the same tree, so the program word's byte offset identifies
/// it. The fallback covers a command whose name is itself a substitution
/// (`$(which git) --version`), where the name owns no bytes of its own and the
/// node's first span is its next word instead.
fn graph_command_at(graph: &crate::graph::Graph, node: Node) -> Option<usize> {
    let (start, end) = (node.start_byte(), node.end_byte());
    let mut fallback = None;
    for (id, command) in graph.commands() {
        // a payload command (`rm` in `sudo rm x`) is a view of another stage,
        // not a stage of its own, and owns no bytes
        if graph.owned_spans(id).is_empty() {
            continue;
        }
        let Some(first) = command.spans.first().map(|s| s.start) else {
            continue;
        };
        if first == start {
            return Some(id);
        }
        if first > start && first < end && fallback.is_none() {
            fallback = Some(id);
        }
    }
    fallback
}

// 5, already down from 7. `out`, `words`, `synthetic`, `variant` and `group`
// are unrelated inputs; there is no further cluster to extract.
#[allow(clippy::too_many_arguments)]
fn push_variant(
    out: &mut Extraction,
    words: Vec<Word>,
    synthetic: bool,
    variant: Variant,
    group: GroupInfo,
) {
    let last_site = out.commands.last().map(|c| c.site);
    let site = match (variant.share_site, last_site) {
        (true, Some(site)) => site,
        (_, Some(site)) => site + 1,
        (_, None) => 0,
    };
    // inline detection per-variant: raw `sudo python -c` -> None, stripped `python -c` -> Some,
    // find-exec'd `sh` -> Some (this is what closes the -exec shell-spawn gap).
    // A re-parsed heredoc script is real coverage, not an unanalyzable stdin read.
    let inline = if variant.stdin_script {
        None
    } else {
        detect_inline(&words)
    };
    out.commands.push(Command {
        words,
        synthetic,
        site,
        inline,
        redirects_output: variant.redirects_output,
        rewritable: variant.rewritable,
        group: group.group,
        position: group.position,
        group_len: group.group_len,
        connector: group.connector,
    });
}

// `cmd > file` / `cmd >> file` / `cmd &> file` write to disk even when the command
// itself is read-only; fd dups (2>&1) and /dev/null don't count
fn writes_via_redirect(node: Node, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    // direct: `cmd > file`
    if parent.kind() == "redirected_statement" && redirect_writes_file(parent, source) {
        return true;
    }
    // chained: `a && cmd > file` — tree-sitter binds the trailing redirect to the
    // enclosing list, so the redirect is the last command's, not a direct parent
    if matches!(parent.kind(), "list" | "pipeline")
        && is_last_command(node, parent)
        && parent
            .parent()
            .is_some_and(|g| g.kind() == "redirected_statement" && redirect_writes_file(g, source))
    {
        return true;
    }
    false
}

fn redirect_writes_file(stmt: Node, source: &str) -> bool {
    for i in 0..stmt.named_child_count() {
        let Some(child) = stmt.named_child(i) else {
            continue;
        };
        if child.kind() != "file_redirect" {
            continue;
        }
        let Ok(text) = child.utf8_text(source.as_bytes()) else {
            return true;
        };
        let operator = text.trim_start_matches(|c: char| c.is_ascii_digit());
        if !operator.starts_with('>') && !operator.starts_with("&>") {
            continue;
        }
        let destination = child.named_child(child.named_child_count().saturating_sub(1));
        let is_harmless = destination.is_some_and(|d| {
            d.kind() == "number"
                || d.utf8_text(source.as_bytes())
                    .is_ok_and(|t| t == "/dev/null")
        });
        if !is_harmless {
            return true;
        }
    }
    false
}

fn is_last_command(node: Node, list: Node) -> bool {
    let mut last = None;
    for i in 0..list.named_child_count() {
        if let Some(child) = list
            .named_child(i)
            .filter(|c| matches!(c.kind(), "command" | "redirected_statement"))
        {
            last = Some(child);
        }
    }
    last.is_some_and(|c| c.id() == node.id())
}

// wrapper-stripped variant from the graph's `Spawns` chain: the innermost local
// payload whose words are a suffix of this command's words. The recipes'
// `kind = "cmd"` args are the source of truth for what peels — no hand-list.
// The suffix check is what keeps embedded payloads (`find . -exec rm {} ;` —
// the `;` belongs to find, not rm) from producing a junk variant, and the
// locality check keeps remote payloads (`ssh host rm x`) out of local rules.
fn graph_stripped(graph: &crate::graph::Graph, words: &[Word]) -> Option<Vec<Word>> {
    let first = words.first()?;
    let (outer, _) = graph
        .commands()
        .find(|(_, c)| c.spans.iter().any(|s| s.start == first.start))?;
    let mut candidates: Vec<crate::graph::NodeId> = Vec::new();
    let mut frontier = vec![outer];
    while let Some(id) = frontier.pop() {
        for edge in &graph.edges {
            if edge.kind != crate::graph::EdgeKind::Spawns || edge.from != id {
                continue;
            }
            let crate::graph::Node::Command(payload) = &graph.nodes[edge.to] else {
                continue;
            };
            // remote payloads run on another machine and must not feed local variants
            if payload.locality.is_remote() || payload.host.is_some() {
                continue;
            }
            candidates.push(edge.to);
            frontier.push(edge.to);
        }
    }
    // innermost valid payload wins — same result as the old iterative peel
    let mut best: Option<usize> = None;
    for id in candidates {
        let Some(start) = graph.nodes[id].spans().first().map(|s| s.start) else {
            continue;
        };
        let Some(idx) = words.iter().position(|w| w.start == start) else {
            continue;
        };
        if idx == 0 {
            continue;
        }
        // a wrapper payload's program IS an outer word; a grafted re-parse
        // (`bash -c 'rm x'`) borrows the holder string's span, so the word
        // there is the whole script, not the program — name mismatch drops it
        let crate::graph::Node::Command(payload) = &graph.nodes[id] else {
            continue;
        };
        if words[idx].text.as_deref() != payload.name.as_deref() {
            continue;
        }
        // the payload's spans are its consumed run (claim_payload_words) — a
        // valid slice point means every later word belongs to the payload
        let owned: Vec<usize> = graph.nodes[id].spans().iter().map(|s| s.start).collect();
        if words[idx + 1..].iter().all(|w| owned.contains(&w.start)) && best.is_none_or(|b| idx > b)
        {
            best = Some(idx);
        }
    }
    best.map(|idx| words[idx..].to_vec())
}

// flag-normalized variant from the recipes: a program whose map declares
// subcommand entries gets its leading flags (+ `takes = true` values) dropped,
// so `git -C x commit` still matches a `git commit` rule. The bare entry's
// flag table is the single source of truth for which flags take values.
// `-c <cfg>` IS normalized so `git -c user.email=x commit` still matches the
// `git commit` ban. Config-injection (`git -c core.pager=!sh log`) is caught by
// the gtfobins catalog on the un-normalized variant, where deny beats the
// normalized variant's git-read allow.
fn graph_flag_normalized(words: &[Word]) -> Option<Vec<Word>> {
    let program = words.first()?.text.as_deref()?;
    let flags = crate::cmdmap::Maps::shipped().prefix_flags(basename(program))?;
    let mut idx = 1;
    while idx < words.len() {
        let Some(text) = words[idx].text.as_deref() else {
            break;
        };
        if !text.starts_with('-') {
            break;
        }
        let takes = !text.contains('=') && flags.get(text).is_some_and(|f| f.takes);
        idx += if takes { 2 } else { 1 };
    }
    if idx == 1 || idx >= words.len() {
        return None;
    }
    let mut normalized = vec![words[0].clone()];
    normalized.extend_from_slice(&words[idx..]);
    Some(normalized)
}

pub fn basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

// returns the basename iff `program` is a bin-dir/`bin`-segment executable path
// (/usr/local/bin/x, ./node_modules/.bin/x, pkg/bin/cli) — NOT a plain local
// script like ./deploy.sh, whose basename wouldn't resolve on PATH
pub fn bin_path_basename<'a>(program: &'a str, bin_dirs: &[String]) -> Option<&'a str> {
    if !program.contains('/') {
        return None;
    }
    let base = basename(program);
    if base.is_empty() {
        return None;
    }
    if program.contains("/bin/") || program.contains("/.bin/") {
        return Some(base);
    }
    if bin_dirs.iter().any(|dir| {
        program
            .strip_prefix(dir.as_str())
            .is_some_and(|r| r.starts_with('/'))
    }) {
        return Some(base);
    }
    None
}

const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "su"];

// re-parses statically-known inner scripts: bash -c "...", eval "...", find -exec
fn derive_nested(words: &[Word], depth: usize, out: &mut Extraction) {
    let Some(program) = words.first().and_then(|w| w.text.as_deref()) else {
        return;
    };
    let program = basename(program);
    if SHELLS.contains(&program) {
        derive_shell_c(words, depth, out);
    }
    if program == "eval" {
        derive_eval(words, depth, out);
    }
    if program == "find" {
        derive_find_exec(words, out);
    }
}

fn derive_shell_c(words: &[Word], depth: usize, out: &mut Extraction) {
    // `-c` is a short option; a long option that merely contains 'c' (--rcfile,
    // --init-file) must NOT be taken for it, or its argument gets extracted as the
    // payload while the real `-c '<script>'` rides free past every rule.
    let flag_pos = words[1..]
        .iter()
        .position(|w| w.text.as_deref().is_some_and(|t| cluster_has(t, &['c'])));
    let Some(flag_pos) = flag_pos else {
        return;
    };
    match words.get(flag_pos + 2).map(|w| w.text.as_deref()) {
        Some(Some(script)) => extract_into(&mut ParseCtx::new(script, true, depth + 1), out),
        Some(None) => block(out, "shell -c receives a dynamic string"),
        None => {}
    }
}

fn derive_eval(words: &[Word], depth: usize, out: &mut Extraction) {
    if words.len() < 2 {
        return;
    }
    let parts: Option<Vec<&str>> = words[1..].iter().map(|w| w.text.as_deref()).collect();
    match parts {
        Some(parts) => extract_into(&mut ParseCtx::new(&parts.join(" "), true, depth + 1), out),
        None => block(out, "eval receives a dynamic string"),
    }
}

fn derive_find_exec(words: &[Word], out: &mut Extraction) {
    let mut idx = 1;
    while idx < words.len() {
        let is_exec = words[idx]
            .text
            .as_deref()
            .is_some_and(|t| matches!(t, "-exec" | "-execdir" | "-ok" | "-okdir"));
        if !is_exec {
            idx += 1;
            continue;
        }
        let start = idx + 1;
        let mut end = start;
        while end < words.len() {
            let terminator = words[end]
                .text
                .as_deref()
                .is_some_and(|t| matches!(t, ";" | "\\;" | "+"));
            if terminator {
                break;
            }
            end += 1;
        }
        if end > start {
            let inner = words[start..end].to_vec();
            derive_nested(&inner, 0, out);
            // not a real tree-sitter command node (it's a word-slice of `find`'s
            // arguments) — no pipeline/list ancestor to derive structure from
            let standalone = GroupInfo {
                group: out.next_group_id(),
                position: 0,
                group_len: 1,
                connector: Connector::Standalone,
            };
            // not synthetic (security rules must still see it), but not
            // rewritable — its word spans index into the outer `find` line
            push_variant(
                out,
                inner,
                false,
                Variant {
                    share_site: false,
                    redirects_output: false,
                    rewritable: false,
                    stdin_script: false,
                },
                standalone,
            );
        }
        idx = end + 1;
    }
}

// zero-width/bidi characters have no place in a legitimate command
fn is_invisible_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

fn decode_ansi_c(raw: &str) -> Option<String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '\\' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&escape) = chars.get(i) else {
            out.push('\\');
            break;
        };
        i += 1;
        match escape {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0C'),
            'v' => out.push('\x0B'),
            'e' | 'E' => out.push('\x1B'),
            '\\' | '\'' | '"' | '?' => out.push(escape),
            'x' => {
                let hex: String = chars[i..]
                    .iter()
                    .take(2)
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                if hex.is_empty() {
                    return None;
                }
                i += hex.len();
                out.push(u8::from_str_radix(&hex, 16).ok()? as char);
            }
            '0'..='7' => {
                let mut octal = String::from(escape);
                while octal.len() < 3 && chars.get(i).is_some_and(|c| ('0'..='7').contains(c)) {
                    octal.push(chars[i]);
                    i += 1;
                }
                out.push(u8::from_str_radix(&octal, 8).ok()? as char);
            }
            'u' | 'U' => {
                let width = if escape == 'u' { 4 } else { 8 };
                let hex: String = chars[i..]
                    .iter()
                    .take(width)
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                if hex.is_empty() {
                    return None;
                }
                i += hex.len();
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            // \cX control chars and anything exotic: give up, treat as dynamic
            'c' => return None,
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Some(out)
}

const BENIGN_FLAGS: &[&str] = &["--version", "-V", "--help", "-h"];

fn interpreter_language(program: &str) -> Option<&'static str> {
    if program.starts_with("python") {
        return Some("python");
    }
    match program {
        "node" | "nodejs" => Some("node"),
        "deno" => Some("deno"),
        "bun" => Some("bun"),
        "ruby" => Some("ruby"),
        "perl" => Some("perl"),
        "php" => Some("php"),
        "lua" | "luajit" => Some("lua"),
        "expect" => Some("expect"),
        "jrunscript" => Some("jrunscript"),
        "bash" | "sh" | "zsh" | "dash" | "ksh" => Some("shell"),
        _ => None,
    }
}

// single-dash cluster like -c / -uc / -ne, but not --long flags
fn cluster_has(text: &str, chars: &[char]) -> bool {
    text.starts_with('-')
        && !text.starts_with("--")
        && text.chars().skip(1).any(|c| chars.contains(&c))
}

fn has_eval_flag(language: &str, words: &[Word]) -> bool {
    if language == "deno" {
        return words
            .get(1)
            .and_then(|w| w.text.as_deref())
            .is_some_and(|t| t == "eval");
    }
    words.iter().skip(1).any(|w| {
        let Some(text) = w.text.as_deref() else {
            return false;
        };
        match language {
            "python" => cluster_has(text, &['c']),
            "ruby" | "lua" | "jrunscript" => cluster_has(text, &['e']),
            "perl" => cluster_has(text, &['e', 'E']),
            "expect" => text == "-c",
            "php" => text == "-r",
            "node" | "bun" => {
                matches!(text, "-e" | "--eval" | "-p" | "--print")
                    || text.starts_with("--eval=")
                    || text.starts_with("--print=")
            }
            _ => false,
        }
    })
}

// python -c / node -e payloads, and interpreters fed via stdin/heredoc (curl | sh),
// are opaque to static analysis -> settings.on_inline_script (default ask).
// shell -c is NOT flagged here: derive_shell_c parses literal payloads.
fn detect_inline(words: &[Word]) -> Option<String> {
    let program = basename(words.first()?.text.as_deref()?);
    let language = interpreter_language(program)?;
    if language != "shell" && has_eval_flag(language, words) {
        return Some(format!("inline {language} script cannot be analyzed"));
    }
    let benign = words
        .iter()
        .skip(1)
        .any(|w| w.text.as_deref().is_some_and(|t| BENIGN_FLAGS.contains(&t)));
    if benign {
        return None;
    }
    let has_positional = words.iter().skip(1).any(|w| match w.text.as_deref() {
        Some(text) => !text.starts_with('-'),
        None => true,
    });
    if !has_positional {
        return Some(format!(
            "{language} would read its script from stdin/heredoc; cannot be analyzed"
        ));
    }
    None
}

fn block(out: &mut Extraction, reason: &str) {
    if out.blocked_reason.is_none() {
        out.blocked_reason = Some(reason.to_string());
    }
}

fn resolve_word(node: Node, source: &str) -> Word {
    let range = node.byte_range();
    let text = resolve_text(node, source);
    let raw = if text.is_none() {
        node.utf8_text(source.as_bytes()).ok().map(str::to_string)
    } else {
        None
    };
    Word {
        text,
        raw,
        start: range.start,
        end: range.end,
    }
}

fn resolve_text(node: Node, source: &str) -> Option<String> {
    let text = node.utf8_text(source.as_bytes()).ok()?;
    match node.kind() {
        "word" | "number" | "string_content" => Some(text.to_string()),
        "raw_string" => Some(text.trim_matches('\'').to_string()),
        // decode $'\x67it' so escape-obfuscated commands hit the normal rules;
        // undecodable escapes make the word dynamic (fail closed)
        "ansi_c_string" => decode_ansi_c(
            text.strip_prefix("$'")
                .and_then(|t| t.strip_suffix('\''))
                .unwrap_or(text),
        ),
        "string" | "translated_string" => {
            let mut parts = Vec::new();
            for i in 0..node.named_child_count() {
                parts.push(resolve_text(node.named_child(i)?, source)?);
            }
            Some(parts.join(""))
        }
        "concatenation" => {
            let mut parts = Vec::new();
            for i in 0..node.named_child_count() {
                parts.push(resolve_text(node.named_child(i)?, source)?);
            }
            Some(parts.join(""))
        }
        _ => None,
    }
}
