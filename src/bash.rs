use tree_sitter::Node;

const MAX_DEPTH: usize = 5;

#[derive(Debug, Clone)]
pub struct Word {
    pub text: Option<String>,
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
}

fn is_device_write_target(dest: &str) -> bool {
    crate::constants::DEVICE_WRITE_GLOBS
        .iter()
        .any(|d| dest.starts_with(d))
}

// classic fork bomb `:(){ :|:& };:` and variants: a function whose body pipes
// its own name into itself. Requires the self-pipe, so legit funcs don't trip it.
fn is_fork_bomb(node: Node, source: &str) -> bool {
    let name = (0..node.named_child_count())
        .filter_map(|i| node.named_child(i))
        .find(|c| c.kind() == "word")
        .and_then(|c| c.utf8_text(source.as_bytes()).ok());
    let Some(name) = name else {
        return false;
    };
    fork_self_pipe(node, source, name)
}

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

pub fn extract(source: &str) -> Extraction {
    let mut out = Extraction::default();
    extract_into(source, false, 0, &mut out);
    out
}

fn extract_into(source: &str, synthetic: bool, depth: usize, out: &mut Extraction) {
    if depth > MAX_DEPTH {
        block(out, "shell nesting too deep to analyze");
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("bash grammar");
    let Some(tree) = parser.parse(source, None) else {
        block(out, "bash parse failed");
        return;
    };
    if tree.root_node().has_error() {
        block(out, "command could not be parsed as valid bash");
    }
    walk(tree.root_node(), source, synthetic, depth, out);
}

fn walk(node: Node, source: &str, synthetic: bool, depth: usize, out: &mut Extraction) {
    if node.kind() == "command" {
        collect_command(node, source, synthetic, depth, out);
    }
    if node.kind() == "function_definition"
        && is_fork_bomb(node, source)
        && out.obfuscation.is_none()
    {
        out.obfuscation = Some("fork bomb: function recursively pipes into itself".to_string());
    }
    // catch bare redirects too (`> /dev/sda` has no command node)
    if node.kind() == "file_redirect" && out.device_write.is_none() {
        let dest = node
            .named_child(node.named_child_count().saturating_sub(1))
            .and_then(|d| d.utf8_text(source.as_bytes()).ok());
        if let Some(dest) = dest.filter(|d| is_device_write_target(d)) {
            out.device_write = Some(format!("write to raw device `{dest}`"));
        }
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            walk(child, source, synthetic, depth, out);
        }
    }
}

fn collect_command(node: Node, source: &str, synthetic: bool, depth: usize, out: &mut Extraction) {
    let mut words = Vec::new();
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        match child.kind() {
            // NAME=val prefix (LD_PRELOAD=x cmd) — not a word, but the name matters
            "variable_assignment" => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    flag_dangerous_env(text, out);
                }
                if !synthetic
                    && let Some(value) = child
                        .child_by_field_name("value")
                        .and_then(|v| resolve_text(v, source))
                {
                    out.assignments.push(value);
                }
            }
            "command_name" => {
                let inner = child.named_child(0).unwrap_or(child);
                words.push(resolve_word(inner, source));
            }
            _ => words.push(resolve_word(child, source)),
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
    let stripped = strip_wrappers(&words);
    let effective = stripped.as_ref().unwrap_or(&words);
    let flag_normalized = strip_global_flags(effective);

    derive_nested(&words, depth, out);
    if let Some(stripped) = &stripped {
        derive_nested(stripped, depth, out);
    }

    let redirects_output = writes_via_redirect(node, source);
    push_variant(out, words, synthetic, false, redirects_output);
    if let Some(stripped) = stripped {
        push_variant(out, stripped, synthetic, false, redirects_output);
    }
    if let Some(flag_normalized) = flag_normalized {
        push_variant(out, flag_normalized, synthetic, true, redirects_output);
    }
}

fn push_variant(
    out: &mut Extraction,
    words: Vec<Word>,
    synthetic: bool,
    share_site: bool,
    redirects_output: bool,
) {
    let last_site = out.commands.last().map(|c| c.site);
    let site = match (share_site, last_site) {
        (true, Some(site)) => site,
        (_, Some(site)) => site + 1,
        (_, None) => 0,
    };
    // inline detection per-variant: raw `sudo python -c` -> None, stripped `python -c` -> Some,
    // find-exec'd `sh` -> Some (this is what closes the -exec shell-spawn gap)
    let inline = detect_inline(&words);
    out.commands.push(Command {
        words,
        synthetic,
        site,
        inline,
        redirects_output,
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

struct Wrapper {
    name: &'static str,
    flags_with_arg: &'static [&'static str],
    skip_positional: usize,
    skip_env_assigns: bool,
}

const WRAPPERS: &[Wrapper] = &[
    Wrapper {
        name: "env",
        flags_with_arg: &["-u", "-C", "-S"],
        skip_positional: 0,
        skip_env_assigns: true,
    },
    Wrapper {
        name: "sudo",
        flags_with_arg: &["-u", "-g", "-p", "-h", "-C", "-D", "-R", "-T", "-U"],
        skip_positional: 0,
        skip_env_assigns: true,
    },
    Wrapper {
        name: "doas",
        flags_with_arg: &["-u"],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "command",
        flags_with_arg: &[],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "builtin",
        flags_with_arg: &[],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "exec",
        flags_with_arg: &["-a"],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "nohup",
        flags_with_arg: &[],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "setsid",
        flags_with_arg: &[],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "nice",
        flags_with_arg: &["-n"],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "ionice",
        flags_with_arg: &["-c", "-n", "-p"],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "stdbuf",
        flags_with_arg: &["-i", "-o", "-e"],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "timeout",
        flags_with_arg: &["-k", "-s", "--signal", "--kill-after"],
        skip_positional: 1,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "flock",
        flags_with_arg: &["-w", "--timeout", "-E", "--conflict-exit-code"],
        skip_positional: 1,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "taskset",
        flags_with_arg: &["-c"],
        skip_positional: 1,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "cpulimit",
        flags_with_arg: &["-l", "-p", "-e"],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "time",
        flags_with_arg: &[],
        skip_positional: 0,
        skip_env_assigns: false,
    },
    Wrapper {
        name: "xargs",
        flags_with_arg: &[
            "-a", "-d", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "-P", "-s", "-S",
        ],
        skip_positional: 0,
        skip_env_assigns: false,
    },
];

// peels wrapper programs (sudo env xargs ...) so rules see the real command;
// returns None when nothing was stripped
fn strip_wrappers(words: &[Word]) -> Option<Vec<Word>> {
    let mut current = words.to_vec();
    let mut stripped_any = false;
    loop {
        let Some(program) = current.first().and_then(|w| w.text.clone()) else {
            break;
        };
        let Some(wrapper) = WRAPPERS.iter().find(|w| w.name == basename(&program)) else {
            break;
        };
        let mut idx = 1;
        while idx < current.len() {
            let Some(text) = current[idx].text.as_deref() else {
                break;
            };
            if wrapper.skip_env_assigns && is_env_assign(text) {
                idx += 1;
            } else if text.starts_with('-') && text != "-" && text != "--" {
                let takes_arg = wrapper.flags_with_arg.contains(&text);
                idx += if takes_arg { 2 } else { 1 };
            } else if text == "--" {
                idx += 1;
                break;
            } else {
                break;
            }
        }
        idx += wrapper.skip_positional;
        if idx >= current.len() {
            return None;
        }
        current = current[idx..].to_vec();
        stripped_any = true;
    }
    stripped_any.then_some(current)
}

const GLOBAL_FLAGS: &[(&str, &[&str])] = &[
    // `-c <cfg>` IS normalized so `git -c user.email=x commit` still matches the
    // `git commit` ban. Config-injection (`git -c core.pager=!sh log`) is caught by
    // the gtfobins catalog on the un-normalized variant, where deny beats the
    // normalized variant's git-read allow.
    (
        "git",
        &[
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--exec-path",
        ],
    ),
    (
        "kubectl",
        &[
            "-n",
            "--namespace",
            "--context",
            "--kubeconfig",
            "--cluster",
            "--user",
            "-s",
            "--server",
        ],
    ),
];

// git -C /x commit -> git commit, so subcommand rules can't be evaded via global flags
fn strip_global_flags(words: &[Word]) -> Option<Vec<Word>> {
    let program = words.first()?.text.as_deref()?;
    let (_, flags_with_arg) = GLOBAL_FLAGS
        .iter()
        .find(|(name, _)| *name == basename(program))?;
    let mut idx = 1;
    while idx < words.len() {
        let Some(text) = words[idx].text.as_deref() else {
            break;
        };
        if !text.starts_with('-') {
            break;
        }
        let takes_arg = !text.contains('=') && flags_with_arg.contains(&text);
        idx += if takes_arg { 2 } else { 1 };
    }
    if idx == 1 || idx >= words.len() {
        return None;
    }
    let mut normalized = vec![words[0].clone()];
    normalized.extend_from_slice(&words[idx..]);
    Some(normalized)
}

fn is_env_assign(text: &str) -> bool {
    match text.split_once('=') {
        Some((name, _)) => {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
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
        Some(Some(script)) => extract_into(script, true, depth + 1, out),
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
        Some(parts) => extract_into(&parts.join(" "), true, depth + 1, out),
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
            push_variant(out, inner, false, false, false);
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
    Word {
        text: resolve_text(node, source),
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
