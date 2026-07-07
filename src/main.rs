use clap::{Parser, Subcommand};
use lictor::{config, content, engine, hook::HookInput, minify, modules, rules};
use serde_json::Value;
use std::io::{IsTerminal, Read};

#[derive(Parser)]
#[command(
    name = "lictor",
    version,
    about = "policy gate + output minifier for coding-agent tool calls",
    after_help = "Run `lictor init` to wire it into Claude Code. \
                  Bare `lictor` with piped stdin acts as `hook`."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Read a hook JSON event on stdin and emit the decision (how Claude Code calls it)
    Hook,
    /// Validate every config file lictor can find; `check -- <cmd...>` runs a command
    /// through the full hook pipeline: prints the decision, asks y/N where the hook
    /// would prompt, executes, and shows the output the model would see (minify/spill
    /// applied). Quote to keep $vars/pipes: `lictor check -- 'cargo test | tail'`
    Check {
        /// Command to gate + run + minify (everything after --)
        #[arg(last = true)]
        command: Vec<String>,
        /// Resolve config as if permission_mode were this value (e.g. auto, bypassPermissions)
        #[arg(long)]
        mode: Option<String>,
    },
    /// Print the settings.json hooks snippet
    Init {
        /// Also write a starter lictor.toml
        #[arg(long)]
        write: bool,
    },
    /// Summarize the audit log (decisions + minify/spill bytes saved)
    Gain,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        // bare `lictor` in a terminal has no hook JSON to read — show usage instead
        // of silently blocking on stdin. When Claude Code invokes it, stdin is a pipe.
        None if std::io::stdin().is_terminal() => {
            use clap::CommandFactory;
            let _ = Cli::command().print_help();
        }
        None | Some(Cmd::Hook) => run_hook(),
        Some(Cmd::Check { command, mode }) if !command.is_empty() => check_command(command, mode),
        Some(Cmd::Check { mode, .. }) => check(mode),
        Some(Cmd::Init { write }) => init(write),
        Some(Cmd::Gain) => gain(),
    }
}

// the y/N permission prompt, mimicking what the agent harness would show.
// No tty means nobody can approve — refuse, so `lictor check -- X` inside a hook
// (where the gate allows it for debugging) can't become an execution bypass.
fn prompt_approval() -> bool {
    use std::io::Write;
    if !std::io::stdin().is_terminal() {
        eprintln!("lictor: stdin is not a tty — nobody to approve; run it from a terminal");
        return false;
    }
    eprint!("lictor: run it? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes")
}

// re-quote an argv word so the reconstructed command round-trips through sh -c
fn quote(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_alphanumeric() || "-_./=:@%+,".contains(c));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

// `check -- <cmd...>`: run one command through the same PreToolUse -> exec ->
// PostToolUse pipeline the hooks use, narrating decisions on stderr. The
// model-visible output (post minify/spill) lands on stdout; exit code propagates.
fn check_command(args: Vec<String>, mode: Option<String>) {
    if args.is_empty() {
        eprintln!("lictor: check -- needs a command, e.g. `lictor check -- git commit -m x`");
        std::process::exit(1);
    }
    let command = if args.len() == 1 {
        args[0].clone()
    } else {
        args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
    };
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));
    let mut config = match config::load(cwd.as_deref(), mode.as_deref()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("lictor: config error: {error}");
            std::process::exit(1);
        }
    };
    // debug runs don't pollute the audit log (and session_id=None skips strikes)
    config.settings.log_file = None;

    let input = HookInput {
        hook_event_name: "PreToolUse".to_string(),
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({ "command": command }),
        tool_response: None,
        error: None,
        cwd: cwd.clone(),
        session_id: None,
        duration_ms: None,
        permission_mode: mode.clone(),
    };
    let mut final_command = command.clone();
    let mut decision = None;
    match engine::evaluate(&input, &config) {
        Some(output) => {
            let out = &output.hook_specific_output;
            decision = out.permission_decision.clone();
            if let Some(d) = &out.permission_decision {
                match &out.permission_decision_reason {
                    Some(reason) => eprintln!("lictor: {d} — {reason}"),
                    None => eprintln!("lictor: {d}"),
                }
            }
            if let Some(updated) = &out.updated_input
                && let Some(rewritten) = updated.get("command").and_then(Value::as_str)
            {
                eprintln!("lictor: rewrite → {rewritten}");
                final_command = rewritten.to_string();
            }
            if let Some(hint) = &out.additional_context {
                eprintln!("lictor: hint — {hint}");
            }
        }
        None => eprintln!("lictor: no opinion — the normal permission flow would decide"),
    }
    match decision.as_deref() {
        Some("deny") => std::process::exit(1),
        Some("allow") => {}
        // ask, or no opinion: mimic the permission prompt
        _ => {
            if !prompt_approval() {
                eprintln!("lictor: not approved — command not run");
                std::process::exit(1);
            }
        }
    }

    eprintln!("lictor: exec: {final_command}");
    let started = std::time::Instant::now();
    let result = std::process::Command::new("sh")
        .arg("-c")
        .arg(&final_command)
        .output();
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            eprintln!("lictor: exec failed: {error}");
            std::process::exit(1);
        }
    };
    let duration_ms = started.elapsed().as_millis() as u64;
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();

    let post = HookInput {
        hook_event_name: "PostToolUse".to_string(),
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({ "command": final_command }),
        tool_response: Some(serde_json::json!({ "stdout": stdout, "stderr": stderr })),
        error: None,
        cwd,
        session_id: None,
        duration_ms: Some(duration_ms),
        permission_mode: mode,
    };
    let mut shown = stdout;
    if let Some(output) = engine::evaluate(&post, &config) {
        let out = &output.hook_specific_output;
        if let Some(updated) = &out.updated_tool_output
            && let Some(minified) = updated.get("stdout").and_then(Value::as_str)
        {
            eprintln!(
                "lictor: output shrunk {} → {} bytes",
                shown.len(),
                minified.len()
            );
            shown = minified.to_string();
        }
        if let Some(hint) = &out.additional_context {
            eprintln!("lictor: hint — {hint}");
        }
    }
    print!("{shown}");
    if !shown.is_empty() && !shown.ends_with('\n') {
        println!();
    }
    eprint!("{stderr}");
    std::process::exit(result.status.code().unwrap_or(1));
}

fn gain() {
    let cwd = std::env::current_dir().ok();
    let cwd = cwd.as_ref().and_then(|p| p.to_str());
    let config = match config::load(cwd, None) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("lictor: {error}");
            std::process::exit(1);
        }
    };
    let Some(path) = config.log_path(cwd) else {
        println!("no `settings.log_file` configured — nothing to summarize");
        return;
    };
    match std::fs::read_to_string(&path) {
        Ok(raw) => print!("{}", lictor::audit::summarize(&raw)),
        Err(_) => println!("no audit log at {} yet", path.display()),
    }
}

fn run_hook() {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return;
    }
    let Ok(input) = serde_json::from_str::<HookInput>(&raw) else {
        return;
    };
    let output = match config::load(input.cwd.as_deref(), input.permission_mode.as_deref()) {
        Ok(config) => engine::evaluate(&input, &config),
        Err(error) if input.hook_event_name == "PreToolUse" => {
            Some(engine::error_output(&input.hook_event_name, &error))
        }
        Err(_) => None,
    };
    if let Some(output) = output {
        println!("{}", serde_json::to_string(&output).expect("serializable"));
    }
}

fn check(mode: Option<String>) {
    let cwd = std::env::current_dir().ok();
    let cwd = cwd.as_ref().and_then(|p| p.to_str());
    let mut found = false;
    for path in config::config_paths(cwd) {
        if !path.exists() {
            continue;
        }
        found = true;
        let loaded = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|raw| toml::from_str::<config::Config>(&raw).map_err(|e| e.to_string()))
            .and_then(|config| {
                rules::compile_bash_rules(&config)?;
                content::compile_edit_rules(&config)?;
                minify::compile_minify_rules(&config)?;
                modules::path_rules::compile(&config)?;
                Ok(config)
            });
        match loaded {
            Ok(config) => println!(
                "ok       {} ({} bash, {} edit, {} path, {} minify rules)",
                path.display(),
                config.bash.len(),
                config.edit.len(),
                config.path.len(),
                config.minify.len()
            ),
            Err(error) => {
                println!("ERROR    {}: {error}", path.display());
                std::process::exit(1);
            }
        }
    }
    if !found {
        println!("no config files found (user config + ancestor lictor.toml chain)");
    }
    match config::load(cwd, mode.as_deref()) {
        Ok(config) => {
            if !config.activated_catalogs.is_empty() {
                println!("catalogs {}", config.activated_catalogs.join(", "));
            }
            if let Some(mode) = &mode {
                println!("mode     {mode}");
            }
            println!(
                "expanded {} bash, {} edit, {} path, {} minify rules total",
                config.bash.len(),
                config.edit.len(),
                config.path.len(),
                config.minify.len()
            );
            check_minify_tools(&config);
        }
        Err(error) => {
            println!("ERROR    merged config: {error}");
            std::process::exit(1);
        }
    }
}

// wrap/pipe name an external minifier (rtk, tokf, squeez, ...); missing ones
// pass rule compilation fine but every matched command fails at run time.
fn check_minify_tools(config: &config::Config) {
    for program in minify::minify_tools(config) {
        if !modules::on_path(program) {
            println!(
                "warn     minify tool `{program}` is not on PATH — matching commands will fail with 'command not found'"
            );
        }
    }
}

fn init(write: bool) {
    if write {
        let target = std::path::Path::new("lictor.toml");
        if target.exists() {
            println!("lictor.toml already exists — not overwriting\n");
        } else {
            match std::fs::write(target, include_str!("default.toml")) {
                Ok(()) => println!("wrote starter policy to lictor.toml\n"),
                Err(error) => {
                    eprintln!("lictor: cannot write lictor.toml: {error}");
                    std::process::exit(1);
                }
            }
        }
    }
    println!(
        r#"Add to .claude/settings.json (or ~/.claude/settings.json):
(PreToolUse must list Write/Edit/MultiEdit/NotebookEdit alongside Bash — jail
and edit-rule checks key off each tool's own file_path, not just Bash commands.)

{{
  "hooks": {{
    "PreToolUse": [
      {{
        "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
        "hooks": [{{ "type": "command", "command": "lictor" }}]
      }}
    ],
    "PostToolUse": [
      {{
        "matcher": "Bash",
        "hooks": [{{ "type": "command", "command": "lictor" }}]
      }}
    ]
  }}
}}

Bootstrap a starter policy: lictor init --write
Validate config files:     lictor check
Audit + savings summary:   lictor gain"#
    );
}
