use lictor::{config, content, engine, hook::HookInput, minify, rules};
use std::io::{IsTerminal, Read};

fn main() {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        // bare `lictor` in a terminal has no hook JSON to read — show usage instead
        // of silently blocking on stdin. When Claude Code invokes it, stdin is a pipe.
        None if std::io::stdin().is_terminal() => usage(),
        None | Some("hook") => run_hook(),
        Some("check") => check(),
        Some("init") => init(),
        Some("gain") => gain(),
        Some("-V" | "--version" | "version") => println!("lictor {}", env!("CARGO_PKG_VERSION")),
        Some("-h" | "--help" | "help") => usage(),
        Some(other) => {
            eprintln!("lictor: unknown command `{other}` (expected: hook, check, init, gain)");
            std::process::exit(1);
        }
    }
}

fn usage() {
    println!(
        "lictor — policy gate + output minifier for coding-agent tool calls

Usage: lictor <command>

  hook    read a hook JSON event on stdin and emit the decision (how Claude Code calls it)
  check   validate every config file lictor can find
  init    print the settings.json hooks snippet (--write to also scaffold lictor.toml)
  gain    summarize the audit log (decisions + minify/spill bytes saved)

Run `lictor init` to wire it into Claude Code. Bare `lictor` with piped stdin acts as `hook`."
    );
}

fn gain() {
    let cwd = std::env::current_dir().ok();
    let cwd = cwd.as_ref().and_then(|p| p.to_str());
    let config = match config::load(cwd) {
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
    let output = match config::load(input.cwd.as_deref()) {
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

fn check() {
    let cwd = std::env::current_dir().ok();
    let cwd = cwd.as_ref().and_then(|p| p.to_str());
    for path in config::config_paths(cwd) {
        if !path.exists() {
            println!("absent   {}", path.display());
            continue;
        }
        let loaded = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|raw| toml::from_str::<config::Config>(&raw).map_err(|e| e.to_string()))
            .and_then(|config| {
                rules::compile_bash_rules(&config)?;
                content::compile_edit_rules(&config)?;
                minify::compile_minify_rules(&config)?;
                Ok(config)
            });
        match loaded {
            Ok(config) => println!(
                "ok       {} ({} bash, {} edit, {} minify rules)",
                path.display(),
                config.bash.len(),
                config.edit.len(),
                config.minify.len()
            ),
            Err(error) => {
                println!("ERROR    {}: {error}", path.display());
                std::process::exit(1);
            }
        }
    }
    match config::load(cwd) {
        Ok(config) => {
            if !config.activated_catalogs.is_empty() {
                println!("catalogs {}", config.activated_catalogs.join(", "));
            }
            println!(
                "expanded {} bash, {} edit, {} minify rules total",
                config.bash.len(),
                config.edit.len(),
                config.minify.len()
            );
        }
        Err(error) => {
            println!("ERROR    merged config: {error}");
            std::process::exit(1);
        }
    }
}

fn init() {
    if std::env::args().nth(2).as_deref() == Some("--write") {
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
