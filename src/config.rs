use crate::catalogs::{builtin_catalogs, bundle_members, merge_catalog};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Ask,
    Rewrite,
    Warn,
    // audit-only: record the match in the log file, decide nothing
    Log,
    // true no-op: contributes no decision, hint, edit, or log entry, and
    // overrides any ask/warn/log/allow another rule gives the same match —
    // Claude Code's own permission rules decide instead. An explicit `deny`
    // elsewhere still wins.
    Skip,
}

// dynamic built-in modules (src/modules/): context-aware suggestions/rewrites;
// each module accepts a subset, validated by modules::validate at load time
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleSetting {
    Off,
    Warn,
    Rewrite,
    Ask,
    Deny,
    Allow,
}

#[derive(Debug, Deserialize)]
pub struct BashRule {
    #[serde(rename = "match")]
    pub pattern: String,
    // extra globs that must match some argument ANYWHERE after the program (flag bans)
    #[serde(default)]
    pub contains: Vec<String>,
    // strict allowlist: EVERY argument after the pattern must match one of these globs
    #[serde(default)]
    pub only: Vec<String>,
    pub action: Action,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub rewrite: Option<String>,
    #[serde(default)]
    pub hint: Option<String>,
    // deny-then-allow: after this many denies of this rule within
    // retry_window seconds, the next resubmission is auto-allowed instead.
    // Both fields must be set to activate; only meaningful on action = deny.
    #[serde(default)]
    pub retry_count: Option<u32>,
    #[serde(default)]
    pub retry_window: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct EditRule {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub removed_pattern: Option<String>,
    #[serde(default)]
    pub required_pattern: Option<String>,
    pub action: Action,
    #[serde(default)]
    pub hint: Option<String>,
    #[serde(default)]
    pub retry_count: Option<u32>,
    #[serde(default)]
    pub retry_window: Option<u64>,
}

// user-listed filesystem paths -> action + hint, matched against paths the
// agent touches (Bash args + Write/Edit file_path). The opinion (which dirs,
// what message) lives here in config, not in Rust — e.g. `/tmp/** -> deny,
// "use .claude/scratch/ or kv"`. First matching rule wins.
#[derive(Debug, Deserialize)]
pub struct PathRule {
    #[serde(rename = "match")]
    pub globs: Vec<String>,
    pub action: Action,
    #[serde(default)]
    pub hint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MinifyRule {
    #[serde(rename = "match")]
    pub pattern: String,
    #[serde(default)]
    pub wrap: Option<String>,
    #[serde(default)]
    pub pipe: Option<String>,
    #[serde(default)]
    pub max_lines: Option<usize>,
    // skip outputs already shorter than this many lines
    #[serde(default)]
    pub min_lines: usize,
    // lines matching these regexes survive truncation; None = default error/warn/fail set
    #[serde(default)]
    pub preserve: Option<Vec<String>>,
    #[serde(default)]
    pub allow: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub on_unparseable: Option<Action>,
    #[serde(default)]
    pub on_inline_script: Option<Action>,
    // structural obfuscation (invisible chars, undecodable escapes, fork bomb); default deny
    #[serde(default)]
    pub on_obfuscation: Option<Action>,
    // a command prefixed by a code-injecting env var (LD_PRELOAD, LESSOPEN, ...); default deny
    #[serde(default)]
    pub on_dangerous_env: Option<Action>,
    // content emitters (cat/echo/printf/tee) writing a file via redirection — the
    // agent should author files with the Write/Edit tool. Default off.
    #[serde(default)]
    pub on_shell_write: Option<Action>,
    // program words that are bin paths (/usr/local/bin/x, ./node_modules/.bin/x):
    // rewrite|warn|ask|deny. Default off. Trims tokens; basename must resolve on PATH.
    #[serde(default)]
    pub strip_program_paths: Option<Action>,
    #[serde(default)]
    pub bin_dirs: Option<Vec<String>>,
    // catalog bundles to activate at built-in defaults: recommended | read-only | paranoid
    #[serde(default)]
    pub catalogs: Vec<String>,
    // audit JSONL destination; logging is off when unset
    #[serde(default)]
    pub log_file: Option<String>,
    // spill: when Bash output exceeds this many lines, store it in the kv CLI
    // and show only the tail plus retrieval instructions; off when unset
    #[serde(default)]
    pub spill_lines: Option<usize>,
    #[serde(default)]
    pub spill_keep: Option<usize>,
    #[serde(default)]
    pub spill_command: Option<String>,
    #[serde(default)]
    pub spill_expires: Option<String>,
    // spill also when the command ran at least this many seconds (expensive to
    // re-run: test suites, builds), even below spill_lines
    #[serde(default)]
    pub spill_seconds: Option<u64>,
    // consecutive lictor denies before shell lockdown (every Bash call -> ask);
    // a successfully executed command resets the counter. Off when unset.
    #[serde(default)]
    pub strikes: Option<u32>,
    #[serde(default)]
    pub strikes_window: Option<u64>,
    // literal paths outside the project (and jail_allow roots): warn|ask|deny
    #[serde(default)]
    pub jail: Option<Action>,
    #[serde(default)]
    pub jail_allow: Option<Vec<String>>,
}

// membership entry with argument constraints, e.g. secret files read by pagers
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CatalogRule {
    #[serde(rename = "match", default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub contains: Vec<String>,
    #[serde(default)]
    pub only: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Catalog {
    #[serde(rename = "match", default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub rules: Vec<CatalogRule>,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub rewrite: Option<String>,
    #[serde(default)]
    pub hint: Option<String>,
    #[serde(default)]
    pub wrap: Option<String>,
    #[serde(default)]
    pub pipe: Option<String>,
    #[serde(default)]
    pub max_lines: Option<usize>,
    #[serde(default)]
    pub min_lines: Option<usize>,
    #[serde(default)]
    pub preserve: Option<Vec<String>>,
}

// toolchain activation: when a managed program fails and its marker file is in
// cwd, tell the agent to activate (proto/nvm/mise) and retry
#[derive(Debug, Clone, Deserialize)]
pub struct ActivateRule {
    pub file: String,
    pub run: String,
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub bash: Vec<BashRule>,
    #[serde(default)]
    pub edit: Vec<EditRule>,
    #[serde(default)]
    pub path: Vec<PathRule>,
    #[serde(default)]
    pub minify: Vec<MinifyRule>,
    #[serde(default)]
    pub activate: Vec<ActivateRule>,
    #[serde(default)]
    pub catalog: HashMap<String, Catalog>,
    #[serde(default)]
    pub modules: HashMap<String, ModuleSetting>,
    #[serde(default)]
    pub settings: Settings,
    // per-permission-mode overlay, applied like one more config layer on top of
    // everything else when its key matches the hook's `permission_mode`
    // ("default" | "plan" | "acceptEdits" | "auto" | "dontAsk" | "bypassPermissions")
    #[serde(default)]
    pub modes: HashMap<String, Config>,
    #[serde(skip)]
    pub activated_catalogs: Vec<String>,
}

impl Config {
    pub fn merge(mut self, other: Config) -> Config {
        self.bash.extend(other.bash);
        self.edit.extend(other.edit);
        self.path.extend(other.path);
        self.minify.extend(other.minify);
        self.activate.extend(other.activate);
        // same-name catalog block: later file (project) replaces earlier (user)
        self.catalog.extend(other.catalog);
        self.modules.extend(other.modules);
        // same-name mode block: later file replaces earlier, same as catalogs
        self.modes.extend(other.modes);
        self.settings.catalogs.extend(other.settings.catalogs);
        if other.settings.on_unparseable.is_some() {
            self.settings.on_unparseable = other.settings.on_unparseable;
        }
        if other.settings.on_inline_script.is_some() {
            self.settings.on_inline_script = other.settings.on_inline_script;
        }
        if other.settings.on_obfuscation.is_some() {
            self.settings.on_obfuscation = other.settings.on_obfuscation;
        }
        if other.settings.on_dangerous_env.is_some() {
            self.settings.on_dangerous_env = other.settings.on_dangerous_env;
        }
        if other.settings.on_shell_write.is_some() {
            self.settings.on_shell_write = other.settings.on_shell_write;
        }
        if other.settings.strip_program_paths.is_some() {
            self.settings.strip_program_paths = other.settings.strip_program_paths;
        }
        if other.settings.bin_dirs.is_some() {
            self.settings.bin_dirs = other.settings.bin_dirs;
        }
        if other.settings.log_file.is_some() {
            self.settings.log_file = other.settings.log_file;
        }
        if other.settings.spill_lines.is_some() {
            self.settings.spill_lines = other.settings.spill_lines;
        }
        if other.settings.spill_keep.is_some() {
            self.settings.spill_keep = other.settings.spill_keep;
        }
        if other.settings.spill_command.is_some() {
            self.settings.spill_command = other.settings.spill_command;
        }
        if other.settings.spill_expires.is_some() {
            self.settings.spill_expires = other.settings.spill_expires;
        }
        if other.settings.spill_seconds.is_some() {
            self.settings.spill_seconds = other.settings.spill_seconds;
        }
        if other.settings.strikes.is_some() {
            self.settings.strikes = other.settings.strikes;
        }
        if other.settings.strikes_window.is_some() {
            self.settings.strikes_window = other.settings.strikes_window;
        }
        if other.settings.jail.is_some() {
            self.settings.jail = other.settings.jail;
        }
        if other.settings.jail_allow.is_some() {
            self.settings.jail_allow = other.settings.jail_allow;
        }
        self
    }

    pub fn spill_lines(&self) -> Option<usize> {
        self.settings.spill_lines
    }

    pub fn spill_keep(&self) -> usize {
        self.settings.spill_keep.unwrap_or(30)
    }

    pub fn spill_command(&self) -> &str {
        self.settings.spill_command.as_deref().unwrap_or("kv")
    }

    pub fn spill_expires(&self) -> Option<&str> {
        self.settings.spill_expires.as_deref()
    }

    pub fn spill_seconds(&self) -> Option<u64> {
        self.settings.spill_seconds
    }

    pub fn strikes(&self) -> Option<u32> {
        self.settings.strikes
    }

    pub fn strikes_window(&self) -> u64 {
        self.settings.strikes_window.unwrap_or(600)
    }

    // resolves the [modes.<mode>] overlay (if declared) as one more merge pass,
    // so scalar settings override and rule lists append, same as file layering
    pub fn apply_mode(mut self, mode: Option<&str>) -> Config {
        if let Some(overlay) = mode.and_then(|m| self.modes.remove(m)) {
            self = self.merge(overlay);
        }
        self
    }

    pub fn jail(&self) -> Option<Action> {
        self.settings.jail
    }

    pub fn jail_allow(&self) -> &[String] {
        self.settings.jail_allow.as_deref().unwrap_or(&[])
    }

    // relative paths resolve against the hook's cwd, not the lictor process cwd
    pub fn log_path(&self, cwd: Option<&str>) -> Option<std::path::PathBuf> {
        let raw = self.settings.log_file.as_deref()?;
        let expanded = match raw.strip_prefix("~/") {
            Some(rest) => format!("{}/{rest}", std::env::var("HOME").ok()?),
            None => raw.to_string(),
        };
        let path = std::path::PathBuf::from(expanded);
        match (path.is_relative(), cwd) {
            (true, Some(cwd)) => Some(std::path::Path::new(cwd).join(path)),
            _ => Some(path),
        }
    }

    pub fn on_unparseable(&self) -> Action {
        self.settings.on_unparseable.unwrap_or(Action::Ask)
    }

    pub fn on_inline_script(&self) -> Action {
        self.settings.on_inline_script.unwrap_or(Action::Ask)
    }

    pub fn on_obfuscation(&self) -> Action {
        self.settings.on_obfuscation.unwrap_or(Action::Deny)
    }

    pub fn on_dangerous_env(&self) -> Action {
        self.settings.on_dangerous_env.unwrap_or(Action::Deny)
    }

    // off by default: shell file-authoring is a workflow nudge, not a security signal
    pub fn on_shell_write(&self) -> Option<Action> {
        self.settings.on_shell_write
    }

    pub fn strip_program_paths(&self) -> Option<Action> {
        self.settings.strip_program_paths
    }

    pub fn bin_dirs(&self) -> Vec<String> {
        if let Some(dirs) = &self.settings.bin_dirs {
            return dirs.clone();
        }
        let home = std::env::var("HOME").unwrap_or_default();
        crate::constants::DEFAULT_BIN_DIRS
            .iter()
            .map(|d| d.replace('~', &home))
            .collect()
    }

    // expands bundles + [catalog.*] blocks into plain bash/minify rules;
    // must run once after all files merged, before compiling rules
    pub fn finalize(&mut self) -> Result<(), String> {
        for (name, setting) in &self.modules {
            crate::modules::validate(name, *setting)?;
        }
        let builtins = builtin_catalogs()?;
        let mut active: BTreeMap<String, Catalog> = BTreeMap::new();
        for bundle in self.settings.catalogs.clone() {
            let members =
                bundle_members(&bundle).ok_or(format!("unknown catalog bundle '{bundle}'"))?;
            for (name, action_override) in members {
                let mut catalog = builtins.get(name).cloned().ok_or(format!(
                    "bundle '{bundle}' references unknown catalog '{name}'"
                ))?;
                if action_override.is_some() {
                    catalog.action = action_override;
                }
                active.insert(name.to_string(), catalog);
            }
        }
        for (name, user_catalog) in std::mem::take(&mut self.catalog) {
            let base = active
                .get(&name)
                .cloned()
                .or_else(|| builtins.get(&name).cloned());
            active.insert(name.clone(), merge_catalog(base, user_catalog));
        }
        for (name, catalog) in active {
            self.expand_catalog(&name, &catalog)?;
            self.activated_catalogs.push(name);
        }
        Ok(())
    }

    fn expand_catalog(&mut self, name: &str, catalog: &Catalog) -> Result<(), String> {
        // the structural detector, not a pattern list; action routes to the setting
        if name == "obfuscation" {
            if let Some(action) = catalog.action {
                self.settings.on_obfuscation = Some(action);
            }
            return Ok(());
        }
        let mut patterns: Vec<String> = catalog.patterns.clone();
        patterns.extend(catalog.add.iter().cloned());
        patterns.retain(|p| !catalog.remove.contains(p));
        let has_minify =
            catalog.wrap.is_some() || catalog.pipe.is_some() || catalog.max_lines.is_some();
        if catalog.action.is_none() && !has_minify {
            return Err(format!(
                "catalog '{name}' needs an action or minify fields (wrap/pipe/max_lines)"
            ));
        }
        if patterns.is_empty() && catalog.rules.is_empty() {
            return Err(format!(
                "catalog '{name}' is not a built-in and lists no match patterns"
            ));
        }
        let mut members: Vec<CatalogRule> = patterns
            .iter()
            .map(|p| CatalogRule {
                patterns: vec![p.clone()],
                ..Default::default()
            })
            .collect();
        members.extend(catalog.rules.iter().cloned());
        for member in &members {
            for pattern in &member.patterns {
                if let Some(action) = catalog.action {
                    self.bash.push(BashRule {
                        pattern: pattern.clone(),
                        contains: member.contains.clone(),
                        only: member.only.clone(),
                        action,
                        reason: catalog.reason.clone(),
                        rewrite: catalog.rewrite.clone(),
                        hint: catalog.hint.clone(),
                        retry_count: None,
                        retry_window: None,
                    });
                }
                if has_minify {
                    self.minify.push(MinifyRule {
                        pattern: pattern.clone(),
                        wrap: catalog.wrap.clone(),
                        pipe: catalog.pipe.clone(),
                        max_lines: catalog.max_lines,
                        min_lines: catalog.min_lines.unwrap_or(0),
                        preserve: catalog.preserve.clone(),
                        allow: catalog.action == Some(Action::Allow),
                    });
                }
            }
        }
        Ok(())
    }
}

pub fn config_paths(cwd: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let base = std::env::var("XDG_CONFIG_HOME").unwrap_or(format!("{home}/.config"));
        paths.push(Path::new(&base).join("lictor/config.toml"));
    }
    // ancestor chain, root-most first: a monorepo root config applies in every
    // package dir, and deeper files win per key (rule lists concatenate)
    if let Some(cwd) = cwd {
        let mut dirs: Vec<&Path> = Path::new(cwd).ancestors().collect();
        dirs.reverse();
        for dir in dirs {
            paths.push(dir.join(".claude/lictor.toml"));
            paths.push(dir.join("lictor.toml"));
        }
    }
    paths
}

pub fn load(cwd: Option<&str>, mode: Option<&str>) -> Result<Config, String> {
    let mut config = Config::default();
    for path in config_paths(cwd) {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let parsed: Config =
            toml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        config = config.merge(parsed);
    }
    config = config.apply_mode(mode);
    config.finalize()?;
    Ok(config)
}
