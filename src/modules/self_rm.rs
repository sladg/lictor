use super::state_dir;
use crate::bash::{Command, Extraction, basename};
use crate::config::{Config, ModuleSetting};
use std::path::PathBuf;

// self-cleanup: paths this session created (via Write, or bash `mkdir`/`touch`)
// are fingerprinted so a later `rm`/`git rm` that targets ONLY those paths skips
// the mutating-catalog ask — the agent doesn't need permission to delete its own
// scratch. A target counts as "ours" if it matches a tracked path exactly or
// sits inside a tracked directory.
//
// ponytail: only cancels the ask when no OTHER module already wants one for this
// same command (checked by the caller via `plan.asks`); a gate-level ask from
// jail/obfuscation/etc. landing on the very same `rm` is a rare enough overlap
// to accept rather than re-derive here.

const MAX_ENTRIES: usize = 256;

fn setting(config: &Config) -> ModuleSetting {
    *config.modules.get("self-rm").unwrap_or(&ModuleSetting::Off)
}

fn state_file(config: &Config, cwd: Option<&str>, session: &str) -> Option<PathBuf> {
    let slug: String = session
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    Some(state_dir(config, cwd)?.join(format!("created-{slug}.json")))
}

fn load(path: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn remember(config: &Config, cwd: &str, session: &str, path: String) {
    let Some(state) = state_file(config, Some(cwd), session) else {
        return;
    };
    let mut list = load(&state);
    if list.contains(&path) {
        return;
    }
    list.push(path);
    if list.len() > MAX_ENTRIES {
        let excess = list.len() - MAX_ENTRIES;
        list.drain(..excess);
    }
    if let Some(parent) = state.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(raw) = serde_json::to_string(&list) {
        let _ = std::fs::write(&state, raw);
    }
}

// a Write to a path that doesn't exist yet is a genuine creation, not an
// overwrite of something already there
pub fn record_write(config: &Config, cwd: Option<&str>, session: Option<&str>, path: &str) {
    if setting(config) == ModuleSetting::Off {
        return;
    }
    let (Some(cwd), Some(session)) = (cwd, session) else {
        return;
    };
    let resolved = super::recreate::resolve(path, cwd);
    if std::fs::metadata(&resolved).is_ok() {
        return;
    }
    remember(config, cwd, session, resolved);
}

// literal path args of `mkdir [flags]` / `touch [flags]`; a dynamic word means
// abstain rather than guess, same rule as recreate::deletion_targets
fn creation_targets(command: &Command) -> Vec<String> {
    let words: Vec<&str> = command
        .words
        .iter()
        .filter_map(|w| w.text.as_deref())
        .collect();
    if words.len() != command.words.len() {
        return Vec::new();
    }
    let args = match words.split_first() {
        Some((&first, rest)) if matches!(basename(first), "mkdir" | "touch") => rest,
        _ => return Vec::new(),
    };
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .map(|a| a.to_string())
        .collect()
}

pub fn record_bash(
    extraction: &Extraction,
    config: &Config,
    cwd: Option<&str>,
    session: Option<&str>,
) {
    if setting(config) == ModuleSetting::Off {
        return;
    }
    let (Some(cwd), Some(session)) = (cwd, session) else {
        return;
    };
    for command in &extraction.commands {
        for target in creation_targets(command) {
            let resolved = super::recreate::resolve(&target, cwd);
            if std::fs::metadata(&resolved).is_ok() {
                continue;
            }
            remember(config, cwd, session, resolved);
        }
    }
}

fn owned(created: &[String], target: &str) -> bool {
    created
        .iter()
        .any(|c| target == c || target.starts_with(&format!("{c}/")))
}

// Some((Allow, message)) to auto-approve, Some((Warn, message)) to just hint;
// None when the module is off, nothing is tracked, or the chain touches
// anything besides a plain `rm`/`git rm` of tracked paths.
pub fn check(
    extraction: &Extraction,
    config: &Config,
    cwd: Option<&str>,
    session: Option<&str>,
) -> Option<(ModuleSetting, String)> {
    let setting = setting(config);
    if setting == ModuleSetting::Off {
        return None;
    }
    let (Some(cwd), Some(session)) = (cwd, session) else {
        return None;
    };
    let state = state_file(config, Some(cwd), session)?;
    let created = load(&state);
    if created.is_empty() || extraction.commands.is_empty() {
        return None;
    }
    for command in &extraction.commands {
        let targets = super::recreate::deletion_targets(command);
        if targets.is_empty() {
            return None;
        }
        for target in &targets {
            let resolved = super::recreate::resolve(target, cwd);
            if !owned(&created, &resolved) {
                return None;
            }
        }
    }
    Some((
        setting,
        "lictor: rm targets only paths created earlier this session".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    fn config(dir: &std::path::Path, setting: &str) -> Config {
        toml::from_str(&format!(
            "[modules]\nself-rm = \"{setting}\"\n[settings]\nlog_file = \"{}/audit.jsonl\"",
            dir.display()
        ))
        .expect("test config parses")
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lictor-self-rm-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_then_rm_allowed() {
        let dir = temp("write");
        let config = config(&dir, "allow");
        record_write(&config, dir.to_str(), Some("s1"), "scratch.txt");
        let hit = check(
            &bash::extract("rm scratch.txt"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        assert_eq!(hit.unwrap().0, ModuleSetting::Allow);
    }

    #[test]
    fn mkdir_then_rm_dir_allowed() {
        let dir = temp("mkdir");
        let config = config(&dir, "allow");
        record_bash(
            &bash::extract("mkdir scratch"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        let hit = check(
            &bash::extract("rm -rf scratch"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        assert!(hit.is_some());
    }

    #[test]
    fn path_inside_created_dir_allowed() {
        let dir = temp("nested");
        let config = config(&dir, "allow");
        record_bash(
            &bash::extract("mkdir scratch"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        let hit = check(
            &bash::extract("rm scratch/notes.txt"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        assert!(hit.is_some());
    }

    #[test]
    fn traversal_out_of_tracked_dir_not_allowed() {
        // a tracked "scratch" dir must not let `../../` walk the check out to an
        // unrelated, untracked path via a naive (non-normalizing) prefix match
        let dir = temp("traversal");
        let config = config(&dir, "allow");
        record_bash(
            &bash::extract("mkdir scratch"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        let outside = dir
            .parent()
            .unwrap()
            .join("lictor-self-rm-traversal-outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "x").unwrap();
        let escape = format!(
            "rm scratch/../../{}/secret.txt",
            outside.file_name().unwrap().to_str().unwrap()
        );
        assert!(
            check(&bash::extract(&escape), &config, dir.to_str(), Some("s1")).is_none(),
            "traversal target must not be treated as owned"
        );
    }

    #[test]
    fn untracked_target_not_allowed() {
        let dir = temp("untracked");
        let config = config(&dir, "allow");
        record_write(&config, dir.to_str(), Some("s1"), "scratch.txt");
        assert!(
            check(
                &bash::extract("rm other.txt"),
                &config,
                dir.to_str(),
                Some("s1")
            )
            .is_none()
        );
    }

    #[test]
    fn mixed_chain_not_allowed() {
        let dir = temp("mixed");
        let config = config(&dir, "allow");
        record_write(&config, dir.to_str(), Some("s1"), "scratch.txt");
        let hit = check(
            &bash::extract("rm scratch.txt && ls"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        assert!(hit.is_none());
    }

    #[test]
    fn preexisting_path_not_tracked() {
        let dir = temp("preexisting");
        let config = config(&dir, "allow");
        std::fs::write(dir.join("already-there.txt"), "x").unwrap();
        record_write(&config, dir.to_str(), Some("s1"), "already-there.txt");
        assert!(
            check(
                &bash::extract("rm already-there.txt"),
                &config,
                dir.to_str(),
                Some("s1")
            )
            .is_none()
        );
    }

    #[test]
    fn off_setting_tracks_nothing() {
        let dir = temp("off");
        let config = config(&dir, "off");
        record_write(&config, dir.to_str(), Some("s1"), "scratch.txt");
        assert!(
            check(
                &bash::extract("rm scratch.txt"),
                &config,
                dir.to_str(),
                Some("s1")
            )
            .is_none()
        );
    }

    #[test]
    fn warn_setting_hints_without_allowing() {
        let dir = temp("warn");
        let config = config(&dir, "warn");
        record_write(&config, dir.to_str(), Some("s1"), "scratch.txt");
        let hit = check(
            &bash::extract("rm scratch.txt"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        assert_eq!(hit.unwrap().0, ModuleSetting::Warn);
    }
}
