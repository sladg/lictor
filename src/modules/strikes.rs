use crate::audit;
use crate::config::Config;
use std::path::PathBuf;

// consecutive-deny counter per session, persisted across hook invocations.
// Threshold reached -> lockdown: the engine turns every Bash call into "ask"
// until a command actually executes (PostToolUse), which resets the counter.

fn state_path(config: &Config, cwd: Option<&str>, session: &str) -> Option<PathBuf> {
    let slug: String = session
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    Some(super::state_dir(config, cwd)?.join(format!("strikes-{slug}.json")))
}

fn read(path: &PathBuf, window: u64) -> u32 {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return 0;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return 0;
    };
    let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let last = value.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
    // stale strikes expire: an idle window means the user was likely involved
    if audit::now().saturating_sub(last) > window {
        return 0;
    }
    count
}

pub fn count(config: &Config, cwd: Option<&str>, session: &str) -> u32 {
    match state_path(config, cwd, session) {
        Some(path) => read(&path, config.strikes_window()),
        None => 0,
    }
}

pub fn bump(config: &Config, cwd: Option<&str>, session: &str) {
    let Some(path) = state_path(config, cwd, session) else {
        return;
    };
    let next = read(&path, config.strikes_window()) + 1;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        &path,
        format!("{{\"count\":{next},\"ts\":{}}}", audit::now()),
    );
}

pub fn reset(config: &Config, cwd: Option<&str>, session: &str) {
    if let Some(path) = state_path(config, cwd, session) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // state lands next to the configured log_file, isolated per test
    fn config(dir: &std::path::Path) -> Config {
        toml::from_str(&format!(
            "[settings]\nstrikes = 3\nlog_file = \"{}/audit.jsonl\"",
            dir.display()
        ))
        .expect("test config parses")
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lictor-strikes-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bump_counts_and_reset_clears() {
        let dir = temp("bump");
        let config = config(&dir);
        let cwd = dir.to_str();
        assert_eq!(count(&config, cwd, "s1"), 0);
        bump(&config, cwd, "s1");
        bump(&config, cwd, "s1");
        assert_eq!(count(&config, cwd, "s1"), 2);
        reset(&config, cwd, "s1");
        assert_eq!(count(&config, cwd, "s1"), 0);
    }

    #[test]
    fn sessions_are_isolated() {
        let dir = temp("iso");
        let config = config(&dir);
        let cwd = dir.to_str();
        bump(&config, cwd, "a");
        assert_eq!(count(&config, cwd, "b"), 0);
    }

    #[test]
    fn stale_strikes_expire() {
        let dir = temp("stale");
        let config = config(&dir);
        let cwd = dir.to_str();
        bump(&config, cwd, "old");
        let path = state_path(&config, cwd, "old").unwrap();
        // rewind the timestamp past the window
        std::fs::write(
            &path,
            format!("{{\"count\":9,\"ts\":{}}}", crate::audit::now() - 700),
        )
        .unwrap();
        assert_eq!(count(&config, cwd, "old"), 0);
    }

    #[test]
    fn corrupt_state_reads_as_zero() {
        let dir = temp("corrupt");
        let config = config(&dir);
        let cwd = dir.to_str();
        let path = state_path(&config, cwd, "bad").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(count(&config, cwd, "bad"), 0);
    }
}
