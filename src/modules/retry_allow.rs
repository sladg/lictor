use super::state_dir;
use crate::audit;
use crate::config::Config;
use std::path::PathBuf;

// deny-then-allow: a bash/edit rule with retry_count+retry_window denies the
// first N matches (its hint keeps surfacing) but auto-allows a resubmission
// once N denies have landed within the window — cosmetic retries of a denied
// command are common enough (see out-of-git/bullshit-corpus.md) that a hard
// deny just adds churn without preventing the action. One counter per rule
// per session, persisted across hook invocations the same way strikes/
// recreate/self_rm are; expires on its own if the agent doesn't retry in time.

// ponytail: fixed cap, bounds file growth if a session trips many distinct rules
const MAX_ENTRIES: usize = 64;

#[derive(serde::Serialize, serde::Deserialize)]
struct Entry {
    rule: String,
    count: u32,
    ts: u64,
}

fn state_file(config: &Config, cwd: Option<&str>, session: &str) -> Option<PathBuf> {
    let slug: String = session
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    Some(state_dir(config, cwd)?.join(format!("retries-{slug}.json")))
}

fn load(path: &PathBuf) -> Vec<Entry> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save(path: &PathBuf, entries: &[Entry]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(raw) = serde_json::to_string(entries) {
        let _ = std::fs::write(path, raw);
    }
}

// prior denies recorded for `rule_key` within `window` seconds; stale or
// missing reads as 0 — an idle window means the resubmission isn't a retry
pub fn count(
    config: &Config,
    cwd: Option<&str>,
    session: &str,
    rule_key: &str,
    window: u64,
) -> u32 {
    let Some(path) = state_file(config, cwd, session) else {
        return 0;
    };
    let now = audit::now();
    load(&path)
        .into_iter()
        .find(|e| e.rule == rule_key && now.saturating_sub(e.ts) <= window)
        .map(|e| e.count)
        .unwrap_or(0)
}

pub fn bump(config: &Config, cwd: Option<&str>, session: &str, rule_key: &str) {
    let Some(path) = state_file(config, cwd, session) else {
        return;
    };
    let now = audit::now();
    let mut entries = load(&path);
    match entries.iter_mut().find(|e| e.rule == rule_key) {
        Some(entry) => {
            entry.count += 1;
            entry.ts = now;
        }
        None => {
            if entries.len() >= MAX_ENTRIES
                && let Some((i, _)) = entries.iter().enumerate().min_by_key(|(_, e)| e.ts)
            {
                entries.remove(i);
            }
            entries.push(Entry {
                rule: rule_key.to_string(),
                count: 1,
                ts: now,
            });
        }
    }
    save(&path, &entries);
}

pub fn reset(config: &Config, cwd: Option<&str>, session: &str, rule_key: &str) {
    let Some(path) = state_file(config, cwd, session) else {
        return;
    };
    let mut entries = load(&path);
    entries.retain(|e| e.rule != rule_key);
    save(&path, &entries);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &std::path::Path) -> Config {
        toml::from_str(&format!(
            "[settings]\nlog_file = \"{}/audit.jsonl\"",
            dir.display()
        ))
        .expect("test config parses")
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lictor-retry-allow-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bump_counts_and_reset_clears() {
        let dir = temp("bump");
        let config = config(&dir);
        let cwd = dir.to_str();
        assert_eq!(count(&config, cwd, "s1", "rule-a", 30), 0);
        bump(&config, cwd, "s1", "rule-a");
        assert_eq!(count(&config, cwd, "s1", "rule-a", 30), 1);
        bump(&config, cwd, "s1", "rule-a");
        assert_eq!(count(&config, cwd, "s1", "rule-a", 30), 2);
        reset(&config, cwd, "s1", "rule-a");
        assert_eq!(count(&config, cwd, "s1", "rule-a", 30), 0);
    }

    #[test]
    fn rules_are_isolated_within_a_session() {
        let dir = temp("rule-iso");
        let config = config(&dir);
        let cwd = dir.to_str();
        bump(&config, cwd, "s1", "rule-a");
        assert_eq!(count(&config, cwd, "s1", "rule-b", 30), 0);
    }

    #[test]
    fn sessions_are_isolated() {
        let dir = temp("session-iso");
        let config = config(&dir);
        let cwd = dir.to_str();
        bump(&config, cwd, "a", "rule-a");
        assert_eq!(count(&config, cwd, "b", "rule-a", 30), 0);
    }

    #[test]
    fn stale_entry_expires() {
        let dir = temp("stale");
        let config = config(&dir);
        let cwd = dir.to_str();
        bump(&config, cwd, "s1", "rule-a");
        let path = state_file(&config, cwd, "s1").unwrap();
        std::fs::write(
            &path,
            format!(
                "[{{\"rule\":\"rule-a\",\"count\":9,\"ts\":{}}}]",
                audit::now() - 700
            ),
        )
        .unwrap();
        assert_eq!(count(&config, cwd, "s1", "rule-a", 30), 0);
    }

    #[test]
    fn corrupt_state_reads_as_zero() {
        let dir = temp("corrupt");
        let config = config(&dir);
        let cwd = dir.to_str();
        let path = state_file(&config, cwd, "s1").unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(count(&config, cwd, "s1", "rule-a", 30), 0);
    }

    #[test]
    fn max_entries_evicts_the_stalest_rule() {
        let dir = temp("evict");
        let config = config(&dir);
        let cwd = dir.to_str();
        bump(&config, cwd, "s1", "rule-oldest");
        for i in 0..MAX_ENTRIES {
            bump(&config, cwd, "s1", &format!("rule-{i}"));
        }
        assert_eq!(count(&config, cwd, "s1", "rule-oldest", 30), 0);
        assert_eq!(count(&config, cwd, "s1", "rule-0", 30), 1);
    }
}
