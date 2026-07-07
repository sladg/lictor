use super::state_dir;
use crate::audit;
use crate::bash::{Command, Extraction, basename};
use crate::config::{Config, ModuleSetting};
use std::path::PathBuf;

// delete/recreate detector: `rm`/`git rm` targets are fingerprinted BEFORE the
// command runs (PreToolUse — the file still exists); a later Write whose content
// fuzzy-matches a recent deletion gets flagged: that is a rename done the
// history-destroying way. Suggest restore + `git mv` instead.

// ponytail: fixed knobs; config them if real projects need different tuning
const WINDOW_SECS: u64 = 3600;
const MAX_ENTRIES: usize = 32;
const MIN_LINES: usize = 8;
const MAX_BYTES: u64 = 1_000_000;
const SIMILARITY: f64 = 0.6;

#[derive(serde::Serialize, serde::Deserialize)]
struct Entry {
    path: String,
    ts: u64,
    hashes: Vec<u64>,
}

pub struct Recreated {
    pub old_path: String,
    pub percent: u32,
}

fn setting(config: &Config) -> ModuleSetting {
    *config
        .modules
        .get("delete-recreate")
        .unwrap_or(&ModuleSetting::Off)
}

fn state_file(config: &Config, cwd: Option<&str>, session: &str) -> Option<PathBuf> {
    let slug: String = session
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    Some(state_dir(config, cwd)?.join(format!("deletes-{slug}.json")))
}

// sorted, deduped hashes of trimmed non-empty lines; DefaultHasher::new() is
// deterministic across processes, which the record->check round-trip relies on
fn fingerprint(contents: &str) -> Vec<u64> {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hashes: Vec<u64> = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let mut h = DefaultHasher::new();
            l.hash(&mut h);
            h.finish()
        })
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

fn jaccard(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut shared = 0usize;
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                shared += 1;
                i += 1;
                j += 1;
            }
        }
    }
    shared as f64 / (a.len() + b.len() - shared) as f64
}

// literal path args of `rm [flags]` / `git rm [flags]`; --cached keeps the
// file so it does not count as a deletion
pub(super) fn deletion_targets(command: &Command) -> Vec<String> {
    let words: Vec<&str> = command
        .words
        .iter()
        .filter_map(|w| w.text.as_deref())
        .collect();
    if words.len() != command.words.len() {
        return Vec::new(); // dynamic word somewhere; don't guess
    }
    let args = match words.split_first() {
        Some((&first, rest)) if basename(first) == "rm" => rest,
        Some((&first, rest))
            if basename(first) == "git" && rest.first().is_some_and(|w| *w == "rm") =>
        {
            &rest[1..]
        }
        _ => return Vec::new(),
    };
    if args.contains(&"--cached") {
        return Vec::new();
    }
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .map(|a| a.to_string())
        .collect()
}

fn load(path: &PathBuf) -> Vec<Entry> {
    let now = audit::now();
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<Entry>>(&raw).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|e| now.saturating_sub(e.ts) <= WINDOW_SECS)
        .collect()
}

// lexically collapses `.`/`..` and expands `~` (see jail::normalize) — a naive
// `{cwd}/{path}` concatenation lets `scratch/../../outside/secret` pass a
// tracked-prefix check for `scratch` while landing entirely outside it
pub(super) fn resolve(path: &str, cwd: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    crate::modules::jail::normalize(path, cwd, &home)
}

pub fn record(extraction: &Extraction, config: &Config, cwd: Option<&str>, session: Option<&str>) {
    if setting(config) == ModuleSetting::Off {
        return;
    }
    let (Some(cwd), Some(session)) = (cwd, session) else {
        return;
    };
    let Some(state) = state_file(config, Some(cwd), session) else {
        return;
    };
    let mut entries: Option<Vec<Entry>> = None;
    for command in &extraction.commands {
        for target in deletion_targets(command) {
            let path = resolve(&target, cwd);
            let fits = std::fs::metadata(&path)
                .map(|m| m.is_file() && m.len() <= MAX_BYTES)
                .unwrap_or(false);
            if !fits {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            let hashes = fingerprint(&contents);
            if hashes.len() < MIN_LINES {
                continue;
            }
            let list = entries.get_or_insert_with(|| load(&state));
            list.retain(|e| e.path != path);
            list.push(Entry {
                path,
                ts: audit::now(),
                hashes,
            });
        }
    }
    let Some(mut list) = entries else {
        return;
    };
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

pub fn check(
    config: &Config,
    cwd: Option<&str>,
    session: Option<&str>,
    path: &str,
    contents: &[String],
) -> Option<(ModuleSetting, Recreated)> {
    let setting = setting(config);
    if setting == ModuleSetting::Off {
        return None;
    }
    let session = session?;
    let hashes = fingerprint(&contents.join("\n"));
    if hashes.len() < MIN_LINES {
        return None;
    }
    let state = state_file(config, cwd, session)?;
    let new_path = resolve(path, cwd.unwrap_or(""));
    load(&state)
        .into_iter()
        .filter(|e| e.path != new_path)
        .map(|e| (jaccard(&hashes, &e.hashes), e))
        .filter(|(score, _)| *score >= SIMILARITY)
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .map(|(score, e)| {
            (
                setting,
                Recreated {
                    old_path: e.path,
                    percent: (score * 100.0).round() as u32,
                },
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    fn config(dir: &std::path::Path, setting: &str) -> Config {
        toml::from_str(&format!(
            "[modules]\ndelete-recreate = \"{setting}\"\n[settings]\nlog_file = \"{}/audit.jsonl\"",
            dir.display()
        ))
        .expect("test config parses")
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lictor-recreate-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn body(tag: &str) -> String {
        (1..=10).map(|i| format!("{tag} line {i}\n")).collect()
    }

    #[test]
    fn resolve_collapses_traversal() {
        // a naive `{cwd}/{path}` concatenation would leave `../..` intact,
        // letting a prefix check on the result believe it's still inside cwd
        assert_eq!(
            resolve("scratch/../../outside/secret.txt", "/repo"),
            "/outside/secret.txt"
        );
        assert_eq!(resolve("a/./b", "/repo"), "/repo/a/b");
    }

    #[test]
    fn fingerprint_trims_and_dedups() {
        let a = fingerprint("x\n  x  \n\ny\n");
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn jaccard_identical_and_disjoint() {
        let a = fingerprint(&body("a"));
        let b = fingerprint(&body("b"));
        assert_eq!(jaccard(&a, &a), 1.0);
        assert_eq!(jaccard(&a, &b), 0.0);
    }

    #[test]
    fn deletion_targets_match_rm_and_git_rm() {
        let targets = |cmd: &str| {
            bash::extract(cmd)
                .commands
                .iter()
                .flat_map(deletion_targets)
                .collect::<Vec<_>>()
        };
        assert_eq!(targets("rm -f a.rs b.rs"), vec!["a.rs", "b.rs"]);
        assert_eq!(targets("git rm src/a.rs"), vec!["src/a.rs"]);
        assert!(targets("git rm --cached a.rs").is_empty());
        assert!(targets("rm $FILE").is_empty());
        assert!(targets("cat a.rs").is_empty());
    }

    #[test]
    fn record_then_check_flags_similar_write() {
        let dir = temp("roundtrip");
        let config = config(&dir, "ask");
        std::fs::write(dir.join("old.rs"), body("same")).unwrap();
        let extraction = bash::extract("rm old.rs");
        record(&extraction, &config, dir.to_str(), Some("s1"));

        let hit = check(&config, dir.to_str(), Some("s1"), "new.rs", &[body("same")]);
        let (setting, hit) = hit.expect("similar write flagged");
        assert_eq!(setting, ModuleSetting::Ask);
        assert!(hit.old_path.ends_with("old.rs"));
        assert_eq!(hit.percent, 100);

        // dissimilar content passes
        assert!(
            check(
                &config,
                dir.to_str(),
                Some("s1"),
                "new.rs",
                &[body("other")]
            )
            .is_none()
        );
        // other sessions see nothing
        assert!(check(&config, dir.to_str(), Some("s2"), "new.rs", &[body("same")]).is_none());
    }

    #[test]
    fn rewriting_the_same_path_passes() {
        let dir = temp("samepath");
        let config = config(&dir, "ask");
        std::fs::write(dir.join("keep.rs"), body("keep")).unwrap();
        record(
            &bash::extract("rm keep.rs"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        assert!(
            check(
                &config,
                dir.to_str(),
                Some("s1"),
                "keep.rs",
                &[body("keep")]
            )
            .is_none()
        );
    }

    #[test]
    fn tiny_files_ignored() {
        let dir = temp("tiny");
        let config = config(&dir, "ask");
        std::fs::write(dir.join("tiny.rs"), "one\ntwo\n").unwrap();
        record(
            &bash::extract("rm tiny.rs"),
            &config,
            dir.to_str(),
            Some("s1"),
        );
        assert!(
            check(
                &config,
                dir.to_str(),
                Some("s1"),
                "new.rs",
                &["one\ntwo\n".to_string()]
            )
            .is_none()
        );
    }

    #[test]
    fn off_records_nothing() {
        let dir = temp("off");
        std::fs::write(dir.join("old.rs"), body("x")).unwrap();
        record(
            &bash::extract("rm old.rs"),
            &config(&dir, "off"),
            dir.to_str(),
            Some("s1"),
        );
        let ask = config(&dir, "ask");
        assert!(check(&ask, dir.to_str(), Some("s1"), "new.rs", &[body("x")]).is_none());
    }
}
