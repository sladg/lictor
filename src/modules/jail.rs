use crate::bash::{Command, Extraction};
use crate::config::Config;

// literal argument words that look like filesystem paths and resolve outside
// the project and every allowed root. Lexical only: `~` expanded, `.`/`..`
// collapsed — symlinks and flag-attached paths (-o/tmp/x) are not resolved.
//
// the primary root is the git repo containing cwd, not cwd itself — an agent
// invoked from a subdirectory can still `cd ..`/reference sibling paths
// anywhere in the repo. cwd is the fallback when it isn't inside a repo.

fn roots(config: &Config, cwd: &str, home: &str) -> Vec<String> {
    let primary = git_root(cwd).unwrap_or_else(|| cwd.to_string());
    let mut roots = vec![normalize(&primary, cwd, home)];
    roots.extend(config.jail_allow().iter().map(|p| normalize(p, cwd, home)));
    roots
}

fn is_inside(roots: &[String], resolved: &str) -> bool {
    roots
        .iter()
        .any(|r| resolved == r || resolved.starts_with(&format!("{r}/")))
}

// a single already-known literal path (Write/Edit/MultiEdit/NotebookEdit's
// file_path) rather than a shell command to scan — no word-extraction or `cd`
// tracking needed, just resolve-and-check-roots.
pub fn violation_for_path(path: &str, config: &Config, cwd: &str) -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let roots = roots(config, cwd, &home);
    let resolved = normalize(path, cwd, &home);
    (!is_inside(&roots, &resolved)).then_some(resolved)
}

pub fn violations(extraction: &Extraction, config: &Config, cwd: &str) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let roots = roots(config, cwd, &home);
    let mut out = Vec::new();
    // `cd` earlier in the same chain changes the base every later relative path
    // resolves against (`cd .. && cat ../secret` escapes further than `cat`'s
    // own literal ".." suggests). Track it sequentially. A subshell's `cd`
    // (synthetic: bash -c/eval/find -exec) never leaks back to the parent
    // shell, so only a non-synthetic `cd` updates the tracked cwd.
    let mut effective_cwd = cwd.to_string();
    for command in &extraction.commands {
        for word in command.words.iter().skip(1) {
            let expanded;
            let text = match word.text.as_deref() {
                Some(text) => text,
                // dynamic word: recover $HOME/${HOME} paths from the raw source.
                // synthetic spans index the inner re-parsed string, not `source`, so skip.
                None if !command.synthetic => {
                    let raw = extraction.source.get(word.start..word.end).unwrap_or("");
                    match expand_home(raw, &home) {
                        Some(path) => {
                            expanded = path;
                            expanded.as_str()
                        }
                        None => continue,
                    }
                }
                None => continue,
            };
            let candidate = path_candidate(text);
            if !looks_like_path(candidate) {
                continue;
            }
            let resolved = normalize(candidate, &effective_cwd, &home);
            if !is_inside(&roots, &resolved) && !out.contains(&resolved) {
                out.push(resolved);
            }
        }
        // `cd -` or a dynamic target: no way to know the result, so freeze
        // rather than guess — never worse than the old always-the-original-cwd
        // behavior, and correct everywhere else.
        if !command.synthetic
            && let Some(Some(target)) = cd_target(command, &home)
        {
            effective_cwd = normalize(&target, &effective_cwd, &home);
        }
    }
    out
}

// bash `cd [-L|-P|-e|-@]... [target]`; bare `cd` goes to $HOME, `cd -` needs
// OLDPWD (which we don't have). None when this command isn't a `cd` at all.
fn cd_target(command: &Command, home: &str) -> Option<Option<String>> {
    let program = command.words.first()?.text.as_deref()?;
    if program != "cd" {
        return None;
    }
    for word in &command.words[1..] {
        match word.text.as_deref() {
            Some("-") => return Some(None),
            Some(t) if t.starts_with('-') => continue,
            Some(t) => return Some(Some(t.to_string())),
            None => return Some(None),
        }
    }
    Some(Some(home.to_string()))
}

// read-only probe: the git repository root containing `cwd`, so the jail's
// primary root is the whole repo — not the literal directory the hook happened
// to start from. None when cwd isn't inside a repo (or `git` isn't available).
fn git_root(cwd: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(cwd)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = String::from_utf8(output.stdout).ok()?;
    let root = root.trim();
    (!root.is_empty()).then(|| root.to_string())
}

// value after `flag=`, plus the path glued onto a short flag (-o/etc/x -> /etc/x);
// the glued case requires an alphabetic flag letter so `-1/2`-style args don't false-trip
fn path_candidate(text: &str) -> &str {
    let value = text.split_once('=').map_or(text, |(_, v)| v);
    if value.starts_with('-')
        && !value.starts_with("--")
        && value
            .chars()
            .nth(1)
            .is_some_and(|c| c.is_ascii_alphabetic())
        && let Some(idx) = value.find('/')
    {
        return &value[idx..];
    }
    value
}

// $HOME/... and ${HOME}/... parse as dynamic words (text = None) but their target
// is known; recover the same absolute path `~/...` would yield. ponytail: only HOME —
// add other well-known vars if an escape via $XDG_*/etc. shows up.
fn expand_home(raw: &str, home: &str) -> Option<String> {
    let rest = raw
        .strip_prefix("$HOME")
        .or_else(|| raw.strip_prefix("${HOME}"))?;
    (rest.is_empty() || rest.starts_with('/')).then(|| format!("{home}{rest}"))
}

pub(crate) fn looks_like_path(text: &str) -> bool {
    text.starts_with('/')
        || text == "~"
        || text.starts_with("~/")
        || text == ".."
        || text.starts_with("../")
        || text.contains("/../")
}

pub(crate) fn normalize(path: &str, cwd: &str, home: &str) -> String {
    let expanded = match (path, path.strip_prefix("~/")) {
        ("~", _) => home.to_string(),
        (_, Some(rest)) => format!("{home}/{rest}"),
        _ => path.to_string(),
    };
    let absolute = if expanded.starts_with('/') {
        expanded
    } else {
        format!("{cwd}/{expanded}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for segment in absolute.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    const CWD: &str = "/Users/nobody/project";

    fn config(allow: &[&str]) -> Config {
        let list = allow
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        toml::from_str(&format!(
            "[settings]\njail = \"ask\"\njail_allow = [{list}]"
        ))
        .expect("test config parses")
    }

    fn check(command: &str, allow: &[&str]) -> Vec<String> {
        violations(&bash::extract(command), &config(allow), CWD)
    }

    #[test]
    fn outside_paths_flagged() {
        assert_eq!(check("cat /etc/hosts", &[]), vec!["/etc/hosts"]);
        assert_eq!(
            check("cat ../outside.txt", &[]),
            vec!["/Users/nobody/outside.txt"]
        );
        assert_eq!(
            check("ls src/../../other", &[]),
            vec!["/Users/nobody/other"]
        );
        assert!(!check("cat ~/.zshrc", &[]).is_empty());
    }

    #[test]
    fn flag_attached_value_flagged() {
        assert_eq!(
            check("rg x --path=/var/log/sys.log", &[]),
            vec!["/var/log/sys.log"]
        );
    }

    #[test]
    fn project_paths_pass() {
        assert!(check("cat src/main.rs", &[]).is_empty());
        assert!(check(&format!("cat {CWD}/src/main.rs"), &[]).is_empty());
        assert!(check("cat src/../README.md", &[]).is_empty());
    }

    #[test]
    fn non_paths_pass() {
        assert!(check("curl https://example.com/etc/passwd", &[]).is_empty());
        assert!(check("echo a/b", &[]).is_empty());
    }

    #[test]
    fn allow_roots_grant_access() {
        assert!(check("cp a.txt /tmp/a.txt", &["/tmp"]).is_empty());
        assert!(check("cat /tmp/x", &[]).len() == 1);
        // sibling dir with the allowed root as prefix is NOT covered
        assert_eq!(check("cat /tmpfoo/x", &["/tmp"]), vec!["/tmpfoo/x"]);
    }

    #[test]
    fn synthetic_nested_shell_flagged() {
        // paths inside `bash -c '...'` are re-parsed and jailed like any other
        assert_eq!(check("bash -c 'cat /etc/hosts'", &[]), vec!["/etc/hosts"]);
    }

    #[test]
    fn home_env_var_paths_flagged() {
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(
            check("cat $HOME/.ssh/id_rsa", &[]),
            vec![format!("{home}/.ssh/id_rsa")]
        );
        assert_eq!(
            check("cat ${HOME}/.aws/creds", &[]),
            vec![format!("{home}/.aws/creds")]
        );
    }

    #[test]
    fn glued_flag_path_flagged() {
        assert_eq!(check("tail -o/etc/shadow", &[]), vec!["/etc/shadow"]);
        // alphabetic flag letter required — `-1/2`-style args stay untouched
        assert!(check("bc -1/2", &[]).is_empty());
    }

    #[test]
    fn duplicate_paths_reported_once() {
        assert_eq!(check("cat /etc/hosts /etc/hosts", &[]).len(), 1);
    }

    // CWD above doesn't exist on disk, so `git rev-parse` fails there and jail
    // falls back to plain-cwd anchoring (covered by the tests above). These use
    // this crate's own repo to exercise the git-root anchor for real.
    fn repo_subdir(rel: &str) -> String {
        format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn sibling_path_inside_repo_passes_from_subdir() {
        let subdir = repo_subdir("src/modules");
        assert!(check_at("cat ../../README.md", &[], &subdir).is_empty());
    }

    #[test]
    fn cd_to_repo_root_from_subdir_passes() {
        let subdir = repo_subdir("src/modules");
        assert!(check_at("cd ../..", &[], &subdir).is_empty());
    }

    #[test]
    fn path_outside_repo_still_flagged_from_subdir() {
        let subdir = repo_subdir("src/modules");
        assert_eq!(check_at("cat /etc/hosts", &[], &subdir), vec!["/etc/hosts"]);
    }

    #[test]
    fn multi_hop_cd_stays_in_bounds() {
        let subdir = repo_subdir("src/modules");
        assert!(check_at("cd .. && cd .. && cat docs/reference.md", &[], &subdir).is_empty());
        assert!(check_at("cd ../.. && rg TODO docs", &[], &subdir).is_empty());
    }

    #[test]
    fn multi_hop_cd_escape_now_detected() {
        // previously `../README.md` resolved against the ORIGINAL cwd
        // (src/modules), landing inside `src/` — a false negative. With `cd`
        // tracked, it resolves against the post-`cd ../..` cwd (repo root),
        // landing one level ABOVE the repo — correctly flagged.
        let subdir = repo_subdir("src/modules");
        assert_eq!(
            check_at("cd ../.. && cat ../README.md", &[], &subdir).len(),
            1
        );
    }

    #[test]
    fn absolute_cd_inside_repo_then_relative_path_passes() {
        let repo = env!("CARGO_MANIFEST_DIR");
        let subdir = repo_subdir("src/modules");
        let command = format!("cd {repo}/docs && cat ../README.md");
        assert!(check_at(&command, &[], &subdir).is_empty());
    }

    #[test]
    fn absolute_cd_outside_repo_flagged() {
        let subdir = repo_subdir("src/modules");
        assert_eq!(check_at("cd /etc && cat hosts", &[], &subdir), vec!["/etc"]);
    }

    #[test]
    fn bare_cd_home_then_escape_detected() {
        // bare `cd` goes to $HOME; a subsequent relative escape from there
        // used to be invisible (jail always resolved against the original cwd)
        assert_eq!(check("cd && cat ../evil", &[]).len(), 1);
    }

    #[test]
    fn cd_dash_freezes_instead_of_guessing() {
        // `cd -` needs OLDPWD, which we don't have; tracking freezes at the
        // last known cwd rather than dropping the escape entirely
        let subdir = repo_subdir("src/modules");
        assert!(!check_at("cd - && cat ../../../../../../etc/passwd", &[], &subdir).is_empty());
    }

    fn check_at(command: &str, allow: &[&str], cwd: &str) -> Vec<String> {
        violations(&bash::extract(command), &config(allow), cwd)
    }
}
