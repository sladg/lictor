use crate::bash::Extraction;
use crate::config::Config;

// literal argument words that look like filesystem paths and resolve outside
// the project and every allowed root. Lexical only: `~` expanded, `.`/`..`
// collapsed — symlinks and flag-attached paths (-o/tmp/x) are not resolved.

pub fn violations(extraction: &Extraction, config: &Config, cwd: &str) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut roots = vec![normalize(cwd, cwd, &home)];
    roots.extend(config.jail_allow().iter().map(|p| normalize(p, cwd, &home)));
    let mut out = Vec::new();
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
            let resolved = normalize(candidate, cwd, &home);
            let inside = roots
                .iter()
                .any(|r| resolved == *r || resolved.starts_with(&format!("{r}/")));
            if !inside && !out.contains(&resolved) {
                out.push(resolved);
            }
        }
    }
    out
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
}
