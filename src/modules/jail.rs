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
        if command.synthetic {
            continue;
        }
        for word in command.words.iter().skip(1) {
            let Some(text) = word.text.as_deref() else {
                continue;
            };
            // also catch --flag=/path values
            let candidate = text.split_once('=').map_or(text, |(_, v)| v);
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
    fn synthetic_nested_shell_skipped() {
        assert!(check("bash -c 'cat /etc/hosts'", &[]).is_empty());
    }

    #[test]
    fn duplicate_paths_reported_once() {
        assert_eq!(check("cat /etc/hosts /etc/hosts", &[]).len(), 1);
    }
}
