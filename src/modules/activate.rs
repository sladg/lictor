use crate::bash::{Extraction, basename};
use crate::config::ActivateRule;
use std::path::Path;

// heuristics for "the program wasn't found", the only failure we can safely
// suggest re-running after a toolchain activation
const NOT_FOUND_MARKERS: &[&str] = &[
    "command not found",
    "not found",
    "no such file or directory",
    "status code 127",
    "executable file not found",
    "is not recognized",
];

fn looks_like_not_found(text: &str) -> bool {
    let lower = text.to_lowercase();
    NOT_FOUND_MARKERS.iter().any(|m| lower.contains(m))
}

// returns a guidance string when a managed program failed to resolve and its
// toolchain marker file is present in cwd
pub fn guidance(
    extraction: &Extraction,
    rules: &[ActivateRule],
    cwd: Option<&str>,
    signal: &str,
) -> Option<String> {
    if rules.is_empty() || !looks_like_not_found(signal) {
        return None;
    }
    let cwd = cwd?;
    let programs: Vec<&str> = extraction
        .commands
        .iter()
        .filter_map(|c| c.words.first())
        .filter_map(|w| w.text.as_deref())
        .map(basename)
        .collect();
    for rule in rules {
        if !Path::new(cwd).join(&rule.file).exists() {
            continue;
        }
        let tool = programs
            .iter()
            .find(|p| rule.tools.is_empty() || rule.tools.iter().any(|t| t == *p))?;
        return Some(format!(
            "lictor: `{tool}` did not resolve. This project pins toolchains via `{}` — run `{}`, then retry the command.",
            rule.file, rule.run
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    fn rule() -> ActivateRule {
        ActivateRule {
            file: ".prototools".into(),
            run: "proto use".into(),
            tools: vec!["node".into(), "bun".into()],
        }
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lictor-activate-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn guide(command: &str, cwd: &std::path::Path, signal: &str) -> Option<String> {
        guidance(&bash::extract(command), &[rule()], cwd.to_str(), signal)
    }

    #[test]
    fn hints_on_not_found_with_marker() {
        let dir = temp("hit");
        std::fs::write(dir.join(".prototools"), "node = \"22\"\n").unwrap();
        let hint = guide("bun run check", &dir, "bun: command not found").unwrap();
        assert!(hint.contains("proto use") && hint.contains("bun"), "{hint}");
    }

    #[test]
    fn silent_without_marker() {
        assert!(guide("bun run check", &temp("nomarker"), "command not found").is_none());
    }

    #[test]
    fn silent_for_unmanaged_tool() {
        let dir = temp("unmanaged");
        std::fs::write(dir.join(".prototools"), "node = \"22\"\n").unwrap();
        assert!(guide("cargo build", &dir, "command not found").is_none());
    }

    #[test]
    fn silent_for_ordinary_failure() {
        let dir = temp("ordinary");
        std::fs::write(dir.join(".prototools"), "node = \"22\"\n").unwrap();
        assert!(guide("bun run check", &dir, "type error in src/x.ts").is_none());
    }
}
