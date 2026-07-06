use crate::bash::{Command, Extraction, basename};
use crate::config::{Config, ModuleSetting};
use crate::rules::SpanEdit;

pub struct Spec {
    pub name: &'static str,
    program: &'static str,
    // flags shared by the plain command and its git twin; anything else skips the command
    flags: &'static [&'static str],
    // last path argument is a destination, not a source to verify
    dest_arg: bool,
    rewrite_to: &'static str,
    hint: &'static str,
}

pub const SPECS: &[Spec] = &[
    Spec {
        name: "git-mv",
        program: "mv",
        flags: &["-f", "-n", "-v", "--"],
        dest_arg: true,
        rewrite_to: "git mv",
        hint: "keeps history",
    },
    Spec {
        name: "git-rm",
        program: "rm",
        flags: &["-r", "-f", "-rf", "-fr", "--"],
        dest_arg: false,
        rewrite_to: "git rm",
        hint: "records the deletion in the index",
    },
];

impl Spec {
    // literal path args when the command is `<program> [known-flags] <paths...>`;
    // None = not this program, an unknown flag, or a dynamic word we can't verify
    fn match_paths(&self, command: &Command) -> Option<Vec<String>> {
        let program = command.words.first()?.text.as_deref()?;
        if basename(program) != self.program {
            return None;
        }
        let mut paths = Vec::new();
        for word in &command.words[1..] {
            let text = word.text.as_deref()?;
            if text.starts_with('-') {
                if !self.flags.contains(&text) {
                    return None;
                }
            } else {
                paths.push(text.to_string());
            }
        }
        Some(paths)
    }
}

use super::Plan;

pub fn plan(extraction: &Extraction, config: &Config, tracked: &dyn Fn(&[String]) -> bool) -> Plan {
    let mut plan = Plan::default();
    for command in &extraction.commands {
        if command.synthetic {
            continue;
        }
        for spec in SPECS {
            let setting = match config.modules.get(spec.name) {
                Some(s) if *s != ModuleSetting::Off => *s,
                _ => continue,
            };
            let Some(paths) = spec.match_paths(command) else {
                continue;
            };
            let sources = match (spec.dest_arg, paths.len()) {
                (true, n) if n >= 2 => &paths[..n - 1],
                (false, n) if n >= 1 => &paths[..],
                _ => continue,
            };
            if !tracked(sources) {
                continue;
            }
            let display = command.display();
            match setting {
                ModuleSetting::Rewrite => {
                    let word = &command.words[0];
                    plan.edits.push(SpanEdit {
                        start: word.start,
                        end: word.end,
                        text: spec.rewrite_to.to_string(),
                    });
                    plan.hints.push(format!(
                        "lictor: `{display}` targets git-tracked paths; rewrote to `{}` ({})",
                        spec.rewrite_to, spec.hint
                    ));
                }
                ModuleSetting::Warn => plan.hints.push(format!(
                    "lictor: `{display}` targets git-tracked paths; use `{}` ({})",
                    spec.rewrite_to, spec.hint
                )),
                // off is filtered above; ask/deny are rejected at config load
                _ => unreachable!(),
            }
        }
    }
    plan
}

// read-only probe; the analyzed command itself is never executed
pub fn git_tracked(cwd: Option<&str>, paths: &[String]) -> bool {
    let Some(cwd) = cwd else {
        return false;
    };
    std::process::Command::new("git")
        .args(["ls-files", "--error-unmatch", "--"])
        .args(paths)
        .current_dir(cwd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    fn config(toml: &str) -> Config {
        toml::from_str(toml).expect("test config parses")
    }

    fn plan_for(command: &str, toml: &str, tracked: bool) -> Plan {
        plan(&bash::extract(command), &config(toml), &|_| tracked)
    }

    const REWRITE: &str = "[modules]\ngit-mv = \"rewrite\"\ngit-rm = \"rewrite\"";

    #[test]
    fn mv_tracked_rewrites() {
        let plan = plan_for("mv src/a.rs src/b.rs", REWRITE, true);
        assert_eq!(plan.edits.len(), 1);
        assert_eq!(plan.edits[0].text, "git mv");
        assert_eq!(plan.edits[0].start, 0);
        assert_eq!(plan.edits[0].end, 2);
    }

    #[test]
    fn mv_untracked_untouched() {
        let plan = plan_for("mv /tmp/x /tmp/y", REWRITE, false);
        assert!(plan.edits.is_empty() && plan.hints.is_empty());
    }

    #[test]
    fn rm_tracked_rewrites_with_flags() {
        let plan = plan_for("rm -rf src/old", REWRITE, true);
        assert_eq!(plan.edits.len(), 1);
        assert_eq!(plan.edits[0].text, "git rm");
    }

    #[test]
    fn unknown_flag_skips() {
        assert!(plan_for("mv -i a b", REWRITE, true).edits.is_empty());
        assert!(plan_for("rm -v a", REWRITE, true).edits.is_empty());
    }

    #[test]
    fn dynamic_arg_skips() {
        assert!(plan_for("mv $SRC dst", REWRITE, true).edits.is_empty());
    }

    #[test]
    fn mv_single_arg_skips() {
        assert!(plan_for("mv a", REWRITE, true).edits.is_empty());
    }

    #[test]
    fn warn_hints_without_edit() {
        let plan = plan_for("mv a b", "[modules]\ngit-mv = \"warn\"", true);
        assert!(plan.edits.is_empty());
        assert_eq!(plan.hints.len(), 1);
        assert!(plan.hints[0].contains("git mv"));
    }

    #[test]
    fn off_and_unconfigured_do_nothing() {
        assert!(
            plan_for("mv a b", "[modules]\ngit-mv = \"off\"", true)
                .hints
                .is_empty()
        );
        assert!(plan_for("mv a b", "", true).hints.is_empty());
    }

    #[test]
    fn chain_rewrites_each_site() {
        let plan = plan_for("mv a b && rm c", REWRITE, true);
        assert_eq!(plan.edits.len(), 2);
    }

    #[test]
    fn synthetic_nested_shell_skipped() {
        assert!(plan_for("bash -c 'mv a b'", REWRITE, true).edits.is_empty());
    }
}
