use super::Plan;
use crate::bash::Extraction;
use crate::config::{Config, ModuleSetting};
use crate::modules::jail::{looks_like_path, normalize};

// project-scoped path hygiene. The agent keeps constructing absolute paths that
// either (a) point INSIDE the project — pure token waste vs a relative path, and
// a cwd-drift footgun — or (b) point at a system-temp dir, where scratch belongs
// in .claude/scratch/ or the kv cache, never /tmp. Literal paths only (command
// args and `NAME=val` prefixes); dynamic/expanded values are left alone.
// Paths OUTSIDE the project are the jail's concern, not ours.

const TEMP_ROOTS: &[&str] = &["/tmp", "/private/tmp", "/var/tmp", "/var/folders"];

pub fn plan(extraction: &Extraction, config: &Config, cwd: Option<&str>, out: &mut Plan) {
    let setting = match config.modules.get("abs-paths") {
        Some(s) if *s != ModuleSetting::Off => *s,
        _ => return,
    };
    let Some(cwd) = cwd else {
        return;
    };
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = normalize(cwd, cwd, &home);

    // command args (never the program word — bin paths are strip_program_paths'
    // job) plus the values of `NAME=val` prefixes the parser dropped from words
    let args = extraction
        .commands
        .iter()
        .filter(|c| !c.synthetic)
        .flat_map(|c| c.words.iter().skip(1).filter_map(|w| w.text.as_deref()));
    let assigns = extraction.assignments.iter().map(String::as_str);

    let mut seen: Vec<String> = Vec::new();
    for raw in args.chain(assigns) {
        // split only flag values (--path=/abs); a bare `msg=/tmp/x` arg (commit
        // message, echo payload) must not be mistaken for a path
        let candidate = if raw.starts_with('-') {
            raw.split_once('=').map_or(raw, |(_, v)| v)
        } else {
            raw
        };
        if !is_absolute(candidate) || !looks_like_path(candidate) {
            continue;
        }
        let resolved = normalize(candidate, &cwd, &home);
        if seen.contains(&resolved) {
            continue;
        }
        let Some(message) = classify(&resolved, &cwd) else {
            continue;
        };
        seen.push(resolved);
        match setting {
            ModuleSetting::Deny => out.denies.push(message),
            ModuleSetting::Ask => out.asks.push(message),
            ModuleSetting::Warn => out.hints.push(message),
            ModuleSetting::Rewrite | ModuleSetting::Off => {}
        }
    }
}

fn is_absolute(text: &str) -> bool {
    text.starts_with('/') || text == "~" || text.starts_with("~/")
}

fn is_under(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{root}/"))
}

// in-project check first: if cwd itself sits under a temp root (CI tmp checkout),
// a real project path must still read as in-project, not temp
fn classify(resolved: &str, cwd: &str) -> Option<String> {
    if is_under(resolved, cwd) {
        let rel = resolved
            .strip_prefix(&format!("{cwd}/"))
            .unwrap_or(resolved);
        return Some(format!(
            "lictor: `{resolved}` is inside the project — reference it relative to the repo root as `{rel}`, not by absolute path (saves tokens, avoids cwd-drift path bugs)"
        ));
    }
    if TEMP_ROOTS.iter().any(|t| is_under(resolved, t)) {
        return Some(format!(
            "lictor: `{resolved}` is a system-temp path — put scratch files under .claude/scratch/ or cache command output with `kv set`, never /tmp"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    const CWD: &str = "/Users/nobody/project";

    fn plan_for(command: &str, setting: &str) -> Plan {
        let config: Config = toml::from_str(&format!("[modules]\nabs-paths = \"{setting}\""))
            .expect("test config parses");
        let mut plan = Plan::default();
        super::plan(&bash::extract(command), &config, Some(CWD), &mut plan);
        plan
    }

    #[test]
    fn in_project_absolute_arg_denied_with_relative_hint() {
        // the motivating case: agent builds a full path for a repo file
        let plan = plan_for(
            "grep -c \"\" /Users/nobody/project/apps/courier/src/register/onboarding-flow.ts",
            "deny",
        );
        assert_eq!(plan.denies.len(), 1);
        assert!(
            plan.denies[0].contains("apps/courier/src/register/onboarding-flow.ts")
                && plan.denies[0].contains("relative"),
            "{:?}",
            plan.denies
        );
    }

    #[test]
    fn scratch_var_assignment_denied() {
        // the `D=/private/tmp/...` scratchpad-exploit shape (corpus §6)
        let plan = plan_for(
            "D=/private/tmp/claude-501/scratchpad/exploit cargo build",
            "deny",
        );
        assert_eq!(plan.denies.len(), 1);
        assert!(
            plan.denies[0].contains(".claude/scratch/") && plan.denies[0].contains("kv set"),
            "{:?}",
            plan.denies
        );
    }

    #[test]
    fn temp_arg_denied() {
        let plan = plan_for("git clone /Users/nobody/project /tmp/checkout", "deny");
        // /tmp/checkout is temp; the source is in-project — both flagged
        assert_eq!(plan.denies.len(), 2, "{:?}", plan.denies);
    }

    #[test]
    fn flag_attached_in_project_path_denied() {
        let plan = plan_for("rg foo --path=/Users/nobody/project/src", "deny");
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
    }

    #[test]
    fn relative_paths_untouched() {
        // already relative — nothing to nag about
        for cmd in [
            "grep -c \"\" apps/courier/src/register/onboarding-flow.ts",
            "cat src/main.rs",
            "cargo build",
            "ls ./scripts",
        ] {
            assert!(plan_for(cmd, "deny").denies.is_empty(), "flagged: {cmd}");
        }
    }

    #[test]
    fn outside_project_left_to_jail() {
        // /etc/passwd is outside and not temp — abspath ignores it (jail's job)
        assert!(plan_for("cat /etc/passwd", "deny").denies.is_empty());
    }

    #[test]
    fn dynamic_value_ignored() {
        // $HOME/... resolves at runtime; abspath only reasons about literals
        assert!(plan_for("cat $HOME/.ssh/config", "deny").denies.is_empty());
        assert!(
            plan_for("D=$TMPDIR/x cargo build", "deny")
                .denies
                .is_empty()
        );
    }

    #[test]
    fn setting_channels() {
        let temp = "D=/tmp/x cargo build";
        assert_eq!(plan_for(temp, "ask").asks.len(), 1);
        assert_eq!(plan_for(temp, "warn").hints.len(), 1);
        assert!(plan_for(temp, "off").denies.is_empty());
    }

    #[test]
    fn nested_shell_assignment_skipped() {
        // synthetic (inside bash -c) assignments aren't attributed here
        assert!(
            plan_for("bash -c 'D=/tmp/x cargo build'", "deny")
                .denies
                .is_empty()
        );
    }
}
