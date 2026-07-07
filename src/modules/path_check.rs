use super::Plan;
use crate::bash::Extraction;
use crate::config::{ActivateRule, Config, ModuleSetting};
use std::path::Path;

// fail fast on guaranteed "command not found": program words that resolve to
// nothing on PATH, and unquoted `=name` words that zsh equals-expands into a
// PATH lookup (`echo ===` dies with "== not found"). Aliases and functions
// from the user's rc files are invisible here — drop to "warn" if they misfire.

pub fn plan(extraction: &Extraction, config: &Config, cwd: Option<&str>, out: &mut Plan) {
    let setting = match config.modules.get("path-check") {
        Some(s) if *s != ModuleSetting::Off => *s,
        _ => return,
    };
    let zsh = std::env::var("SHELL").is_ok_and(|s| s.ends_with("zsh"));
    check(extraction, &config.activate, cwd, zsh, setting, out);
}

fn check(
    extraction: &Extraction,
    rules: &[ActivateRule],
    cwd: Option<&str>,
    zsh: bool,
    setting: ModuleSetting,
    out: &mut Plan,
) {
    let mut seen: Vec<String> = Vec::new();
    for command in &extraction.commands {
        let Some(program) = command.words.first().and_then(|w| w.text.as_deref()) else {
            continue;
        };
        // paths are strip_program_paths'/jail's concern; a path may also be a
        // build artifact that only exists once an earlier chain link ran
        if program.contains('/')
            || crate::constants::SHELL_BUILTINS.contains(&program)
            || extraction.functions.iter().any(|f| f == program)
            || seen.iter().any(|s| s == program)
            || on_path(program)
        {
            continue;
        }
        seen.push(program.to_string());
        let activate = activate_hint(program, rules, cwd).unwrap_or_default();
        push(
            out,
            setting,
            format!(
                "lictor: `{program}` is not on PATH — this command would fail with 'command not found'{activate}"
            ),
        );
    }
    if zsh {
        check_equals_expansion(extraction, setting, out);
    }
}

// zsh expands an unquoted word starting with `=` to the full path of the named
// command and aborts the whole line when it doesn't exist (`echo ===` → the
// shell looks up `==`). Only literal, unquoted, non-synthetic words qualify —
// the source span tells quoted (`'==='`) apart from bare.
fn check_equals_expansion(extraction: &Extraction, setting: ModuleSetting, out: &mut Plan) {
    let mut seen: Vec<String> = Vec::new();
    let words = extraction
        .commands
        .iter()
        .filter(|c| !c.synthetic)
        .flat_map(|c| c.words.iter().skip(1));
    for word in words {
        let Some(text) = word.text.as_deref() else {
            continue;
        };
        let Some(name) = text.strip_prefix('=').filter(|n| !n.is_empty()) else {
            continue;
        };
        let unquoted = extraction
            .source
            .get(word.start..word.end)
            .is_some_and(|s| s.starts_with('='));
        if !unquoted || seen.iter().any(|s| s == text) || on_path(name) {
            continue;
        }
        seen.push(text.to_string());
        push(
            out,
            setting,
            format!(
                "lictor: unquoted `{text}` triggers zsh =cmd expansion — the shell looks up `{name}` on PATH and aborts with '{name} not found'; quote it as '{text}' or drop it"
            ),
        );
    }
}

pub fn on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return true; // no PATH visible: can't judge, stay silent
    };
    std::env::split_paths(&path).any(|dir| is_executable(&dir.join(name)))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

// a managed tool that is missing because the toolchain isn't activated gets the
// activation command inline, instead of a dead-end deny
fn activate_hint(program: &str, rules: &[ActivateRule], cwd: Option<&str>) -> Option<String> {
    let cwd = cwd?;
    rules
        .iter()
        .find(|r| {
            Path::new(cwd).join(&r.file).exists()
                && (r.tools.is_empty() || r.tools.iter().any(|t| t == program))
        })
        .map(|r| {
            format!(
                " — this project pins toolchains via `{}`; run `{}` first, then retry",
                r.file, r.run
            )
        })
}

fn push(out: &mut Plan, setting: ModuleSetting, message: String) {
    match setting {
        ModuleSetting::Deny => out.denies.push(message),
        ModuleSetting::Ask => out.asks.push(message),
        ModuleSetting::Warn => out.hints.push(message),
        ModuleSetting::Rewrite | ModuleSetting::Off | ModuleSetting::Allow => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    const MISSING: &str = "lictor-test-definitely-not-a-real-cmd";

    fn plan_for(command: &str, setting: ModuleSetting, zsh: bool) -> Plan {
        let mut plan = Plan::default();
        check(&bash::extract(command), &[], None, zsh, setting, &mut plan);
        plan
    }

    fn denies(command: &str) -> Vec<String> {
        plan_for(command, ModuleSetting::Deny, true).denies
    }

    #[test]
    fn missing_program_denied() {
        let denies = denies(&format!("{MISSING} --flag"));
        assert_eq!(denies.len(), 1, "{denies:?}");
        assert!(denies[0].contains(MISSING) && denies[0].contains("not on PATH"));
    }

    #[test]
    fn resolved_programs_pass() {
        assert!(denies("ls -la && cat Cargo.toml | tail -1").is_empty());
    }

    #[test]
    fn builtins_and_functions_skipped() {
        assert!(denies("cd /x && export A=1 && echo done").is_empty());
        assert!(denies("f() { ls; }; f").is_empty());
    }

    #[test]
    fn program_paths_skipped() {
        // ./script.sh may be a build artifact of an earlier chain link
        assert!(denies("./not-built-yet.sh && /opt/none/tool run").is_empty());
    }

    #[test]
    fn wrapper_stripped_target_checked_once() {
        let denies = denies(&format!("sudo {MISSING} install"));
        assert_eq!(denies.len(), 1, "{denies:?}");
    }

    #[test]
    fn nested_shell_program_checked() {
        assert_eq!(denies(&format!("bash -c '{MISSING} run'")).len(), 1);
    }

    #[test]
    fn equals_expansion_flagged_on_zsh_only() {
        let denies = denies("echo === && ls");
        assert_eq!(denies.len(), 1, "{denies:?}");
        assert!(denies[0].contains("=cmd expansion") && denies[0].contains("`==`"));
        assert!(
            plan_for("echo === && ls", ModuleSetting::Deny, false)
                .denies
                .is_empty()
        );
    }

    #[test]
    fn quoted_or_resolving_equals_passes() {
        assert!(denies("echo '==='").is_empty());
        assert!(denies("echo \"===\"").is_empty());
        // =ls resolves, expansion succeeds — intentional zsh use
        assert!(denies("echo =ls").is_empty());
        // --flag=value never triggers equals expansion
        assert!(denies("cargo build --message-format=json").is_empty());
    }

    #[test]
    fn missing_managed_tool_gets_activation_hint() {
        let dir = std::env::temp_dir().join(format!("lictor-pathcheck-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".prototools"), "node = \"22\"\n").unwrap();
        let rules = [ActivateRule {
            file: ".prototools".into(),
            run: "proto use".into(),
            tools: vec![MISSING.into()],
        }];
        let mut plan = Plan::default();
        check(
            &bash::extract(&format!("{MISSING} run check")),
            &rules,
            dir.to_str(),
            false,
            ModuleSetting::Deny,
            &mut plan,
        );
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
        assert!(plan.denies[0].contains("proto use"), "{:?}", plan.denies);
    }

    #[test]
    fn setting_channels() {
        let cmd = format!("{MISSING} run");
        assert_eq!(plan_for(&cmd, ModuleSetting::Ask, false).asks.len(), 1);
        assert_eq!(plan_for(&cmd, ModuleSetting::Warn, false).hints.len(), 1);
    }
}
