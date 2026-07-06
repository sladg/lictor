use super::Plan;
use crate::bash::{Command, Extraction, basename};
use crate::config::{Config, ModuleSetting};
use crate::rules::SpanEdit;

// monorepo hygiene: `cd pkg && bun run lint` changes the shell cwd to run a
// package task; every package manager has a root-level flag for that. The
// exact two-command shape is rewritten; anything more complex gets the hint.

const PMS: &[(&str, &str)] = &[
    ("bun", "--cwd"),
    ("pnpm", "-C"),
    ("npm", "--prefix"),
    ("yarn", "--cwd"),
];

fn is_cd(command: &Command) -> bool {
    command
        .words
        .first()
        .and_then(|w| w.text.as_deref())
        .is_some_and(|t| t == "cd")
}

fn pm_flag(command: &Command) -> Option<(&'static str, &'static str)> {
    let program = command.words.first()?.text.as_deref()?;
    PMS.iter().find(|(pm, _)| *pm == basename(program)).copied()
}

pub fn plan(extraction: &Extraction, config: &Config, out: &mut Plan) {
    let setting = match config.modules.get("pm-cwd") {
        Some(s) if *s != ModuleSetting::Off => *s,
        _ => return,
    };
    let commands = &extraction.commands;
    let Some(cd_idx) = commands.iter().position(|c| !c.synthetic && is_cd(c)) else {
        return;
    };
    let Some((pm_idx, (pm, flag))) = commands
        .iter()
        .enumerate()
        .skip(cd_idx + 1)
        .find_map(|(i, c)| (!c.synthetic).then(|| pm_flag(c)).flatten().map(|f| (i, f)))
    else {
        return;
    };
    let cd = &commands[cd_idx];
    let pm_cmd = &commands[pm_idx];
    // literal single-arg cd; anything else (flags, dynamic dir) blocks the rewrite
    let dir = (cd.words.len() == 2)
        .then(|| cd.words[1].text.as_deref())
        .flatten()
        .filter(|d| !d.chars().any(char::is_whitespace));
    let message = format!(
        "lictor: don't `cd` into a package to run {pm} — run from the repo root: `{pm} {flag} {} …`",
        dir.unwrap_or("<dir>")
    );
    match setting {
        ModuleSetting::Rewrite => {
            if let (2, 1, Some(dir)) = (commands.len(), pm_idx, dir) {
                out.edits.push(SpanEdit {
                    start: cd.words[0].start,
                    end: pm_cmd.words[0].end,
                    text: format!("{pm} {flag} {dir}"),
                });
                out.hints.push(format!(
                    "lictor: rewrote `cd {dir} && {pm} …` to `{pm} {flag} {dir} …` — run package tasks from the repo root"
                ));
            } else {
                // a longer chain can't be rewritten mechanically; teach instead
                out.hints.push(message);
            }
        }
        ModuleSetting::Warn => out.hints.push(message),
        ModuleSetting::Ask => out.asks.push(message),
        ModuleSetting::Deny => out.denies.push(message),
        ModuleSetting::Off => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;
    use crate::rules::apply_edits;

    fn plan_for(command: &str, setting: &str) -> Plan {
        let config: Config = toml::from_str(&format!("[modules]\npm-cwd = \"{setting}\""))
            .expect("test config parses");
        let mut plan = Plan::default();
        super::plan(&bash::extract(command), &config, &mut plan);
        plan
    }

    fn rewritten(command: &str) -> String {
        apply_edits(command, &plan_for(command, "rewrite").edits)
    }

    #[test]
    fn rewrites_each_package_manager() {
        assert_eq!(
            rewritten("cd monorepo/pkg && bun run lint"),
            "bun --cwd monorepo/pkg run lint"
        );
        assert_eq!(rewritten("cd pkg; pnpm run build"), "pnpm -C pkg run build");
        assert_eq!(rewritten("cd pkg && npm test"), "npm --prefix pkg test");
        assert_eq!(rewritten("cd pkg && yarn lint"), "yarn --cwd pkg lint");
    }

    #[test]
    fn longer_chain_hints_instead() {
        let plan = plan_for("cd pkg && bun install && bun run lint", "rewrite");
        assert!(plan.edits.is_empty());
        assert_eq!(plan.hints.len(), 1);
        assert!(plan.hints[0].contains("--cwd pkg"));
    }

    #[test]
    fn dynamic_dir_hints_instead() {
        let plan = plan_for("cd $PKG && bun run lint", "rewrite");
        assert!(plan.edits.is_empty());
        assert!(plan.hints[0].contains("<dir>"));
    }

    #[test]
    fn ask_and_deny_fill_channels() {
        assert_eq!(plan_for("cd pkg && bun run lint", "ask").asks.len(), 1);
        assert_eq!(plan_for("cd pkg && pnpm test", "deny").denies.len(), 1);
    }

    #[test]
    fn unrelated_commands_untouched() {
        assert!(
            plan_for("cd pkg && cargo build", "rewrite")
                .hints
                .is_empty()
        );
        assert!(plan_for("bun run lint && cd pkg", "deny").denies.is_empty());
        assert!(plan_for("bun --cwd pkg run lint", "deny").denies.is_empty());
    }

    #[test]
    fn nested_shell_skipped() {
        assert!(
            plan_for("bash -c 'cd pkg && bun run lint'", "deny")
                .denies
                .is_empty()
        );
    }
}
