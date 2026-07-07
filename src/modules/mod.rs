// dynamic modules: context-aware checks backed by read-only probes.
// git_wrap and pm_cwd plan command rewrites before gating; jail and strikes
// hook into the gate and the engine; activate hints after a not-found failure;
// path_check stops guaranteed not-found commands before they run;
// recreate flags delete+rewrite done instead of a rename;
// self_rm tracks session-created paths so their own rm/git rm skips the ask;
// retry_allow counts denies-per-rule so a deny-then-allow rule flips to
// allow once its retry_count is spent within retry_window.
// One module per file, tests included.
pub mod abspath;
pub mod activate;
pub mod git_wrap;
pub mod jail;
pub mod path_check;
pub mod pm_cwd;
pub mod recreate;
pub mod retry_allow;
pub mod self_rm;
pub mod strikes;

pub use git_wrap::git_tracked;
pub use path_check::on_path;

use crate::bash::Extraction;
use crate::config::{Config, ModuleSetting};
use crate::rules::SpanEdit;
use std::path::PathBuf;

// what the planning modules want done to the command before it is gated:
// edits rewrite it, hints reach the model, asks/denies become the decision
#[derive(Default)]
pub struct Plan {
    pub edits: Vec<SpanEdit>,
    pub hints: Vec<String>,
    pub asks: Vec<String>,
    pub denies: Vec<String>,
}

pub fn plan(
    extraction: &Extraction,
    config: &Config,
    cwd: Option<&str>,
    tracked: &dyn Fn(&[String]) -> bool,
) -> Plan {
    let mut plan = git_wrap::plan(extraction, config, tracked);
    pm_cwd::plan(extraction, config, &mut plan);
    abspath::plan(extraction, config, cwd, &mut plan);
    path_check::plan(extraction, config, cwd, &mut plan);
    plan
}

// [modules] namespace with the settings each entry accepts
const ALLOWED: &[(&str, &[ModuleSetting])] = &[
    (
        "git-mv",
        &[
            ModuleSetting::Off,
            ModuleSetting::Warn,
            ModuleSetting::Rewrite,
        ],
    ),
    (
        "git-rm",
        &[
            ModuleSetting::Off,
            ModuleSetting::Warn,
            ModuleSetting::Rewrite,
        ],
    ),
    (
        "delete-recreate",
        &[
            ModuleSetting::Off,
            ModuleSetting::Warn,
            ModuleSetting::Ask,
            ModuleSetting::Deny,
        ],
    ),
    (
        "self-rm",
        &[
            ModuleSetting::Off,
            ModuleSetting::Warn,
            ModuleSetting::Allow,
        ],
    ),
    (
        "pm-cwd",
        &[
            ModuleSetting::Off,
            ModuleSetting::Warn,
            ModuleSetting::Rewrite,
            ModuleSetting::Ask,
            ModuleSetting::Deny,
        ],
    ),
    (
        "abs-paths",
        &[
            ModuleSetting::Off,
            ModuleSetting::Warn,
            ModuleSetting::Ask,
            ModuleSetting::Deny,
        ],
    ),
    (
        "path-check",
        &[
            ModuleSetting::Off,
            ModuleSetting::Warn,
            ModuleSetting::Ask,
            ModuleSetting::Deny,
        ],
    ),
];

pub fn validate(name: &str, setting: ModuleSetting) -> Result<(), String> {
    let (_, allowed) = ALLOWED
        .iter()
        .find(|(n, _)| *n == name)
        .ok_or(format!("unknown module '{name}'"))?;
    if !allowed.contains(&setting) {
        return Err(format!(
            "module '{name}' does not support setting '{setting:?}'"
        ));
    }
    Ok(())
}

// per-session module state lives next to the audit log, or under XDG state
pub(super) fn state_dir(config: &Config, cwd: Option<&str>) -> Option<PathBuf> {
    match config.log_path(cwd) {
        Some(log) => Some(log.parent()?.to_path_buf()),
        None => {
            let home = std::env::var("HOME").ok()?;
            let base = std::env::var("XDG_STATE_HOME").unwrap_or(format!("{home}/.local/state"));
            Some(PathBuf::from(base).join("lictor"))
        }
    }
}
