//! Built-in catalog bundles and merge logic. The catalog membership data lives in
//! `builtin.toml`; the config schema types (`Catalog`, `CatalogRule`) live in
//! `config.rs`. Add a bundle or reshuffle its members here.

use crate::config::{Action, Catalog};
use std::collections::HashMap;

const READ_CATALOGS: &[(&str, Option<Action>)] = &[
    ("shell-core", None),
    ("fs-read", None),
    ("text-read", None),
    ("sysinfo", None),
    ("proc-read", None),
    ("net-query", None),
    ("git-read", None),
    ("gh-read", None),
    ("docker-read", None),
    ("kubectl-read", None),
    ("helm-read", None),
    ("tf-read", None),
    ("svc-read", None),
    ("pkg-query", None),
    ("kv-cache", None),
    ("search-nudge", None),
];

const RECOMMENDED_EXTRA: &[(&str, Option<Action>)] = &[
    ("net-egress", None),
    ("mutating", None),
    ("pkg-install", None),
    ("secrets-read", None),
    ("destructive", None),
    ("obfuscation", None),
    ("gtfobins", None),
];

const PARANOID_EXTRA: &[(&str, Option<Action>)] = &[
    ("net-egress", Some(Action::Deny)),
    ("mutating", Some(Action::Deny)),
    ("pkg-install", None),
    ("secrets-read", None),
    ("destructive", None),
    ("obfuscation", None),
    ("gtfobins", None),
    ("interactive", None),
];

pub fn bundle_members(name: &str) -> Option<Vec<(&'static str, Option<Action>)>> {
    match name {
        "read-only" => Some(READ_CATALOGS.to_vec()),
        "recommended" => Some([READ_CATALOGS, RECOMMENDED_EXTRA].concat()),
        "paranoid" => Some([READ_CATALOGS, PARANOID_EXTRA].concat()),
        _ => None,
    }
}

pub fn builtin_catalogs() -> Result<HashMap<String, Catalog>, String> {
    #[derive(serde::Deserialize)]
    struct CatalogFile {
        catalog: HashMap<String, Catalog>,
    }
    toml::from_str::<CatalogFile>(include_str!("builtin.toml"))
        .map(|f| f.catalog)
        .map_err(|e| format!("built-in catalogs: {e}"))
}

// user block overlays a built-in: user fields win, empty ones fall back to the base
pub fn merge_catalog(base: Option<Catalog>, user: Catalog) -> Catalog {
    let Some(base) = base else {
        return user;
    };
    Catalog {
        patterns: if user.patterns.is_empty() {
            base.patterns
        } else {
            user.patterns
        },
        add: user.add,
        remove: user.remove,
        rules: if user.rules.is_empty() {
            base.rules
        } else {
            user.rules
        },
        action: user.action.or(base.action),
        reason: user.reason.or(base.reason),
        rewrite: user.rewrite.or(base.rewrite),
        hint: user.hint.or(base.hint),
        wrap: user.wrap.or(base.wrap),
        pipe: user.pipe.or(base.pipe),
        max_lines: user.max_lines.or(base.max_lines),
        min_lines: user.min_lines.or(base.min_lines),
        preserve: user.preserve.or(base.preserve),
        modes: if user.modes.is_empty() {
            base.modes
        } else {
            user.modes
        },
    }
}
