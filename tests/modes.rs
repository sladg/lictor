use lictor::config::Config;
use lictor::engine::evaluate;
use lictor::hook::HookInput;
use serde_json::{Value, json};

// mirrors run_with in tests/commands.rs, but resolves a [modes.<mode>] overlay
// (Config::apply_mode) before finalizing, the way config::load does for real hooks
fn run(policy: &str, mode: Option<&str>, command: &str) -> Option<Value> {
    let config: Config = toml::from_str(policy).expect("test policy parses");
    let mut config = config.apply_mode(mode);
    config.finalize().expect("config finalizes");
    let input: HookInput = serde_json::from_value(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "permission_mode": mode,
    }))
    .unwrap();
    evaluate(&input, &config).map(|o| serde_json::to_value(o).unwrap()["hookSpecificOutput"].take())
}

fn decision(output: &Option<Value>) -> Option<String> {
    output
        .as_ref()?
        .get("permissionDecision")?
        .as_str()
        .map(str::to_string)
}

fn hint(output: &Option<Value>) -> Option<String> {
    output
        .as_ref()?
        .get("additionalContext")?
        .as_str()
        .map(str::to_string)
}

const OVERLAY_POLICY: &str = r#"
[[bash]]
match = "curl*"
action = "allow"

[[modes.auto.bash]]
match = "curl*"
action = "deny"
reason = "auto mode: no curl without review"
"#;

#[test]
fn mode_overlay_rule_appends_and_wins_as_most_restrictive() {
    // no mode selected: only the base allow rule applies
    let output = run(OVERLAY_POLICY, None, "curl https://example.com");
    assert_eq!(decision(&output), Some("allow".to_string()));
}

#[test]
fn mode_overlay_rule_applies_only_in_its_own_mode() {
    // auto: the overlay's deny rule is appended and outranks the base allow
    let output = run(OVERLAY_POLICY, Some("auto"), "curl https://example.com");
    assert_eq!(decision(&output), Some("deny".to_string()));
}

#[test]
fn mode_overlay_ignored_for_a_different_mode() {
    // a declared [modes.auto] block must not leak into other modes
    let output = run(
        OVERLAY_POLICY,
        Some("acceptEdits"),
        "curl https://example.com",
    );
    assert_eq!(decision(&output), Some("allow".to_string()));
}

const SETTINGS_OVERLAY_POLICY: &str = r#"
[settings]
on_dangerous_env = "warn"

[modes.auto.settings]
on_dangerous_env = "deny"
"#;

#[test]
fn mode_overlay_settings_scalar_overrides_base() {
    let cmd = "LD_PRELOAD=/tmp/x.so ls";

    // base: warn only, no decision
    let output = run(SETTINGS_OVERLAY_POLICY, None, cmd);
    assert_eq!(decision(&output), None);
    assert!(hint(&output).is_some_and(|h| h.contains("LD_PRELOAD")));

    // auto: the overlay's scalar setting replaces the base one
    let output = run(SETTINGS_OVERLAY_POLICY, Some("auto"), cmd);
    assert_eq!(decision(&output), Some("deny".to_string()));
}

// the shipped default.toml declares this remap; the hardcoded auto special-case
// is gone — the mechanism is config all the way down
const ASK_POLICY: &str = r#"
[[bash]]
match = "git push*"
action = "ask"
reason = "Pushing needs a look."

[modes.auto.remap]
ask = "deny"
"#;

#[test]
fn auto_mode_downgrades_ask_to_deny() {
    let output = run(ASK_POLICY, None, "git push");
    assert_eq!(decision(&output), Some("ask".to_string()));

    let output = run(ASK_POLICY, Some("auto"), "git push");
    assert_eq!(decision(&output), Some("deny".to_string()));
    let reason = output
        .as_ref()
        .and_then(|o| o.get("permissionDecisionReason"))
        .and_then(Value::as_str)
        .unwrap();
    assert!(reason.contains("Pushing needs a look."));
    assert!(reason.contains("auto mode"));
}

#[test]
fn other_modes_keep_ask_as_is() {
    for mode in [None, Some("default"), Some("bypassPermissions")] {
        let output = run(ASK_POLICY, mode, "git push");
        assert_eq!(decision(&output), Some("ask".to_string()), "mode: {mode:?}");
    }
}

// ── per-rule modes map: one pattern, mode-specific actions ────────────────────

const PER_RULE_POLICY: &str = r#"
[[bash]]
match = "cargo test*"
action = "allow"
modes = { plan = "deny", acceptEdits = "ask" }
"#;

#[test]
fn per_rule_modes_map_overrides_action_per_mode() {
    let output = run(PER_RULE_POLICY, None, "cargo test");
    assert_eq!(decision(&output), Some("allow".to_string()));

    let output = run(PER_RULE_POLICY, Some("plan"), "cargo test");
    assert_eq!(decision(&output), Some("deny".to_string()));

    let output = run(PER_RULE_POLICY, Some("acceptEdits"), "cargo test");
    assert_eq!(decision(&output), Some("ask".to_string()));

    // a mode not listed in the map keeps the base action
    let output = run(PER_RULE_POLICY, Some("auto"), "cargo test");
    assert_eq!(decision(&output), Some("allow".to_string()));
}

#[test]
fn catalog_modes_map_flows_into_expanded_rules() {
    let policy = r#"
[catalog.git-read]
action = "allow"
modes = { plan = "ask" }
"#;
    let output = run(policy, None, "git status");
    assert_eq!(decision(&output), Some("allow".to_string()));

    let output = run(policy, Some("plan"), "git status");
    assert_eq!(decision(&output), Some("ask".to_string()));
}

// ── default_bash: allowlist lockdown ──────────────────────────────────────────

const LOCKDOWN_POLICY: &str = r#"
[[bash]]
match = "git status*"
action = "allow"

[modes.plan.settings]
default_bash = "deny"
"#;

#[test]
fn default_bash_denies_unmatched_commands_in_mode() {
    // outside the mode: no rule matched -> no opinion (Claude Code decides)
    let output = run(LOCKDOWN_POLICY, None, "cargo build");
    assert_eq!(decision(&output), None);

    // in plan mode the fallback closes the hole
    let output = run(LOCKDOWN_POLICY, Some("plan"), "cargo build");
    assert_eq!(decision(&output), Some("deny".to_string()));

    // explicit allow rules still pass
    let output = run(LOCKDOWN_POLICY, Some("plan"), "git status");
    assert_eq!(decision(&output), Some("allow".to_string()));
}

// ── remap: warn -> skip drops hints ───────────────────────────────────────────

#[test]
fn remap_warn_skip_suppresses_hints() {
    let policy = r#"
[[bash]]
match = "curl*"
action = "warn"
hint = "Prefer the project HTTP client."

[modes.auto.remap]
warn = "skip"
"#;
    let output = run(policy, None, "curl https://example.com");
    assert!(hint(&output).is_some_and(|h| h.contains("HTTP client")));

    let output = run(policy, Some("auto"), "curl https://example.com");
    assert_eq!(hint(&output), None);
}

// ── mode_aliases: harness renames a mode, config maps it back ─────────────────

#[test]
fn mode_alias_resolves_overlay_per_rule_map_and_remap() {
    let policy = r#"
[settings]
mode_aliases = { unattended = "auto" }

[[bash]]
match = "cargo test*"
action = "allow"
modes = { auto = "deny" }

[[bash]]
match = "git push*"
action = "ask"

[modes.auto.remap]
ask = "deny"
"#;
    // the harness sends the new name; everything keyed on "auto" still fires
    let output = run(policy, Some("unattended"), "cargo test");
    assert_eq!(decision(&output), Some("deny".to_string()));
    let output = run(policy, Some("unattended"), "git push");
    assert_eq!(decision(&output), Some("deny".to_string()));

    // the config name itself keeps working
    let output = run(policy, Some("auto"), "cargo test");
    assert_eq!(decision(&output), Some("deny".to_string()));

    // unrelated modes untouched
    let output = run(policy, Some("plan"), "cargo test");
    assert_eq!(decision(&output), Some("allow".to_string()));
}

#[test]
fn remap_ask_to_warn_demotes_decision_to_hint() {
    let policy = r#"
[[bash]]
match = "git push*"
action = "ask"
reason = "Pushing needs a look."

[modes.acceptEdits.remap]
ask = "warn"
"#;
    let output = run(policy, Some("acceptEdits"), "git push");
    assert_eq!(decision(&output), None);
    assert!(hint(&output).is_some_and(|h| h.contains("Pushing needs a look.")));
}
