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

const ASK_POLICY: &str = r#"
[[bash]]
match = "git push*"
action = "ask"
reason = "Pushing needs a look."
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
