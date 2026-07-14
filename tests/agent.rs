use lictor::config::Config;
use lictor::engine::evaluate;
use lictor::hook::HookInput;
use serde_json::{Value, json};

fn run(policy: &str, input: Value) -> Option<Value> {
    let config: Config = toml::from_str(policy).expect("test policy parses");
    let mut config = config.apply_mode(None);
    config.finalize().expect("config finalizes");
    let hook: HookInput = serde_json::from_value(input).unwrap();
    evaluate(&hook, &config).map(|o| serde_json::to_value(o).unwrap()["hookSpecificOutput"].take())
}

const POLICY: &str = r#"
[[agent]]
pattern = "(?i)comprehensive analysis"
on = "output"
action = "warn"
hint = "subagent output smells like filler"

[[agent]]
pattern = "(?i)delete all"
on = "prompt"
action = "deny"
reason = "destructive subagent prompt"
"#;

#[test]
fn agent_prompt_deny_blocks_launch() {
    let output = run(
        POLICY,
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_input": {"prompt": "please delete all failing tests", "description": "cleanup"},
        }),
    );
    let out = output.unwrap();
    assert_eq!(out["permissionDecision"], "deny");
    assert_eq!(
        out["permissionDecisionReason"],
        "destructive subagent prompt"
    );
}

#[test]
fn agent_prompt_clean_no_opinion() {
    let output = run(
        POLICY,
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Agent",
            "tool_input": {"prompt": "list the exported symbols in src/lib.rs"},
        }),
    );
    assert!(output.is_none());
}

#[test]
fn agent_output_match_hints() {
    let output = run(
        POLICY,
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Task",
            "tool_input": {"prompt": "review the module"},
            "tool_response": {"content": [{"type": "text", "text": "Here is a Comprehensive Analysis of the module."}]},
        }),
    );
    let out = output.unwrap();
    assert!(
        out["additionalContext"]
            .as_str()
            .unwrap()
            .contains("filler")
    );
}

#[test]
fn agent_output_clean_no_hint() {
    let output = run(
        POLICY,
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Task",
            "tool_input": {"prompt": "review the module"},
            "tool_response": {"content": [{"type": "text", "text": "Two bugs: line 14 off-by-one, line 90 unwrap."}]},
        }),
    );
    assert!(output.is_none());
}
