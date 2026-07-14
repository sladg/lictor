// Integration tests for hint-retry on removed_pattern and required_pattern rules.
// Uses real session state (temp dir) and engine::evaluate end-to-end.

use lictor::config::Config;
use lictor::engine::evaluate;
use lictor::hook::HookInput;
use serde_json::{Value, json};

fn config_with_state(toml: &str, state_dir: &std::path::Path) -> Config {
    let log = state_dir.join("audit.jsonl");
    let merged = format!("[settings]\nlog_file = \"{}\"\n\n{toml}", log.display());
    let mut config: Config = toml::from_str(&merged).expect("config parses");
    config.finalize().expect("catalogs expand");
    config
}

fn edit_input(session: &str, path: &str, old: &str, new: &str) -> HookInput {
    serde_json::from_value(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": path,
            "old_string": old,
            "new_string": new,
        },
        "session_id": session,
        "cwd": "/tmp/test-project",
    }))
    .unwrap()
}

fn write_input(session: &str, path: &str, content: &str) -> HookInput {
    serde_json::from_value(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": path,
            "content": content,
        },
        "session_id": session,
        "cwd": "/tmp/test-project",
    }))
    .unwrap()
}

fn hint(out: &Option<Value>) -> Option<String> {
    out.as_ref()?
        .pointer("/hookSpecificOutput/additionalContext")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn decision(out: &Option<Value>) -> Option<String> {
    out.as_ref()?
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lictor-edit-retry-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── removed_pattern hint-retry ────────────────────────────────────────────────

const TSDOC_RETRY: &str = r#"
[[edit]]
paths = ["**/*.ts"]
removed_pattern = "(?s)/\\*\\*.*?\\*/"
action = "warn"
hint = "lictor: do not remove doc-comments"
retry_count = 2
retry_window = 300
"#;

#[test]
fn hint_fires_twice_then_silent_on_third() {
    let dir = temp("tsdoc-retry");
    let config = config_with_state(TSDOC_RETRY, &dir);

    let old = "/** Fetches the user. */\nexport function getUser(id: string) {}";
    let new = "export function getUser(id: string) {}";
    let path = "/tmp/test-project/src/api.ts";

    // call 1: hint fires (count 0 < 2 → bump to 1)
    let out1 = evaluate(&edit_input("sess-1", path, old, new), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out1).is_some(), "call 1: hint expected");

    // call 2: hint fires again (count 1 < 2 → bump to 2)
    let out2 = evaluate(&edit_input("sess-1", path, old, new), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out2).is_some(), "call 2: hint expected");

    // call 3: count 2 >= threshold 2 → hint suppressed, counter reset
    let out3 = evaluate(&edit_input("sess-1", path, old, new), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out3).is_none(), "call 3: hint must be suppressed");

    // call 4: counter was reset → hint fires again
    let out4 = evaluate(&edit_input("sess-1", path, old, new), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out4).is_some(), "call 4: hint restarts after reset");
}

#[test]
fn hint_retry_is_per_session() {
    let dir = temp("tsdoc-session-iso");
    let config = config_with_state(TSDOC_RETRY, &dir);

    let old = "/** Doc. */\nexport function foo() {}";
    let new = "export function foo() {}";
    let path = "/tmp/test-project/src/api.ts";

    // exhaust session A
    evaluate(&edit_input("sess-a", path, old, new), &config);
    evaluate(&edit_input("sess-a", path, old, new), &config);
    let out_a = evaluate(&edit_input("sess-a", path, old, new), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out_a).is_none(), "sess-a: hint suppressed");

    // session B is independent — should still get hint on first call
    let out_b = evaluate(&edit_input("sess-b", path, old, new), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(
        hint(&out_b).is_some(),
        "sess-b: independent counter, hint fires"
    );
}

// ── required_pattern hint-retry on MD writes ──────────────────────────────────

const MD_REQUIRED_RETRY: &str = r#"
[[edit]]
paths = ["**/*.md"]
required_pattern = "created_at:"
action = "warn"
hint = "lictor: markdown files must include 'created_at:' frontmatter"
retry_count = 2
retry_window = 300
"#;

#[test]
fn required_pattern_hint_fires_twice_then_silent() {
    let dir = temp("md-required-retry");
    let config = config_with_state(MD_REQUIRED_RETRY, &dir);

    let content = "# My Note\n\nNo frontmatter here.";
    let path = "/tmp/test-project/docs/guide.md";

    let out1 = evaluate(&write_input("sess-md", path, content), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out1).is_some(), "call 1: hint expected");

    let out2 = evaluate(&write_input("sess-md", path, content), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out2).is_some(), "call 2: hint expected");

    let out3 = evaluate(&write_input("sess-md", path, content), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out3).is_none(), "call 3: hint must be suppressed");
}

#[test]
fn required_pattern_no_hint_when_satisfied() {
    let dir = temp("md-required-satisfied");
    let config = config_with_state(MD_REQUIRED_RETRY, &dir);

    let content = "---\ncreated_at: 2026-07-14\nauthor: jan\n---\n\n# My Note";
    let path = "/tmp/test-project/docs/guide.md";

    let out = evaluate(&write_input("sess-md-ok", path, content), &config)
        .map(|o| serde_json::to_value(o).unwrap());
    assert!(hint(&out).is_none(), "created_at present — no hint");
    assert!(decision(&out).is_none(), "no block");
}
