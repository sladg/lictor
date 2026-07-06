use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: Value,
    #[serde(default)]
    pub tool_response: Option<Value>,
    // PostToolUseFailure: e.g. "Command exited with non-zero status code 127"
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    // PostToolUse: tool execution time, excludes permission prompts and hooks
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_tool_output: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

impl HookOutput {
    pub fn new(event: &str) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: event.to_string(),
                ..Default::default()
            },
        }
    }
}
