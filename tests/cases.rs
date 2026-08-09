//! Declarative test cases — issue #10.
//!
//! Every `tests/cases/*.toml` file is a policy plus a list of tool calls and
//! what lictor should decide about each. This runner discovers and executes
//! them; adding a case means adding four lines of data, not a `#[test] fn`, a
//! `const POLICY` and ten lines of boilerplate.
//!
//! TOML rather than YAML for one decisive reason: **lictor's config is already
//! TOML.** The policy is a native sub-table checked by the same parser the real
//! config uses, instead of an indented block scalar that nothing can lint.
//!
//! Keeping the policy inline also sidesteps lictor's own self-protection. A
//! harness that wrote a `$XDG_CONFIG_HOME/lictor/config.toml` fixture would be
//! blocked by the `[[path]]` rule in `src/default.toml:59-65` — correct
//! behaviour that has already forced three separate agents into three different
//! workarounds. A case file never writes a config-shaped path.
//!
//! # Format
//!
//! ```toml
//! name  = "what this file covers"    # optional, for failure messages
//! issue = 7                          # optional, the issue it pins
//!
//! [config]                           # the policy, exactly as in config.toml
//! [[config.bash]]
//! match   = "grep*"
//! action  = "rewrite"
//! rewrite = "rg"
//!
//! [[case]]
//! name    = "flag survives the rewrite"
//! command = "grep -n TODO src/main.rs"
//! expect  = { decision = "allow", command = "rg -n TODO src/main.rs" }
//! ```
//!
//! | field | meaning |
//! |---|---|
//! | `command` | shorthand for `tool = "Bash"`, `input = { command = … }` |
//! | `tool` + `input` | any other tool; `input` is the raw `tool_input` |
//! | `response` | `tool_response`, for `PostToolUse` cases |
//! | `event` | defaults to `PreToolUse` |
//! | `cwd`, `session_id` | literal values; omitted means the hook gets none |
//! | `expect.decision` | `allow` / `ask` / `deny`, or `none` to assert lictor stayed silent. Omitted means the decision is not asserted at all |
//! | `expect.command` | exact `updatedInput.command`; `"<unchanged>"` asserts the command was not rewritten |
//! | `expect.reason` | substring of `permissionDecisionReason` |
//! | `expect.hint` / `expect.no_hint` | substring that must / must not appear in `additionalContext` |
//!
//! `reason` and `hint` are **different output fields**, and which one a rule's
//! configured `hint` lands in depends on its action. A `deny` or `ask` rule
//! surfaces it as `permissionDecisionReason` — the text the user is shown when
//! the call is blocked — while `warn` surfaces it as `additionalContext`, a
//! nudge to the model that blocks nothing. Assert with `reason` for the former
//! and `hint` for the latter.
//!
//! Two deliberate strictnesses, because a data-driven harness fails silently in
//! ways a hand-written test does not:
//!
//! - **Unknown fields are errors.** A typo'd `expect.decison` would otherwise
//!   assert nothing while looking like it asserts something.
//! - **An empty `expect` is an error.** A case that checks nothing passes
//!   forever and hides the behaviour it was added to pin.

use lictor::config::Config;
use lictor::engine::evaluate;
use lictor::hook::HookInput;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseFile {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    issue: Option<u64>,
    #[serde(default)]
    config: Option<toml::Value>,
    #[serde(default)]
    case: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    input: Option<toml::Value>,
    #[serde(default)]
    response: Option<toml::Value>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    expect: Expect,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Expect {
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    hint: Option<String>,
    #[serde(default)]
    no_hint: Option<String>,
}

impl Expect {
    fn is_empty(&self) -> bool {
        self.decision.is_none()
            && self.command.is_none()
            && self.reason.is_none()
            && self.hint.is_none()
            && self.no_hint.is_none()
    }
}

#[test]
fn declarative_cases() {
    let files = case_files();
    assert!(
        !files.is_empty(),
        "no case files found in tests/cases — the runner would pass vacuously"
    );

    let mut failures = Vec::new();
    let mut ran = 0usize;
    for path in &files {
        let label = path.file_name().unwrap_or_default().to_string_lossy();
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{label}: cannot be read: {e}"));
        let file: CaseFile = match toml::from_str(&text) {
            Ok(file) => file,
            // a malformed case file is a hard stop, not a soft failure: every
            // case in it is silently missing otherwise
            Err(e) => panic!("{label}: does not parse as a case file: {e}"),
        };
        assert!(
            !file.case.is_empty(),
            "{label}: contains no [[case]] entries"
        );

        for (i, case) in file.case.iter().enumerate() {
            ran += 1;
            if let Err(problems) = run_case(&file, case) {
                let name = case
                    .name
                    .clone()
                    .or_else(|| case.command.clone())
                    .unwrap_or_else(|| format!("case #{}", i + 1));
                let issue = file.issue.map(|n| format!(" (#{n})")).unwrap_or_default();
                let heading = file.name.as_deref().unwrap_or(&label);
                failures.push(format!(
                    "── {label}: {heading}{issue}\n   case: {name}\n{}",
                    problems
                        .iter()
                        .map(|p| format!("     - {p}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {ran} declarative cases failed:\n\n{}\n",
        failures.len(),
        failures.join("\n\n")
    );
    println!(
        "{ran} declarative cases passed across {} files",
        files.len()
    );
}

fn case_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();
    files
}

/// Run one case, returning every assertion that did not hold rather than only
/// the first — a case with a wrong decision *and* a wrong rewrite should report
/// both, so one edit-and-rerun cycle fixes it.
fn run_case(file: &CaseFile, case: &Case) -> Result<(), Vec<String>> {
    if case.expect.is_empty() {
        return Err(vec![
            "`expect` is empty — a case that asserts nothing passes forever".to_string(),
        ]);
    }

    let (tool, tool_input) = match (&case.command, &case.tool) {
        (Some(command), None) => ("Bash".to_string(), json!({ "command": command })),
        (None, Some(tool)) => {
            let Some(input) = &case.input else {
                return Err(vec![format!("`tool = \"{tool}\"` needs an `input` table")]);
            };
            (tool.clone(), to_json(input))
        }
        (Some(_), Some(_)) => {
            return Err(vec![
                "sets both `command` and `tool` — use one or the other".to_string(),
            ]);
        }
        (None, None) => {
            return Err(vec![
                "sets neither `command` nor `tool` + `input`".to_string(),
            ]);
        }
    };

    let event = case.event.as_deref().unwrap_or("PreToolUse");
    let mut hook = json!({
        "hook_event_name": event,
        "tool_name": tool,
        "tool_input": tool_input,
    });
    if let Some(response) = &case.response {
        hook["tool_response"] = to_json(response);
    }
    if let Some(cwd) = &case.cwd {
        hook["cwd"] = json!(cwd);
    }
    if let Some(session) = &case.session_id {
        hook["session_id"] = json!(session);
    }

    let policy = file
        .config
        .clone()
        .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));
    let mut config: Config = match policy.try_into() {
        Ok(config) => config,
        Err(e) => return Err(vec![format!("[config] is not a valid policy: {e}")]),
    };
    let input: HookInput = match serde_json::from_value(hook) {
        Ok(input) => input,
        Err(e) => return Err(vec![format!("does not form a valid hook input: {e}")]),
    };

    // mirror run_hook: a config error fails closed on PreToolUse
    let output = match config.finalize() {
        Ok(()) => evaluate(&input, &config),
        Err(error) if event == "PreToolUse" => Some(lictor::engine::error_output(event, &error)),
        Err(_) => None,
    };
    let out: Option<Value> = output.map(|o| {
        let mut v = serde_json::to_value(o).expect("hook output serializes");
        v["hookSpecificOutput"].take()
    });

    let mut problems = Vec::new();
    let field = |key: &str| -> Option<String> {
        out.as_ref()?
            .get(key)?
            .as_str()
            .map(std::string::ToString::to_string)
    };
    let decision = field("permissionDecision");
    let reason = field("permissionDecisionReason");
    let context = field("additionalContext");
    let updated = out
        .as_ref()
        .and_then(|o| o.pointer("/updatedInput/command"))
        .and_then(Value::as_str)
        .map(std::string::ToString::to_string);

    match case.expect.decision.as_deref() {
        // `none` is explicit rather than implied by omission: omitting the
        // field has to mean "not asserted", or every case that only checks a
        // rewrite would accidentally also demand silence
        Some("none") => {
            if let Some(got) = &decision {
                problems.push(format!("expected no decision, got `{got}`"));
            }
        }
        Some(want) => {
            if decision.as_deref() != Some(want) {
                problems.push(format!(
                    "expected decision `{want}`, got {}",
                    decision
                        .as_deref()
                        .map_or_else(|| "no decision".to_string(), |d| format!("`{d}`"))
                ));
            }
        }
        None => {}
    }

    if let Some(want) = &case.expect.command {
        let original = case.command.as_deref().unwrap_or_default();
        if want == "<unchanged>" {
            match &updated {
                Some(got) if got != original => {
                    problems.push(format!("expected no rewrite, got `{got}`"));
                }
                _ => {}
            }
        } else if updated.as_deref() != Some(want.as_str()) {
            problems.push(format!(
                "expected command `{want}`, got {}",
                updated
                    .as_deref()
                    .map_or_else(|| "no rewrite".to_string(), |c| format!("`{c}`"))
            ));
        }
    }

    if let Some(want) = &case.expect.reason
        && !reason.as_deref().is_some_and(|r| r.contains(want.as_str()))
    {
        problems.push(format!(
            "expected reason containing `{want}`, got {}",
            reason
                .as_deref()
                .map_or_else(|| "no reason".to_string(), |r| format!("`{r}`"))
        ));
    }

    if let Some(want) = &case.expect.hint
        && !context
            .as_deref()
            .is_some_and(|c| c.contains(want.as_str()))
    {
        problems.push(format!(
            "expected hint containing `{want}`, got {}",
            context
                .as_deref()
                .map_or_else(|| "no hint".to_string(), |c| format!("`{c}`"))
        ));
    }

    if let Some(unwanted) = &case.expect.no_hint
        && let Some(got) = context.as_deref().filter(|c| c.contains(unwanted.as_str()))
    {
        problems.push(format!(
            "expected no hint containing `{unwanted}`, got `{got}`"
        ));
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// TOML value → JSON value. `toml::Value` is `Serialize`, so this is a
/// re-encode rather than a hand-written walk over every variant.
fn to_json(value: &toml::Value) -> Value {
    serde_json::to_value(value).expect("toml value re-encodes as json")
}

// ── the harness's own guardrails ──
//
// A data-driven runner is only trustworthy if its failure modes are tested.
// These pin the three ways it could pass while checking nothing.

#[test]
fn empty_expect_is_rejected() {
    let file: CaseFile = toml::from_str(
        r#"
        [[case]]
        command = "ls"
        expect  = {}
        "#,
    )
    .expect("parses");
    let problems = run_case(&file, &file.case[0]).expect_err("must reject an empty expect");
    assert!(problems[0].contains("asserts nothing"), "{problems:?}");
}

#[test]
fn unknown_field_is_rejected() {
    // `decison` — the typo that would otherwise assert nothing at all
    let err = toml::from_str::<CaseFile>(
        r#"
        [[case]]
        command = "ls"
        expect  = { decison = "deny" }
        "#,
    )
    .expect_err("a misspelled expect field must not be silently ignored");
    assert!(err.to_string().contains("decison"), "{err}");
}

#[test]
fn omitted_decision_is_not_asserted_but_none_is() {
    // an empty policy has no opinion on `ls`
    let file: CaseFile = toml::from_str(
        r#"
        [[case]]
        name    = "omitted decision, only the command is checked"
        command = "ls"
        expect  = { command = "<unchanged>" }

        [[case]]
        name    = "explicit none asserts silence"
        command = "ls"
        expect  = { decision = "none" }

        [[case]]
        name    = "a decision that will not happen"
        command = "ls"
        expect  = { decision = "deny" }
        "#,
    )
    .expect("parses");
    assert!(run_case(&file, &file.case[0]).is_ok());
    assert!(run_case(&file, &file.case[1]).is_ok());
    let problems = run_case(&file, &file.case[2]).expect_err("must notice the missing deny");
    assert!(
        problems[0].contains("expected decision `deny`"),
        "{problems:?}"
    );
}

#[test]
fn every_failed_assertion_is_reported_not_just_the_first() {
    let file: CaseFile = toml::from_str(
        r#"
        [config]
        [[config.bash]]
        match   = "grep*"
        action  = "rewrite"
        rewrite = "rg"

        [[case]]
        command = "grep foo src"
        expect  = { decision = "deny", command = "wrong", reason = "nope" }
        "#,
    )
    .expect("parses");
    let problems = run_case(&file, &file.case[0]).expect_err("all three must fail");
    assert_eq!(problems.len(), 3, "{problems:?}");
}
