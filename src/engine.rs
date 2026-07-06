use crate::audit;
use crate::config::{Config, ModuleSetting};
use crate::hook::{HookInput, HookOutput};
use crate::modules::{activate, strikes};
use crate::{bash, content, minify, modules, rules};
use serde_json::Value;

pub fn evaluate(input: &HookInput, config: &Config) -> Option<HookOutput> {
    let result = match (input.hook_event_name.as_str(), input.tool_name.as_str()) {
        ("PreToolUse", "Bash") => pre_bash(input, config),
        ("PreToolUse", _) => pre_content(input, config),
        ("PostToolUse", "Bash") => post_bash(input, config),
        ("PostToolUseFailure", "Bash") => post_failure(input, config),
        _ => Ok(None),
    };
    match result {
        Ok(output) => output,
        // config/rule compile error: fail closed on PreToolUse, stay silent on PostToolUse
        Err(error) => match input.hook_event_name.as_str() {
            "PreToolUse" => Some(error_output(&input.hook_event_name, &error)),
            _ => None,
        },
    }
}

pub fn error_output(event: &str, error: &str) -> HookOutput {
    let mut output = HookOutput::new(event);
    output.hook_specific_output.permission_decision = Some("ask".to_string());
    output.hook_specific_output.permission_decision_reason =
        Some(format!("lictor config error: {error}"));
    output
}

fn write_audit(
    config: &Config,
    input: &HookInput,
    subject: &str,
    decision: Option<&str>,
    logged: &[(String, String)],
    minified: &[(String, usize, usize)],
) {
    let Some(path) = config.log_path(input.cwd.as_deref()) else {
        return;
    };
    let ts = audit::now();
    let mut entries = Vec::new();
    for (rule, subj) in logged {
        entries.push(audit::Entry {
            ts,
            kind: "rule-log".into(),
            event: input.hook_event_name.clone(),
            tool: input.tool_name.clone(),
            subject: subj.clone(),
            decision: None,
            rule: Some(rule.clone()),
            bytes_in: None,
            bytes_out: None,
        });
    }
    if let Some(decision) = decision {
        entries.push(audit::Entry {
            ts,
            kind: "decision".into(),
            event: input.hook_event_name.clone(),
            tool: input.tool_name.clone(),
            subject: subject.to_string(),
            decision: Some(decision.to_string()),
            rule: None,
            bytes_in: None,
            bytes_out: None,
        });
    }
    for (rule, bytes_in, bytes_out) in minified {
        entries.push(audit::Entry {
            ts,
            kind: "minify".into(),
            event: input.hook_event_name.clone(),
            tool: input.tool_name.clone(),
            subject: subject.to_string(),
            decision: None,
            rule: Some(rule.clone()),
            bytes_in: Some(*bytes_in),
            bytes_out: Some(*bytes_out),
        });
    }
    audit::append(&path, &entries);
}

fn pre_bash(input: &HookInput, config: &Config) -> Result<Option<HookOutput>, String> {
    let Some(original) = input.tool_input.get("command").and_then(Value::as_str) else {
        return Ok(None);
    };
    let bash_rules = rules::compile_bash_rules(config)?;
    let minify_rules = minify::compile_minify_rules(config)?;
    let mut extraction = bash::extract(original);

    // module rewrites (mv -> git mv, ...) land first; the gate judges the final command
    let mut plan = modules::plan(&extraction, config, input.cwd.as_deref(), &|paths| {
        modules::git_tracked(input.cwd.as_deref(), paths)
    });
    let command = if plan.edits.is_empty() {
        original.to_string()
    } else {
        let rewritten = rules::apply_edits(original, &plan.edits);
        extraction = bash::extract(&rewritten);
        rewritten
    };
    let command = command.as_str();
    let module_rewrote = command != original;

    let mut outcome = rules::gate(&extraction, &bash_rules, config, input.cwd.as_deref());

    // module verdicts: a gate deny still wins; a module deny beats everything else
    if outcome.decision != Some("deny") {
        if let Some(reason) = plan.denies.first() {
            outcome.decision = Some("deny");
            outcome.reason = Some(reason.clone());
            outcome.edits.clear();
            outcome.cosmetic_edits.clear();
            outcome.hints.clear();
            plan.hints.clear();
        } else if let Some(reason) = plan.asks.first() {
            if outcome.decision.is_none() || outcome.decision == Some("allow") {
                outcome.decision = Some("ask");
                outcome.reason = Some(reason.clone());
            }
            // ask reasons only reach the user's prompt; the model learns via hint
            plan.hints.push(reason.clone());
        }
    }

    if outcome.decision != Some("deny") {
        let mut hints = plan.hints;
        hints.append(&mut outcome.hints);
        outcome.hints = hints;

        let (wrap_edits, wrap_vetted) = minify::pre_wrap(&extraction, &minify_rules);
        let had_gate_decision = outcome.decision.is_some();
        outcome.edits.extend(wrap_edits);
        if !had_gate_decision && !outcome.edits.is_empty() {
            outcome.vetted.extend(wrap_vetted);
            if rules::site_coverage(&extraction, &outcome.vetted) {
                outcome.decision = Some("allow");
            }
        }
    }

    // fingerprint rm targets while the files still exist, for delete/recreate detection
    if outcome.decision != Some("deny") {
        modules::recreate::record(
            &extraction,
            config,
            input.cwd.as_deref(),
            input.session_id.as_deref(),
        );
    }

    // rogue-actor guard: consecutive denies with no executed command in between
    // revoke shell autonomy — everything asks until a command actually runs
    if let (Some(threshold), Some(session)) = (config.strikes(), input.session_id.as_deref()) {
        if outcome.decision == Some("deny") {
            strikes::bump(config, input.cwd.as_deref(), session);
        } else if strikes::count(config, input.cwd.as_deref(), session) >= threshold {
            outcome.decision = Some("ask");
            outcome.reason = Some(format!(
                "lictor: {threshold}+ consecutive denied commands — shell autonomy paused; a user-approved command lifts it"
            ));
        }
    }

    write_audit(
        config,
        input,
        command,
        outcome.decision,
        &outcome.logged,
        &[],
    );
    let mut all_edits = outcome.edits;
    all_edits.extend(outcome.cosmetic_edits);
    if outcome.decision.is_none()
        && all_edits.is_empty()
        && outcome.hints.is_empty()
        && !module_rewrote
    {
        return Ok(None);
    }
    let mut output = HookOutput::new(&input.hook_event_name);
    output.hook_specific_output.permission_decision = outcome.decision.map(str::to_string);
    output.hook_specific_output.permission_decision_reason = outcome.reason;
    if (!all_edits.is_empty() || module_rewrote) && outcome.decision != Some("deny") {
        let mut updated = input.tool_input.clone();
        updated["command"] = Value::String(rules::apply_edits(command, &all_edits));
        output.hook_specific_output.updated_input = Some(updated);
    }
    if !outcome.hints.is_empty() {
        output.hook_specific_output.additional_context = Some(outcome.hints.join("\n"));
    }
    Ok(Some(output))
}

fn pre_content(input: &HookInput, config: &Config) -> Result<Option<HookOutput>, String> {
    let Some((path, contents)) = content::target_of(&input.tool_name, &input.tool_input) else {
        return Ok(None);
    };
    let edit_rules = content::compile_edit_rules(config)?;
    let mut outcome = content::gate_content(&path, &contents, &edit_rules);

    // delete/recreate: a Write that resurrects a just-deleted file is a rename
    // done the history-destroying way
    if input.tool_name == "Write" && outcome.decision != Some("deny") {
        let hit = modules::recreate::check(
            config,
            input.cwd.as_deref(),
            input.session_id.as_deref(),
            &path,
            &contents,
        );
        if let Some((setting, hit)) = hit {
            let message = format!(
                "lictor: this content is {}% similar to recently deleted `{}` — don't delete+recreate; run `git checkout -- {}` (or recreate it), then `git mv {} {}`",
                hit.percent, hit.old_path, hit.old_path, hit.old_path, path
            );
            match setting {
                ModuleSetting::Deny => {
                    // the deny reason is fed back to the model, no extra hint needed
                    outcome.decision = Some("deny");
                    outcome.reason = Some(message);
                }
                ModuleSetting::Ask => {
                    if outcome.decision.is_none() || outcome.decision == Some("allow") {
                        outcome.decision = Some("ask");
                        outcome.reason = Some(message.clone());
                    }
                    // the ask reason only reaches the user's prompt; the hint below
                    // reaches the model so an approved write still teaches it
                    if !outcome.hints.contains(&message) {
                        outcome.hints.push(message);
                    }
                }
                _ => {
                    if !outcome.hints.contains(&message) {
                        outcome.hints.push(message);
                    }
                }
            }
        }
    }

    write_audit(config, input, &path, outcome.decision, &outcome.logged, &[]);
    if outcome.decision.is_none() && outcome.hints.is_empty() {
        return Ok(None);
    }
    let mut output = HookOutput::new(&input.hook_event_name);
    output.hook_specific_output.permission_decision = outcome.decision.map(str::to_string);
    output.hook_specific_output.permission_decision_reason = outcome.reason;
    if !outcome.hints.is_empty() {
        output.hook_specific_output.additional_context = Some(outcome.hints.join("\n"));
    }
    Ok(Some(output))
}

fn post_bash(input: &HookInput, config: &Config) -> Result<Option<HookOutput>, String> {
    let Some(command) = input.tool_input.get("command").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(tool_response) = &input.tool_response else {
        return Ok(None);
    };
    let Some(original) = tool_response.get("stdout").and_then(Value::as_str) else {
        return Ok(None);
    };
    let minify_rules = minify::compile_minify_rules(config)?;
    let extraction = bash::extract(command);
    let mut minified: Vec<(String, usize, usize)> = Vec::new();
    let mut current = original.to_string();

    // an executed command means the user is in the loop; strikes expire
    if let (Some(_), Some(session)) = (config.strikes(), input.session_id.as_deref()) {
        strikes::reset(config, input.cwd.as_deref(), session);
    }

    if let Some(outcome) = minify::post_minify(&extraction, &current, &minify_rules) {
        minified.push((outcome.rule.clone(), outcome.bytes_in, outcome.bytes_out));
        current = outcome.stdout;
    }
    // spill runs after rule-based minify, as the last-resort context guard
    if let Some(spilled) = minify::spill(&current, command, config, input.duration_ms) {
        minified.push((
            format!("spill:{}", spilled.key),
            spilled.bytes_in,
            spilled.bytes_out,
        ));
        current = spilled.stdout;
    }

    // a nonzero exit that still routed here (not to PostToolUseFailure) may carry
    // a not-found stderr; suggest toolchain activation
    let stderr = tool_response
        .get("stderr")
        .and_then(Value::as_str)
        .unwrap_or("");
    let hint = activate::guidance(&extraction, &config.activate, input.cwd.as_deref(), stderr);

    write_audit(config, input, command, None, &[], &minified);
    if current == original && hint.is_none() {
        return Ok(None);
    }
    let mut output = HookOutput::new(&input.hook_event_name);
    if current != original {
        let mut updated = tool_response.clone();
        updated["stdout"] = Value::String(current);
        output.hook_specific_output.updated_tool_output = Some(updated);
    }
    output.hook_specific_output.additional_context = hint;
    Ok(Some(output))
}

fn post_failure(input: &HookInput, config: &Config) -> Result<Option<HookOutput>, String> {
    let Some(command) = input.tool_input.get("command").and_then(Value::as_str) else {
        return Ok(None);
    };
    let signal = input.error.as_deref().unwrap_or("");
    let extraction = bash::extract(command);
    let Some(hint) =
        activate::guidance(&extraction, &config.activate, input.cwd.as_deref(), signal)
    else {
        return Ok(None);
    };
    let mut output = HookOutput::new(&input.hook_event_name);
    output.hook_specific_output.additional_context = Some(hint);
    Ok(Some(output))
}
