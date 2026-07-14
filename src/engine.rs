use crate::audit;
use crate::config::{Action, Config, ModuleSetting};
use crate::hook::{HookInput, HookOutput};
use crate::modules::{activate, retry_allow, strikes};
use crate::{agent, bash, content, minify, modules, rules, web};
use serde_json::Value;

pub fn evaluate(input: &HookInput, config: &Config) -> Option<HookOutput> {
    let result = match (input.hook_event_name.as_str(), input.tool_name.as_str()) {
        ("PreToolUse", "Bash") => pre_bash(input, config),
        ("PreToolUse", "WebFetch") => pre_web(input, config),
        // the subagent tool is "Task" in Claude Code, "Agent" in newer harnesses
        ("PreToolUse", "Task" | "Agent") => pre_agent(input, config),
        ("PreToolUse", _) => pre_content(input, config),
        ("PostToolUse", "Bash") => post_bash(input, config),
        ("PostToolUse", "Task" | "Agent") => post_agent(input, config),
        ("PostToolUseFailure", "Bash") => post_failure(input, config),
        _ => Ok(None),
    };
    let output = match result {
        Ok(output) => output,
        // config/rule compile error: fail closed on PreToolUse, stay silent on PostToolUse
        Err(error) => match input.hook_event_name.as_str() {
            "PreToolUse" => Some(error_output(&input.hook_event_name, &error)),
            _ => None,
        },
    };
    output.map(|o| apply_remap(o, config, input))
}

// [remap]: final-decision lookup applied last, e.g. `[modes.auto.remap]
// ask = "deny"` — unattended runs have nobody to answer a prompt, so the agent
// gets a deterministic answer instead of a dialog that stalls the turn.
// `warn = "skip"` drops the emitted hints for the same reason.
fn apply_remap(mut output: HookOutput, config: &Config, input: &HookInput) -> HookOutput {
    if input.hook_event_name != "PreToolUse" || config.remap.is_empty() {
        return output;
    }
    let out = &mut output.hook_specific_output;
    let mode = input.permission_mode.as_deref().unwrap_or("lictor");
    if let Some(decision) = out.permission_decision.as_deref()
        && let Some(target) = config.remap.get(decision)
    {
        let note = |r: Option<&str>, to: &str| {
            let suffix = format!("({mode} mode remap: {decision} → {to})");
            match r {
                Some(r) => format!("{r} {suffix}"),
                None => format!("lictor: {suffix}"),
            }
        };
        match target {
            Action::Allow | Action::Ask | Action::Deny => {
                let to = match target {
                    Action::Allow => "allow",
                    Action::Ask => "ask",
                    _ => "deny",
                };
                if to != decision {
                    out.permission_decision_reason =
                        Some(note(out.permission_decision_reason.as_deref(), to));
                    out.permission_decision = Some(to.to_string());
                }
            }
            // demote the decision to a hint the model sees
            Action::Warn => {
                let hint = note(out.permission_decision_reason.as_deref(), "warn");
                out.permission_decision = None;
                out.permission_decision_reason = None;
                out.additional_context = match out.additional_context.take() {
                    Some(existing) => Some(format!("{existing}\n{hint}")),
                    None => Some(hint),
                };
            }
            // hand the call back to Claude Code's own permission rules
            Action::Skip => {
                out.permission_decision = None;
                out.permission_decision_reason = None;
            }
            Action::Rewrite | Action::Log => {}
        }
    }
    if matches!(config.remap.get("warn"), Some(Action::Skip | Action::Log)) {
        out.additional_context = None;
    }
    output
}

// fallback when no rule produced a decision (settings.default_bash/default_edit/
// default_web): deny/ask/allow decide, warn hints — flips lictor to an allowlist
fn apply_default(outcome: &mut rules::GateOutcome, default: Option<Action>, subject: &str) {
    let Some(action) = default else { return };
    if outcome.decision.is_some() {
        return;
    }
    let message = format!("lictor: `{subject}` matches no rule — mode default applies");
    match action {
        Action::Deny => {
            outcome.decision = Some("deny");
            outcome.reason = Some(message);
        }
        Action::Ask => {
            outcome.decision = Some("ask");
            outcome.reason = Some(message);
        }
        Action::Allow => outcome.decision = Some("allow"),
        Action::Warn => {
            if !outcome.hints.contains(&message) {
                outcome.hints.push(message);
            }
        }
        Action::Rewrite | Action::Log | Action::Skip => {}
    }
}

pub fn error_output(event: &str, error: &str) -> HookOutput {
    let mut output = HookOutput::new(event);
    output.hook_specific_output.permission_decision = Some("ask".to_string());
    output.hook_specific_output.permission_decision_reason =
        Some(format!("lictor config error: {error}"));
    output
}

// deny-then-allow: a rule's retry_count denies within retry_window flip the
// next resubmission to allow instead — the counter is spent (reset) once it does
fn apply_hint_retry(outcome: &mut rules::GateOutcome, config: &Config, input: &HookInput) {
    let Some(session) = input.session_id.as_deref() else {
        return;
    };
    let Some((key, threshold, window, message)) = &outcome.hint_retry else {
        return;
    };
    let prior = retry_allow::count(config, input.cwd.as_deref(), session, key, *window);
    if prior >= *threshold {
        outcome.hints.retain(|h| h != message);
        retry_allow::reset(config, input.cwd.as_deref(), session, key);
    } else {
        retry_allow::bump(config, input.cwd.as_deref(), session, key);
    }
}

fn apply_deny_retry(outcome: &mut rules::GateOutcome, config: &Config, input: &HookInput) {
    let Some(session) = input.session_id.as_deref() else {
        return;
    };
    let Some((key, threshold, window)) = &outcome.deny_retry else {
        return;
    };
    let prior = retry_allow::count(config, input.cwd.as_deref(), session, key, *window);
    if prior >= *threshold {
        outcome.decision = Some("allow");
        outcome.reason = Some(format!(
            "lictor: auto-allowed — resubmitted after {threshold} denies of rule `{key}` within {window}s"
        ));
        retry_allow::reset(config, input.cwd.as_deref(), session, key);
    } else {
        retry_allow::bump(config, input.cwd.as_deref(), session, key);
    }
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
    let web_rules = web::compile(config)?;
    let minify_rules = minify::compile_minify_rules(config)?;
    let mut extraction = bash::extract(original);

    // module rewrites (mv -> git mv, ...) land first; the gate judges the final command
    let mut plan = modules::plan(&extraction, config, input.cwd.as_deref(), &|paths| {
        modules::git_tracked(input.cwd.as_deref(), paths)
    });
    let path_rules = modules::path_rules::compile(config)?;
    modules::path_rules::plan(&path_rules, &extraction, input.cwd.as_deref(), &mut plan);
    let command = if plan.edits.is_empty() {
        original.to_string()
    } else {
        let rewritten = rules::apply_edits(original, &plan.edits);
        extraction = bash::extract(&rewritten);
        rewritten
    };
    let command = command.as_str();
    let module_rewrote = command != original;

    let mut outcome = rules::gate(
        &extraction,
        &bash_rules,
        &web_rules,
        config,
        input.cwd.as_deref(),
    );
    apply_deny_retry(&mut outcome, config, input);

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

    // self-cleanup: rm/git rm of paths created earlier this session skips the
    // ask — but only when no other module is already asking about this command
    if outcome.decision == Some("ask")
        && plan.asks.is_empty()
        && let Some((setting, message)) = modules::self_rm::check(
            &extraction,
            config,
            input.cwd.as_deref(),
            input.session_id.as_deref(),
        )
    {
        match setting {
            ModuleSetting::Allow => {
                outcome.decision = Some("allow");
                outcome.reason = Some(message);
            }
            ModuleSetting::Warn if !outcome.hints.contains(&message) => {
                outcome.hints.push(message);
            }
            _ => {}
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

    apply_default(&mut outcome, config.default_bash(), original);

    // fingerprint rm targets while the files still exist, for delete/recreate detection
    if outcome.decision != Some("deny") {
        modules::recreate::record(
            &extraction,
            config,
            input.cwd.as_deref(),
            input.session_id.as_deref(),
        );
        modules::self_rm::record_bash(
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
    let Some((path, pairs)) = content::target_of(&input.tool_name, &input.tool_input) else {
        return Ok(None);
    };
    let edit_rules = content::compile_edit_rules(config)?;
    let mut outcome = content::gate_content(&path, &pairs, &edit_rules);
    apply_deny_retry(&mut outcome, config, input);
    apply_hint_retry(&mut outcome, config, input);

    // jail: Write/Edit/MultiEdit/NotebookEdit's file_path is a literal, already-
    // resolved path — same containment check as Bash's jail module, just without
    // the shell-word scanning (see modules::jail::violation_for_path)
    if let (Some(action), Some(cwd)) = (config.jail(), input.cwd.as_deref())
        && outcome.decision != Some("deny")
        && let Some(resolved) = modules::jail::violation_for_path(&path, config, cwd)
    {
        let message = format!(
            "lictor: `{resolved}` is outside the project jail — stay in the repo or have the user extend settings.jail_allow"
        );
        match action {
            Action::Allow | Action::Log | Action::Skip => {}
            Action::Warn => {
                if !outcome.hints.contains(&message) {
                    outcome.hints.push(message);
                }
            }
            Action::Ask => {
                if outcome.decision.is_none() || outcome.decision == Some("allow") {
                    outcome.decision = Some("ask");
                    outcome.reason = Some(message);
                }
            }
            // rewrite has no meaning for a jail violation; treat as deny
            Action::Deny | Action::Rewrite => {
                outcome.decision = Some("deny");
                outcome.reason = Some(message);
            }
        }
    }

    // [[path]] rules: file_path matched against the user's dir globs — same
    // check Bash path args get, with the user's own action + hint
    if outcome.decision != Some("deny")
        && let Some(cwd) = input.cwd.as_deref()
    {
        let path_rules = modules::path_rules::compile(config)?;
        if let Some((action, message)) = modules::path_rules::check(&path_rules, &path, cwd) {
            match action {
                Action::Deny => {
                    outcome.decision = Some("deny");
                    outcome.reason = Some(message);
                }
                Action::Ask => {
                    if outcome.decision.is_none() || outcome.decision == Some("allow") {
                        outcome.decision = Some("ask");
                        outcome.reason = Some(message);
                    }
                }
                Action::Warn => {
                    if !outcome.hints.contains(&message) {
                        outcome.hints.push(message);
                    }
                }
                Action::Allow | Action::Log | Action::Rewrite | Action::Skip => {}
            }
        }
    }

    // delete/recreate: a Write that resurrects a just-deleted file is a rename
    // done the history-destroying way
    if input.tool_name == "Write" && outcome.decision != Some("deny") {
        modules::self_rm::record_write(
            config,
            input.cwd.as_deref(),
            input.session_id.as_deref(),
            &path,
        );
        let new_strings: Vec<String> = pairs.iter().map(|(_, n)| n.clone()).collect();
        let hit = modules::recreate::check(
            config,
            input.cwd.as_deref(),
            input.session_id.as_deref(),
            &path,
            &new_strings,
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

    apply_default(&mut outcome, config.default_edit(), &path);

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

// WebFetch: the tool's `url` field judged by [[web]] rules alone; unmatched
// URLs fall to settings.default_web, then Claude Code's own permission flow
fn pre_web(input: &HookInput, config: &Config) -> Result<Option<HookOutput>, String> {
    let Some(raw_url) = input.tool_input.get("url").and_then(Value::as_str) else {
        return Ok(None);
    };
    let web_rules = web::compile(config)?;
    let mut outcome = rules::GateOutcome::default();
    let mut rewritten: Option<String> = None;
    // a non-http(s)/unparseable URL is left to Claude Code's own rules
    if let Some(url) = web::parse(raw_url) {
        match web::check_url(&web_rules, &url) {
            Some((Action::Deny, rule)) => {
                outcome.decision = Some("deny");
                outcome.reason = Some(web::deny_message(rule, raw_url));
            }
            Some((Action::Ask, rule)) => {
                outcome.decision = Some("ask");
                outcome.reason = Some(web::ask_message(rule, raw_url));
            }
            // route through the configured proxy (pure.md-style) and auto-approve
            Some((Action::Rewrite, rule)) => {
                if let Some(target) = web::rewrite_url(rule, raw_url) {
                    outcome.decision = Some("allow");
                    outcome.hints.push(
                        rule.hint
                            .clone()
                            .unwrap_or(format!("lictor: rewrote fetch `{raw_url}` -> `{target}`")),
                    );
                    rewritten = Some(target);
                }
            }
            Some((Action::Warn, rule)) => outcome.hints.push(web::warn_message(rule, raw_url)),
            Some((Action::Allow, _)) => outcome.decision = Some("allow"),
            _ => apply_default(&mut outcome, config.default_web(), raw_url),
        }
    }

    write_audit(config, input, raw_url, outcome.decision, &[], &[]);
    if outcome.decision.is_none() && outcome.hints.is_empty() {
        return Ok(None);
    }
    let mut output = HookOutput::new(&input.hook_event_name);
    output.hook_specific_output.permission_decision = outcome.decision.map(str::to_string);
    output.hook_specific_output.permission_decision_reason = outcome.reason;
    if let Some(target) = rewritten {
        let mut updated = input.tool_input.clone();
        updated["url"] = Value::String(target);
        output.hook_specific_output.updated_input = Some(updated);
    }
    if !outcome.hints.is_empty() {
        output.hook_specific_output.additional_context = Some(outcome.hints.join("\n"));
    }
    Ok(Some(output))
}

fn pre_agent(input: &HookInput, config: &Config) -> Result<Option<HookOutput>, String> {
    let Some(prompt) = input.tool_input.get("prompt").and_then(Value::as_str) else {
        return Ok(None);
    };
    let agent_rules = agent::compile(config)?;
    let mut outcome = rules::GateOutcome::default();
    for hit in agent::matching(&agent_rules, crate::config::AgentOn::Prompt, prompt) {
        let message = agent::message(hit.rule, "the subagent prompt");
        match hit.rule.action {
            Action::Deny => {
                outcome.decision = Some("deny");
                outcome.reason = Some(message);
                break;
            }
            Action::Ask => {
                if outcome.decision.is_none() {
                    outcome.decision = Some("ask");
                    outcome.reason = Some(message);
                }
            }
            Action::Warn => {
                if !outcome.hints.contains(&message) {
                    outcome.hints.push(message);
                }
            }
            Action::Log => outcome.logged.push((hit.rule.pattern.clone(), message)),
            _ => {}
        }
    }

    write_audit(
        config,
        input,
        prompt,
        outcome.decision,
        &outcome.logged,
        &[],
    );
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

// output rules are hint-only: the subagent already ran, so the strongest
// useful verdict is context the model sees next to the result
fn post_agent(input: &HookInput, config: &Config) -> Result<Option<HookOutput>, String> {
    let Some(response) = &input.tool_response else {
        return Ok(None);
    };
    let agent_rules = agent::compile(config)?;
    if agent_rules
        .iter()
        .all(|r| r.rule.on != crate::config::AgentOn::Output)
    {
        return Ok(None);
    }
    // response shape varies by harness; match the serialized JSON text
    let text = response.to_string();
    let mut hints: Vec<String> = Vec::new();
    let mut logged: Vec<(String, String)> = Vec::new();
    for hit in agent::matching(&agent_rules, crate::config::AgentOn::Output, &text) {
        let message = agent::message(hit.rule, "the subagent output");
        match hit.rule.action {
            Action::Warn if !hints.contains(&message) => hints.push(message),
            Action::Log => logged.push((hit.rule.pattern.clone(), message)),
            _ => {}
        }
    }

    write_audit(config, input, "agent output", None, &logged, &[]);
    if hints.is_empty() {
        return Ok(None);
    }
    let mut output = HookOutput::new(&input.hook_event_name);
    output.hook_specific_output.additional_context = Some(hints.join("\n"));
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
