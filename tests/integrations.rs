// Integration-shape tests for the output-compaction tools lictor plugs into.
//
// lictor wires these tools two ways:
//   wrap = "<tool>"  -> PreToolUse: prefix the command  (`git status` -> `<tool> git status`)
//   pipe = "<tool>"  -> PostToolUse: pipe captured stdout through the tool (stdin->stdout)
//
// The real binaries (rtk/tokf/squeez/...) are NOT installed in CI, so these tests
// verify that lictor produces the EXACT invocation / hands the tool the correct
// input — not the tools' own compression quality. For `pipe`, a deterministic
// local stand-in mimics the tool so the plumbing (and the discard-if-grew /
// min_lines guards) is exercised end to end.

use lictor::config::Config;
use lictor::engine::evaluate;
use lictor::hook::HookInput;
use serde_json::{Value, json};

fn pre_bash(policy: &str, command: &str) -> Option<Value> {
    run(
        policy,
        "PreToolUse",
        "Bash",
        json!({"command": command}),
        None,
    )
}

fn post_bash(policy: &str, command: &str, stdout: &str) -> Option<Value> {
    run(
        policy,
        "PostToolUse",
        "Bash",
        json!({"command": command}),
        Some(json!({"stdout": stdout, "stderr": "", "interrupted": false, "isImage": false})),
    )
}

fn run(
    policy: &str,
    event: &str,
    tool: &str,
    input: Value,
    response: Option<Value>,
) -> Option<Value> {
    let mut config: Config = toml::from_str(policy).expect("policy parses");
    config.finalize().expect("catalogs expand");
    let hook: HookInput = serde_json::from_value(json!({
        "hook_event_name": event,
        "tool_name": tool,
        "tool_input": input,
        "tool_response": response,
    }))
    .unwrap();
    evaluate(&hook, &config).map(|o| serde_json::to_value(o).unwrap()["hookSpecificOutput"].take())
}

fn rewritten(out: &Option<Value>) -> Option<String> {
    out.as_ref()?
        .pointer("/updatedInput/command")?
        .as_str()
        .map(str::to_string)
}

fn minified(out: &Option<Value>) -> Option<String> {
    out.as_ref()?
        .pointer("/updatedToolOutput/stdout")?
        .as_str()
        .map(str::to_string)
}

fn decision(out: &Option<Value>) -> Option<String> {
    out.as_ref()?
        .get("permissionDecision")?
        .as_str()
        .map(str::to_string)
}

// ── rtk (rtk-ai/rtk): command proxy, `rtk <cmd>` with args as separate words ──

const RTK: &str = r#"
[[minify]]
match = "git status*"
wrap = "rtk"
allow = true
[[minify]]
match = "git diff*"
wrap = "rtk"
allow = true
[[minify]]
match = "cargo test*"
wrap = "rtk"
[[minify]]
match = "npm install*"
wrap = "rtk"
"#;

#[test]
fn rtk_wraps_command_as_separate_argv() {
    // rtk takes the command as plain argv, exactly what our prefix produces
    let out = pre_bash(RTK, "git status --short");
    assert_eq!(rewritten(&out), Some("rtk git status --short".into()));
    assert_eq!(
        decision(&out),
        Some("allow".into()),
        "allow=true auto-approves"
    );
}

#[test]
fn rtk_wraps_only_matched_commands_in_a_chain() {
    // the un-wrapped `echo hi` keeps the chain from auto-approving: the command is
    // still rewritten (updatedInput) but the decision defers to normal permissions
    let out = pre_bash(RTK, "echo hi && git diff HEAD~1");
    assert_eq!(
        rewritten(&out),
        Some("echo hi && rtk git diff HEAD~1".into())
    );
    assert_eq!(decision(&out), None);
}

#[test]
fn rtk_wraps_each_matched_command() {
    let out = pre_bash(RTK, "git status && cargo test");
    assert_eq!(
        rewritten(&out),
        Some("rtk git status && rtk cargo test".into())
    );
}

#[test]
fn rtk_does_not_wrap_redirected_command() {
    // wrapping `git diff > f` would send rtk's compressed output to the file
    let out = pre_bash(RTK, "git diff > patch.txt");
    assert_eq!(rewritten(&out), None);
}

// ── multi-word wrap prefixes (tokf / ecotokens / squeez / chop) ──
// lictor prepends the whole `wrap` string, so proxies whose real invocation is
// more than one token still fit. Exact forms verified against each tool's source:
//   tokf       -> `tokf run <cmd>`            (separate argv)
//   ecotokens  -> `ecotokens filter -- <cmd>` (separate argv after `--`)
//   squeez     -> `squeez wrap <cmd>`         (argv joined, runs via sh -c)
//   chop       -> `chop <cmd>`                (separate argv)

fn wrap_policy(pattern: &str, wrap: &str) -> String {
    format!("[[minify]]\nmatch = \"{pattern}\"\nwrap = \"{wrap}\"\nallow = true\n")
}

#[test]
fn wrap_supports_multiword_prefix() {
    let out = pre_bash(
        &wrap_policy("cargo test*", "tokf run"),
        "cargo test --workspace",
    );
    assert_eq!(
        rewritten(&out),
        Some("tokf run cargo test --workspace".into())
    );
}

#[test]
fn ecotokens_wrap_with_dashdash() {
    let out = pre_bash(
        &wrap_policy("cargo build*", "ecotokens filter --"),
        "cargo build --release",
    );
    assert_eq!(
        rewritten(&out),
        Some("ecotokens filter -- cargo build --release".into())
    );
}

#[test]
fn squeez_wrap() {
    let out = pre_bash(
        &wrap_policy("git log*", "squeez wrap"),
        "git log --oneline -5",
    );
    assert_eq!(
        rewritten(&out),
        Some("squeez wrap git log --oneline -5".into())
    );
}

#[test]
fn chop_wrap() {
    let out = pre_bash(&wrap_policy("docker ps*", "chop"), "docker ps -a");
    assert_eq!(rewritten(&out), Some("chop docker ps -a".into()));
}

// token-saver takes the command as ONE shell-quoted arg: `python3 wrap.py 'git status'`.
// lictor's wrap can only prepend separate argv, so it produces the WRONG shape
// (`python3 wrap.py git status`). Documented incompatibility — token-saver is not
// wrappable this way; use a tool with a plain-proxy or stdin-filter mode instead.
#[test]
fn token_saver_quoted_arg_form_is_not_expressible() {
    let out = pre_bash(&wrap_policy("git status*", "python3 wrap.py"), "git status");
    let got = rewritten(&out).unwrap();
    assert_eq!(got, "python3 wrap.py git status");
    assert_ne!(
        got, "python3 wrap.py 'git status'",
        "lictor cannot produce the quoted-arg form token-saver needs"
    );
}

// ── pipe plumbing (squeez filter / ecotokens filter-output / rtk pipe) ──
// Real raw-stdin invocations (verified): `squeez filter [hint]`,
// `ecotokens filter-output --command X --exit-code 0`, `rtk pipe -f <name>`.
// The binaries aren't installed, so a deterministic multi-token stand-in proves
// lictor runs the whole pipe string (flags included) as `sh -c` over raw stdout.

const PIPE: &str = r#"
[[minify]]
match = "npm install*"
pipe = "grep -c ."
min_lines = 3
"#;

#[test]
fn pipe_feeds_stdout_and_replaces_with_filter_output() {
    let long = "added\npkg a\npkg b\npkg c\npkg d";
    let out = post_bash(PIPE, "npm install left-pad", long);
    // `grep -c .` returns the line count (with trailing newline) — proves stdin reached the filter
    assert_eq!(minified(&out).as_deref(), Some("5\n"));
}

#[test]
fn pipe_passes_multi_token_string_with_flags() {
    // stands in for `squeez filter cargo` / `ecotokens filter-output --command x --exit-code 0`
    let policy = "[[minify]]\nmatch = \"cargo test*\"\npipe = \"sed -n 1,2p\"\nmin_lines = 2\n";
    let out = post_bash(policy, "cargo test", "l1\nl2\nl3\nl4\nl5");
    // sed terminates every printed line, so the filter output ends in \n
    assert_eq!(
        minified(&out).as_deref(),
        Some("l1\nl2\n"),
        "multi-token pipe with flags ran"
    );
}

#[test]
fn pipe_skips_output_below_min_lines() {
    let out = post_bash(PIPE, "npm install x", "one\ntwo");
    assert!(out.is_none(), "2 lines < min_lines=3");
}
