//! Red-team: adversarial cases that try to smuggle a banned command past the gate
//! or step outside the jail. Two classes:
//!   * regression guards (active) — a bypass that WAS possible and is now closed;
//!     these must stay green so the hole can't silently reopen.
//!   * known gaps (`#[ignore]`) — a bypass still open today. Each asserts the SAFE
//!     outcome, so `cargo test -- --ignored` is the live backlog: un-ignore to fix.

use lictor::config::Config;
use lictor::engine::evaluate;
use lictor::hook::HookInput;
use serde_json::json;

fn decide(policy: &str, command: &str, cwd: &str) -> Option<String> {
    let mut config: Config = toml::from_str(policy).expect("policy parses");
    config.finalize().expect("catalogs expand");
    let input: HookInput = serde_json::from_value(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd,
    }))
    .unwrap();
    evaluate(&input, &config).and_then(|o| o.hook_specific_output.permission_decision)
}

const DENY_COMMIT: &str =
    "[[bash]]\nmatch = \"git commit*\"\naction = \"deny\"\nreason = \"manual\"\n";
const JAIL: &str = "[settings]\njail = \"deny\"\n";
const SHELL_WRITE: &str = "[settings]\non_shell_write = \"deny\"\n";
const CWD: &str = "/Users/nobody/project";

// ── regression guard: nested-shell `-c` payload extraction ──
// `derive_shell_c` used to locate the `-c` flag with `starts_with('-') &&
// contains('c')`, which false-matched the c-bearing long option `--rcfile`. The
// payload was then read from the wrong index and NEVER analyzed, so any banned
// command wrapped as `bash --rcfile X -c '<payload>'` sailed through untouched.
#[test]
fn nested_shell_rcfile_c_is_not_a_gate_bypass() {
    for cmd in [
        "bash -c 'git commit -m x'",
        "bash --rcfile /dev/null -c 'git commit -m x'",
        "bash --noprofile --rcfile /dev/null -c 'git commit -m x'",
        "sh --rcfile /tmp/whatever -c 'git commit'",
    ] {
        assert_eq!(
            decide(DENY_COMMIT, cmd, "/tmp").as_deref(),
            Some("deny"),
            "banned payload escaped nested shell: {cmd}"
        );
    }
}

// ── regression guard: a redirect on the tail of an && / | chain writes a file ──
// tree-sitter binds `a && cmd > f` to the enclosing list, so a per-command
// direct-parent check missed it — letting `on_shell_write` and the auto-allow
// redirect block be bypassed by prepending any command.
#[test]
fn chained_redirect_is_treated_as_a_file_write() {
    for cmd in [
        "echo hi > notes.txt", // direct (control)
        "make build && echo done > out.txt",
        "true || printf x >> config.toml",
        "cat a | tee b > c.txt",
    ] {
        assert_eq!(
            decide(SHELL_WRITE, cmd, CWD).as_deref(),
            Some("deny"),
            "chained file-authoring redirect not caught: {cmd}"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════
// regression guards: jail evasions that WERE open and are now closed. Each
// asserts the SAFE decision; keep them green so the hole can't silently reopen.
// ══════════════════════════════════════════════════════════════════════════

// The jail reads resolved word text, but `$HOME/...` / `${HOME}/...` parse as
// dynamic (text = None). jail::expand_home now recovers the path from raw source
// so an agent can't reach a home-dir secret with `$HOME` instead of `~`.
#[test]
fn jail_escaped_via_home_env_var() {
    for cmd in ["cat $HOME/.ssh/id_rsa", "cat ${HOME}/.aws/credentials"] {
        assert_eq!(decide(JAIL, cmd, CWD).as_deref(), Some("deny"), "{cmd}");
    }
}

// The jail used to skip `synthetic` commands, so anything inside `bash -c '...'`
// went un-path-checked; it now jails re-parsed inner commands too.
#[test]
fn jail_escaped_via_nested_shell() {
    assert_eq!(
        decide(JAIL, "bash -c 'cat /etc/passwd'", CWD).as_deref(),
        Some("deny")
    );
}

// A path glued to a short flag (`-o/etc/passwd`) starts with '-', so
// `looks_like_path` rejected it; jail::path_candidate now deglues the flag.
#[test]
fn jail_escaped_via_glued_flag() {
    assert_eq!(
        decide(JAIL, "tail -o/etc/shadow", CWD).as_deref(),
        Some("deny")
    );
}
