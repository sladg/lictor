use super::Plan;
use crate::bash::{Command, Extraction};
use crate::config::{Config, ModuleSetting};

// literal argument words that look like filesystem paths and resolve outside
// the project and every allowed root. Lexical only: `~` expanded, `.`/`..`
// collapsed — symlinks and flag-attached paths (-o/tmp/x) are not resolved.
//
// the primary root is the git repo containing cwd, not cwd itself — an agent
// invoked from a subdirectory can still `cd ..`/reference sibling paths
// anywhere in the repo. cwd is the fallback when it isn't inside a repo.

// project root (git repo containing cwd) + jail_allow — the one "trusted roots"
// list the outside-project check reasons about
pub(crate) fn roots(config: &Config, cwd: &str, home: &str) -> Vec<String> {
    let primary = git_root(cwd).unwrap_or_else(|| cwd.to_string());
    let mut roots = vec![normalize(&primary, cwd, home)];
    roots.extend(config.jail_allow().iter().map(|p| normalize(p, cwd, home)));
    roots
}

pub(crate) fn is_inside(roots: &[String], resolved: &str) -> bool {
    roots
        .iter()
        .any(|r| resolved == r || resolved.starts_with(&format!("{r}/")))
}

// containment as the filesystem sees it, not just the string: the lexical
// `is_inside` first (fast, no syscalls, the common case), then a symlink-aware
// fallback so a root and a candidate that spell differently but resolve to the
// same place (macOS `/tmp` vs `/private/tmp`, any symlinked jail_allow root)
// still match. The one trust predicate the jail check and path_rules share, so
// neither can flag a path the other trusts.
pub(crate) fn is_trusted(roots: &[String], resolved: &str) -> bool {
    if is_inside(roots, resolved) {
        return true;
    }
    let candidate_real = real_path(resolved);
    roots.iter().any(|root| {
        let root_real = real_path(root);
        candidate_real == root_real || candidate_real.starts_with(&format!("{root_real}/"))
    })
}

// resolves through real filesystem symlinks by canonicalizing the longest
// existing ancestor and reattaching whatever doesn't exist yet unresolved — a
// Write target's own file often doesn't exist. No hardcoded alias table:
// whatever the OS actually symlinks, this follows. Falls back to the path
// as-is when nothing on it resolves (also the common case: no syscalls needed).
pub(crate) fn real_path(path: &str) -> String {
    let mut current = std::path::PathBuf::from(path);
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = current.canonicalize() {
            let mut result = real;
            for part in suffix.iter().rev() {
                result.push(part);
            }
            return result.to_string_lossy().into_owned();
        }
        let (Some(name), Some(parent)) = (
            current.file_name().map(|n| n.to_os_string()),
            current.parent(),
        ) else {
            return path.to_string();
        };
        suffix.push(name);
        current = parent.to_path_buf();
    }
}

// a single already-known literal path (Write/Edit/MultiEdit/NotebookEdit's
// file_path) rather than a shell command to scan — no word-extraction or `cd`
// tracking needed, just resolve-and-check-roots.
pub fn violation_for_path(path: &str, config: &Config, cwd: &str) -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let roots = roots(config, cwd, &home);
    let resolved = normalize(path, cwd, &home);
    (!is_trusted(&roots, &resolved)).then_some(resolved)
}

pub fn violations(extraction: &Extraction, config: &Config, cwd: &str) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let roots = roots(config, cwd, &home);
    let mut out = Vec::new();
    let candidate_of = |text: &str| {
        let candidate = path_candidate(text);
        looks_like_path(candidate).then(|| candidate.to_string())
    };
    for (_, resolved) in walk_words(extraction, cwd, &home, true, candidate_of) {
        if !is_trusted(&roots, &resolved) && !out.contains(&resolved) {
            out.push(resolved);
        }
    }
    out
}

// the inside-the-project mirror of `violations`: an absolute path pointing at a
// file INSIDE the project is pure token waste vs a relative path (and a
// cwd-drift footgun). Literal paths only (args + `NAME=val` prefixes); dynamic
// values are left alone. Gated by the `abs-paths` module setting. Boundary is
// the repo root (jail's primary root), not cwd — a shell that drifted into a
// subdir must not blind the nudge (`cd /abs/repo-root && …` used to sail
// through). Relative resolution of later words still follows the cwd/cd chain.
pub fn relative_hints(extraction: &Extraction, config: &Config, cwd: Option<&str>, out: &mut Plan) {
    let setting = match config.modules.get("abs-paths") {
        Some(s) if *s != ModuleSetting::Off => *s,
        _ => return,
    };
    let Some(cwd) = cwd else {
        return;
    };
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = normalize(cwd, cwd, &home);
    let root = git_root(&cwd).map_or_else(|| cwd.clone(), |r| normalize(&r, &cwd, &home));
    relative_hints_at(extraction, setting, &cwd, &root, &home, out);
}

fn relative_hints_at(
    extraction: &Extraction,
    setting: ModuleSetting,
    cwd: &str,
    root: &str,
    home: &str,
    out: &mut Plan,
) {
    // never the program word — bin paths are strip_program_paths' job. Split
    // only genuine flag-style values (--path=/abs); a bare `msg=/tmp/x` word
    // (commit message, echo payload) must not be mistaken for a path.
    let candidate_of = |text: &str| {
        let candidate = if text.starts_with('-') {
            text.split_once('=').map_or(text, |(_, v)| v)
        } else {
            text
        };
        is_absolute(candidate).then(|| candidate.to_string())
    };
    let mut candidates: Vec<String> = walk_words(extraction, cwd, home, false, candidate_of)
        .into_iter()
        .map(|(_, resolved)| resolved)
        .collect();
    for raw in extraction.assignments.iter().map(String::as_str) {
        if is_absolute(raw) {
            candidates.push(normalize(raw, cwd, home));
        }
    }

    let mut seen: Vec<String> = Vec::new();
    for resolved in candidates {
        if seen.contains(&resolved) {
            continue;
        }
        let Some(message) = classify_in_project(&resolved, root) else {
            continue;
        };
        seen.push(resolved);
        match setting {
            ModuleSetting::Deny => out.denies.push(message),
            ModuleSetting::Ask => out.asks.push(message),
            ModuleSetting::Warn => out.hints.push(message),
            ModuleSetting::Rewrite | ModuleSetting::Off | ModuleSetting::Allow => {}
        }
    }
}

fn is_absolute(text: &str) -> bool {
    text.starts_with('/') || text == "~" || text.starts_with("~/")
}

fn is_under(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{root}/"))
}

fn classify_in_project(resolved: &str, root: &str) -> Option<String> {
    if resolved == root {
        return Some(format!(
            "lictor: `{resolved}` is the project root itself — you're already in this repo, so omit it (drop a redundant `cd`; only fall back to `.` if a flag requires a value)"
        ));
    }
    if is_under(resolved, root) {
        let rel = resolved
            .strip_prefix(&format!("{root}/"))
            .unwrap_or(resolved);
        return Some(format!(
            "lictor: `{resolved}` is inside the project — reference it relative to the repo root as `{rel}`, not by absolute path (saves tokens, avoids cwd-drift path bugs)"
        ));
    }
    None
}

// cd-aware walk over every literal argument word whose raw text passes
// `interesting`, yielding (raw, resolved) pairs; shared by the outside-project
// check, relative_hints, and path_rules so all agree on what a chain's `cd`
// sequence resolves relative paths against.
//
// `cd` earlier in the same chain changes the base every later relative path
// resolves against (`cd .. && cat ../secret` escapes further than `cat`'s
// own literal ".." suggests). Track it sequentially. A subshell's `cd`
// (synthetic: bash -c/eval/find -exec) never leaks back to the parent
// shell, so only a non-synthetic `cd` updates the tracked cwd.
//
// `include_synthetic` controls whether words *inside* a nested shell
// (`bash -c '...'`, `eval`, `find -exec`) are walked at all: the security
// checks (jail, path_rules) want them (an escape hiding in a nested shell is
// still an escape), relative_hints doesn't (a style nudge about the outer
// command's own literal arguments has no opinion on what a sub-shell string
// happens to contain).
//
// `candidate_of` turns a word's raw text into a path candidate, or None to
// skip it — deliberately a caller-supplied strategy, not a shared one: the
// security checks' `path_candidate` splits any `X=Y` word on its first `=` (a
// security check would rather over-catch), which would misread an unrelated
// word like a `bash -c 'D=/tmp/x cmd'` string as a flag=value pair.
// relative_hints wants a much more conservative split (only genuine
// `--flag=value` words).
pub(crate) fn walk_words(
    extraction: &Extraction,
    cwd: &str,
    home: &str,
    include_synthetic: bool,
    candidate_of: impl Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut effective_cwd = cwd.to_string();
    for command in &extraction.commands {
        if command.synthetic && !include_synthetic {
            continue;
        }
        for word in command.words.iter().skip(1) {
            let expanded;
            let text = match word.text.as_deref() {
                Some(text) => text,
                // dynamic word: recover $HOME/${HOME} paths from the raw source.
                // synthetic spans index the inner re-parsed string, not `source`, so skip.
                None if !command.synthetic => {
                    let raw = extraction.source.get(word.start..word.end).unwrap_or("");
                    match expand_home(raw, home) {
                        Some(path) => {
                            expanded = path;
                            expanded.as_str()
                        }
                        None => continue,
                    }
                }
                None => continue,
            };
            let Some(candidate) = candidate_of(text) else {
                continue;
            };
            let resolved = normalize(&candidate, &effective_cwd, home);
            out.push((candidate, resolved));
        }
        // `cd -` or a dynamic target: no way to know the result, so freeze
        // rather than guess — never worse than the old always-the-original-cwd
        // behavior, and correct everywhere else.
        if !command.synthetic
            && let Some(Some(target)) = cd_target(command, home)
        {
            effective_cwd = normalize(&target, &effective_cwd, home);
        }
    }
    out
}

// bash `cd [-L|-P|-e|-@]... [target]`; bare `cd` goes to $HOME, `cd -` needs
// OLDPWD (which we don't have). None when this command isn't a `cd` at all.
fn cd_target(command: &Command, home: &str) -> Option<Option<String>> {
    let program = command.words.first()?.text.as_deref()?;
    if program != "cd" {
        return None;
    }
    for word in &command.words[1..] {
        match word.text.as_deref() {
            Some("-") => return Some(None),
            Some(t) if t.starts_with('-') => continue,
            Some(t) => return Some(Some(t.to_string())),
            None => return Some(None),
        }
    }
    Some(Some(home.to_string()))
}

// read-only probe: the git repository root containing `cwd`, so the jail's
// primary root is the whole repo — not the literal directory the hook happened
// to start from. None when cwd isn't inside a repo (or `git` isn't available).
fn git_root(cwd: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(cwd)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let root = String::from_utf8(output.stdout).ok()?;
    let root = root.trim();
    (!root.is_empty()).then(|| root.to_string())
}

// value after `flag=`, plus the path glued onto a short flag (-o/etc/x -> /etc/x);
// the glued case requires an alphabetic flag letter so `-1/2`-style args don't false-trip
pub(crate) fn path_candidate(text: &str) -> &str {
    let value = text.split_once('=').map_or(text, |(_, v)| v);
    if value.starts_with('-')
        && !value.starts_with("--")
        && value
            .chars()
            .nth(1)
            .is_some_and(|c| c.is_ascii_alphabetic())
        && let Some(idx) = value.find('/')
    {
        return &value[idx..];
    }
    value
}

// $HOME/... and ${HOME}/... parse as dynamic words (text = None) but their target
// is known; recover the same absolute path `~/...` would yield. ponytail: only HOME —
// add other well-known vars if an escape via $XDG_*/etc. shows up.
fn expand_home(raw: &str, home: &str) -> Option<String> {
    let rest = raw
        .strip_prefix("$HOME")
        .or_else(|| raw.strip_prefix("${HOME}"))?;
    (rest.is_empty() || rest.starts_with('/')).then(|| format!("{home}{rest}"))
}

pub(crate) fn looks_like_path(text: &str) -> bool {
    text.starts_with('/')
        || text == "~"
        || text.starts_with("~/")
        || text == ".."
        || text.starts_with("../")
        || text.contains("/../")
}

pub(crate) fn normalize(path: &str, cwd: &str, home: &str) -> String {
    let expanded = match (path, path.strip_prefix("~/")) {
        ("~", _) => home.to_string(),
        (_, Some(rest)) => format!("{home}/{rest}"),
        _ => path.to_string(),
    };
    let absolute = if expanded.starts_with('/') {
        expanded
    } else {
        format!("{cwd}/{expanded}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for segment in absolute.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    const CWD: &str = "/Users/nobody/project";

    fn config(allow: &[&str]) -> Config {
        let list = allow
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        toml::from_str(&format!(
            "[settings]\njail = \"ask\"\njail_allow = [{list}]"
        ))
        .expect("test config parses")
    }

    fn check(command: &str, allow: &[&str]) -> Vec<String> {
        violations(&bash::extract(command), &config(allow), CWD)
    }

    // ── relative_hints: the in-project absolute-path nudge (abs-paths module) ──

    fn hints_for(command: &str, setting: &str) -> Plan {
        let config: Config = toml::from_str(&format!("[modules]\nabs-paths = \"{setting}\""))
            .expect("test config parses");
        let mut plan = Plan::default();
        relative_hints(&bash::extract(command), &config, Some(CWD), &mut plan);
        plan
    }

    #[test]
    fn in_project_absolute_arg_denied_with_relative_hint() {
        // the motivating case: agent builds a full path for a repo file
        let plan = hints_for(
            "grep -c \"\" /Users/nobody/project/apps/courier/src/register/onboarding-flow.ts",
            "deny",
        );
        assert_eq!(plan.denies.len(), 1);
        assert!(
            plan.denies[0].contains("apps/courier/src/register/onboarding-flow.ts")
                && plan.denies[0].contains("relative"),
            "{:?}",
            plan.denies
        );
    }

    #[test]
    fn temp_arg_left_to_path_rules_only_in_project_flagged() {
        // the in-project source is relative_hints' (omit-arg); /tmp/checkout is a
        // [[path]]-rule concern now, so relative_hints flags exactly one
        let plan = hints_for("git clone /Users/nobody/project /tmp/checkout", "deny");
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
    }

    #[test]
    fn flag_attached_in_project_path_denied() {
        let plan = hints_for("rg foo --path=/Users/nobody/project/src", "deny");
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
    }

    #[test]
    fn project_root_itself_gets_omit_hint_not_a_self_referential_one() {
        // the bug: resolved == cwd made strip_prefix miss, echoing the same
        // absolute path back as the "relative" fix
        let plan = hints_for(&format!("rg --files --cwd {CWD}"), "deny");
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
        assert!(
            plan.denies[0].contains("project root itself") && plan.denies[0].contains("omit"),
            "{:?}",
            plan.denies
        );
        assert!(
            !plan.denies[0].contains("reference it relative"),
            "{:?}",
            plan.denies
        );
    }

    fn drifted_hints_for(command: &str, cwd: &str) -> Plan {
        let mut plan = Plan::default();
        relative_hints_at(
            &bash::extract(command),
            ModuleSetting::Deny,
            cwd,
            CWD,
            "/Users/nobody",
            &mut plan,
        );
        plan
    }

    #[test]
    fn drifted_cwd_still_flags_absolute_cd_to_root() {
        // the gap: shell drifted into a subdir, agent cds back by absolute path
        let plan = drifted_hints_for(
            &format!("cd {CWD} && moon run notes:lint"),
            &format!("{CWD}/packages/notes"),
        );
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
        assert!(
            plan.denies[0].contains("project root itself"),
            "{:?}",
            plan.denies
        );
    }

    #[test]
    fn drifted_cwd_still_flags_absolute_in_project_arg() {
        let plan = drifted_hints_for(
            "cat /Users/nobody/project/src/main.rs",
            &format!("{CWD}/packages/notes"),
        );
        assert_eq!(plan.denies.len(), 1, "{:?}", plan.denies);
        assert!(
            plan.denies[0].contains("`src/main.rs`"),
            "{:?}",
            plan.denies
        );
    }

    #[test]
    fn relative_paths_untouched() {
        // already relative — nothing to nag about
        for cmd in [
            "grep -c \"\" apps/courier/src/register/onboarding-flow.ts",
            "cat src/main.rs",
            "cargo build",
            "ls ./scripts",
        ] {
            assert!(hints_for(cmd, "deny").denies.is_empty(), "flagged: {cmd}");
        }
    }

    #[test]
    fn outside_project_left_to_jail_and_path_rules() {
        // /etc/passwd is outside — relative_hints ignores it (jail's job)
        assert!(hints_for("cat /etc/passwd", "deny").denies.is_empty());
    }

    #[test]
    fn dynamic_value_ignored() {
        // $HOME/... resolves at runtime; relative_hints only reasons about literals
        assert!(hints_for("cat $HOME/.ssh/config", "deny").denies.is_empty());
        assert!(
            hints_for("D=$TMPDIR/x cargo build", "deny")
                .denies
                .is_empty()
        );
    }

    #[test]
    fn setting_channels() {
        // an in-project absolute arg exercises the abs-paths deny/ask/warn/off channels
        let arg = "cat /Users/nobody/project/src/main.rs";
        assert_eq!(hints_for(arg, "ask").asks.len(), 1);
        assert_eq!(hints_for(arg, "warn").hints.len(), 1);
        assert!(hints_for(arg, "off").denies.is_empty());
    }

    #[test]
    fn nested_shell_arg_skipped() {
        // relative_hints only nags the outer command's own literal args, never a
        // sub-shell string's contents (include_synthetic = false)
        assert!(
            hints_for("bash -c 'cat /Users/nobody/project/src/main.rs'", "deny")
                .denies
                .is_empty()
        );
    }

    #[test]
    fn outside_paths_flagged() {
        assert_eq!(check("cat /etc/hosts", &[]), vec!["/etc/hosts"]);
        assert_eq!(
            check("cat ../outside.txt", &[]),
            vec!["/Users/nobody/outside.txt"]
        );
        assert_eq!(
            check("ls src/../../other", &[]),
            vec!["/Users/nobody/other"]
        );
        assert!(!check("cat ~/.zshrc", &[]).is_empty());
    }

    #[test]
    fn flag_attached_value_flagged() {
        assert_eq!(
            check("rg x --path=/var/log/sys.log", &[]),
            vec!["/var/log/sys.log"]
        );
    }

    #[test]
    fn project_paths_pass() {
        assert!(check("cat src/main.rs", &[]).is_empty());
        assert!(check(&format!("cat {CWD}/src/main.rs"), &[]).is_empty());
        assert!(check("cat src/../README.md", &[]).is_empty());
    }

    #[test]
    fn non_paths_pass() {
        assert!(check("curl https://example.com/etc/passwd", &[]).is_empty());
        assert!(check("echo a/b", &[]).is_empty());
    }

    #[test]
    fn allow_roots_grant_access() {
        assert!(check("cp a.txt /tmp/a.txt", &["/tmp"]).is_empty());
        assert!(check("cat /tmp/x", &[]).len() == 1);
        // sibling dir with the allowed root as prefix is NOT covered
        assert_eq!(check("cat /tmpfoo/x", &["/tmp"]), vec!["/tmpfoo/x"]);
    }

    // a jail_allow root reached by its symlinked spelling must still be trusted:
    // lexical containment misses it, the real_path fallback in is_trusted catches
    // it — so path_rules (which shares is_trusted) can't disagree on aliased roots.
    #[test]
    fn symlinked_allow_root_recognized() {
        let base = std::env::temp_dir().join(format!("lictor-jail-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real_dir = base.join("real-root");
        let alias_dir = base.join("alias-root");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &alias_dir).unwrap();

        // jail_allow lists the real dir; a path arriving via the alias spelling
        // must still be inside the jail (previously flagged as an escape)
        let command = format!("cat {}/notes.txt", alias_dir.to_str().unwrap());
        assert!(
            check(&command, &[real_dir.to_str().unwrap()]).is_empty(),
            "symlinked allow-root should be trusted by jail"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn synthetic_nested_shell_flagged() {
        // paths inside `bash -c '...'` are re-parsed and jailed like any other
        assert_eq!(check("bash -c 'cat /etc/hosts'", &[]), vec!["/etc/hosts"]);
    }

    #[test]
    fn home_env_var_paths_flagged() {
        let home = std::env::var("HOME").unwrap_or_default();
        assert_eq!(
            check("cat $HOME/.ssh/id_rsa", &[]),
            vec![format!("{home}/.ssh/id_rsa")]
        );
        assert_eq!(
            check("cat ${HOME}/.aws/creds", &[]),
            vec![format!("{home}/.aws/creds")]
        );
    }

    #[test]
    fn glued_flag_path_flagged() {
        assert_eq!(check("tail -o/etc/shadow", &[]), vec!["/etc/shadow"]);
        // alphabetic flag letter required — `-1/2`-style args stay untouched
        assert!(check("bc -1/2", &[]).is_empty());
    }

    #[test]
    fn duplicate_paths_reported_once() {
        assert_eq!(check("cat /etc/hosts /etc/hosts", &[]).len(), 1);
    }

    // CWD above doesn't exist on disk, so `git rev-parse` fails there and jail
    // falls back to plain-cwd anchoring (covered by the tests above). These use
    // this crate's own repo to exercise the git-root anchor for real.
    fn repo_subdir(rel: &str) -> String {
        format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn sibling_path_inside_repo_passes_from_subdir() {
        let subdir = repo_subdir("src/modules");
        assert!(check_at("cat ../../README.md", &[], &subdir).is_empty());
    }

    #[test]
    fn cd_to_repo_root_from_subdir_passes() {
        let subdir = repo_subdir("src/modules");
        assert!(check_at("cd ../..", &[], &subdir).is_empty());
    }

    #[test]
    fn path_outside_repo_still_flagged_from_subdir() {
        let subdir = repo_subdir("src/modules");
        assert_eq!(check_at("cat /etc/hosts", &[], &subdir), vec!["/etc/hosts"]);
    }

    #[test]
    fn multi_hop_cd_stays_in_bounds() {
        let subdir = repo_subdir("src/modules");
        assert!(check_at("cd .. && cd .. && cat docs/reference.md", &[], &subdir).is_empty());
        assert!(check_at("cd ../.. && rg TODO docs", &[], &subdir).is_empty());
    }

    #[test]
    fn multi_hop_cd_escape_now_detected() {
        // previously `../README.md` resolved against the ORIGINAL cwd
        // (src/modules), landing inside `src/` — a false negative. With `cd`
        // tracked, it resolves against the post-`cd ../..` cwd (repo root),
        // landing one level ABOVE the repo — correctly flagged.
        let subdir = repo_subdir("src/modules");
        assert_eq!(
            check_at("cd ../.. && cat ../README.md", &[], &subdir).len(),
            1
        );
    }

    #[test]
    fn absolute_cd_inside_repo_then_relative_path_passes() {
        let repo = env!("CARGO_MANIFEST_DIR");
        let subdir = repo_subdir("src/modules");
        let command = format!("cd {repo}/docs && cat ../README.md");
        assert!(check_at(&command, &[], &subdir).is_empty());
    }

    #[test]
    fn absolute_cd_outside_repo_flagged() {
        let subdir = repo_subdir("src/modules");
        assert_eq!(check_at("cd /etc && cat hosts", &[], &subdir), vec!["/etc"]);
    }

    #[test]
    fn bare_cd_home_then_escape_detected() {
        // bare `cd` goes to $HOME; a subsequent relative escape from there
        // used to be invisible (jail always resolved against the original cwd)
        assert_eq!(check("cd && cat ../evil", &[]).len(), 1);
    }

    #[test]
    fn cd_dash_freezes_instead_of_guessing() {
        // `cd -` needs OLDPWD, which we don't have; tracking freezes at the
        // last known cwd rather than dropping the escape entirely
        let subdir = repo_subdir("src/modules");
        assert!(!check_at("cd - && cat ../../../../../../etc/passwd", &[], &subdir).is_empty());
    }

    fn check_at(command: &str, allow: &[&str], cwd: &str) -> Vec<String> {
        violations(&bash::extract(command), &config(allow), cwd)
    }
}
