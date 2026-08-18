use super::run_store;
use crate::audit;
use crate::config::Config;

pub struct SpillOutcome {
    pub output: String,
    pub key: String,
    pub bytes_in: usize,
    pub bytes_out: usize,
}

// last-resort context guard: oversized output goes to the kv store, the model
// gets the tail plus instructions to query the rest. Slow commands spill too,
// so the model queries the cache instead of re-running them while debugging.
// Runs once per stream — compilers and test runners emit their volume on
// stderr, which `2>&1` merges into the stdout pass but a bare command doesn't.
// four unrelated inputs to one decision.
#[allow(clippy::too_many_arguments)]
pub fn spill(
    text: &str,
    command: &str,
    config: &Config,
    duration_ms: Option<u64>,
    stream: &str,
) -> Option<SpillOutcome> {
    let lines: Vec<&str> = text.lines().collect();
    let keep = config.spill_keep();
    let oversized = config.spill_lines().is_some_and(|t| lines.len() > t);
    let slow_secs = config.spill_seconds().and_then(|threshold| {
        let secs = duration_ms? / 1000;
        // a slow command's output only spills when the tail would hide part of it
        (secs >= threshold && lines.len() > keep).then_some(secs)
    });
    if !oversized && slow_secs.is_none() {
        return None;
    }
    let store = config.spill_command();
    let key = spill_key(command, stream);
    let mut invocation = format!("{store} set {key}");
    if let Some(expires) = config.spill_expires() {
        invocation.push_str(&format!(" --expires-after {expires}"));
    }
    let stored = run_store(&invocation, text);
    let tail = lines[lines.len().saturating_sub(keep)..].join("\n");
    let label = if stream == "stderr" {
        "stderr"
    } else {
        "output"
    };
    let why = match slow_secs {
        Some(secs) if !oversized => format!(
            "command took {secs}s — query the cache instead of re-running it ({} {label} lines / {} bytes)",
            lines.len(),
            text.len(),
        ),
        _ => format!(
            "{label} too large: {} lines / {} bytes",
            lines.len(),
            text.len()
        ),
    };
    let note = if stored {
        format!(
            "[lictor] {why}. Full output stored: retrieve with `{store} get {key}` and pipe through rg/tail — do not dump it whole. Last {keep} lines:\n",
        )
    } else {
        format!(
            "[lictor] {why}; storing via `{store}` FAILED (not installed?). Last {keep} lines:\n",
        )
    };
    let replacement = note + &tail;
    Some(SpillOutcome {
        bytes_in: text.len(),
        bytes_out: replacement.len(),
        output: replacement,
        key,
    })
}

fn spill_key(command: &str, stream: &str) -> String {
    let mut slug = String::new();
    for c in command.chars().take(40) {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    let tag = if stream == "stderr" { "-stderr" } else { "" };
    format!("lictor-{slug}{tag}-{}", audit::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        toml::from_str(toml).expect("test config parses")
    }

    #[test]
    fn spill_key_slugs_the_command() {
        let key = spill_key("cargo test --workspace 2>&1", "stdout");
        assert!(key.starts_with("lictor-cargo-test-workspace-2-1-"), "{key}");
    }

    #[test]
    fn spill_key_tags_the_stderr_stream() {
        let key = spill_key("cargo build", "stderr");
        assert!(key.starts_with("lictor-cargo-build-stderr-"), "{key}");
    }

    #[test]
    fn below_all_thresholds_no_spill() {
        let config = config("[settings]\nspill_lines = 100\nspill_seconds = 30");
        assert!(spill("a\nb\nc", "cargo test", &config, Some(5_000), "stdout").is_none());
    }

    #[test]
    fn slow_without_duration_signal_no_spill() {
        let config = config("[settings]\nspill_seconds = 30\nspill_keep = 2");
        assert!(spill("a\nb\nc\nd", "cargo test", &config, None, "stdout").is_none());
    }

    #[test]
    fn unconfigured_never_spills() {
        assert!(
            spill(
                &"x\n".repeat(5000),
                "cargo test",
                &config(""),
                Some(120_000),
                "stdout"
            )
            .is_none()
        );
    }
}
