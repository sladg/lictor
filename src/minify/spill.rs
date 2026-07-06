use super::run_store;
use crate::audit;
use crate::config::Config;

pub struct SpillOutcome {
    pub stdout: String,
    pub key: String,
    pub bytes_in: usize,
    pub bytes_out: usize,
}

// last-resort context guard: oversized output goes to the kv store, the model
// gets the tail plus instructions to query the rest. Slow commands spill too,
// so the model queries the cache instead of re-running them while debugging.
pub fn spill(
    stdout: &str,
    command: &str,
    config: &Config,
    duration_ms: Option<u64>,
) -> Option<SpillOutcome> {
    let lines: Vec<&str> = stdout.lines().collect();
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
    let key = spill_key(command);
    let mut invocation = format!("{store} set {key}");
    if let Some(expires) = config.spill_expires() {
        invocation.push_str(&format!(" --expires-after {expires}"));
    }
    let stored = run_store(&invocation, stdout);
    let tail = lines[lines.len().saturating_sub(keep)..].join("\n");
    let why = match slow_secs {
        Some(secs) if !oversized => format!(
            "command took {secs}s — query the cache instead of re-running it ({} lines / {} bytes)",
            lines.len(),
            stdout.len(),
        ),
        _ => format!(
            "output too large: {} lines / {} bytes",
            lines.len(),
            stdout.len()
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
        bytes_in: stdout.len(),
        bytes_out: replacement.len(),
        stdout: replacement,
        key,
    })
}

fn spill_key(command: &str) -> String {
    let mut slug = String::new();
    for c in command.chars().take(40) {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    format!("lictor-{slug}-{}", audit::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        toml::from_str(toml).expect("test config parses")
    }

    #[test]
    fn spill_key_slugs_the_command() {
        let key = spill_key("cargo test --workspace 2>&1");
        assert!(key.starts_with("lictor-cargo-test-workspace-2-1-"), "{key}");
    }

    #[test]
    fn below_all_thresholds_no_spill() {
        let config = config("[settings]\nspill_lines = 100\nspill_seconds = 30");
        assert!(spill("a\nb\nc", "cargo test", &config, Some(5_000)).is_none());
    }

    #[test]
    fn slow_without_duration_signal_no_spill() {
        let config = config("[settings]\nspill_seconds = 30\nspill_keep = 2");
        assert!(spill("a\nb\nc\nd", "cargo test", &config, None).is_none());
    }

    #[test]
    fn unconfigured_never_spills() {
        assert!(
            spill(
                &"x\n".repeat(5000),
                "cargo test",
                &config(""),
                Some(120_000)
            )
            .is_none()
        );
    }
}
