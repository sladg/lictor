use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub ts: u64,
    pub kind: String, // "decision" | "rule-log" | "minify"
    pub event: String,
    pub tool: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<usize>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// a failing audit log must never break the hook
pub fn append(path: &Path, entries: &[Entry]) {
    if entries.is_empty() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    for entry in entries {
        let Ok(line) = serde_json::to_string(entry) else {
            continue;
        };
        let _ = writeln!(file, "{line}");
    }
}

pub fn summarize(raw: &str) -> String {
    let mut decisions: Vec<(String, usize)> = Vec::new();
    let mut minify_in: usize = 0;
    let mut minify_out: usize = 0;
    let mut per_rule: Vec<(String, usize, usize)> = Vec::new();
    let mut rule_logs: usize = 0;

    for line in raw.lines() {
        let Ok(entry) = serde_json::from_str::<Entry>(line) else {
            continue;
        };
        match entry.kind.as_str() {
            "decision" => {
                let key = entry.decision.unwrap_or("none".into());
                match decisions.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, n)) => *n += 1,
                    None => decisions.push((key, 1)),
                }
            }
            "rule-log" => rule_logs += 1,
            "minify" => {
                let (i, o) = (entry.bytes_in.unwrap_or(0), entry.bytes_out.unwrap_or(0));
                minify_in += i;
                minify_out += o;
                let key = entry.rule.unwrap_or("?".into());
                match per_rule.iter_mut().find(|(k, _, _)| *k == key) {
                    Some((_, ri, ro)) => {
                        *ri += i;
                        *ro += o;
                    }
                    None => per_rule.push((key, i, o)),
                }
            }
            _ => {}
        }
    }

    let mut out = String::new();
    out.push_str("decisions:\n");
    for (decision, count) in &decisions {
        out.push_str(&format!("  {decision:<8} {count}\n"));
    }
    out.push_str(&format!("rule-log entries: {rule_logs}\n"));
    if minify_in > 0 {
        let saved = minify_in.saturating_sub(minify_out);
        let pct = saved * 100 / minify_in;
        out.push_str(&format!(
            "minify: {minify_in} bytes -> {minify_out} bytes ({pct}% saved)\n"
        ));
        for (rule, i, o) in &per_rule {
            let pct = i.saturating_sub(*o) * 100 / i.max(&1);
            out.push_str(&format!("  {rule:<24} {i} -> {o} ({pct}%)\n"));
        }
    } else {
        out.push_str("minify: no entries\n");
    }
    out
}
