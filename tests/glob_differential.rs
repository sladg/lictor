//! The merge gate for the glob∩glob matcher — issue #13, sub-task 6.
//!
//! `globset` is the oracle. It answers "does this pattern match this path?", so
//! it can check a witness directly: if [`globs::witness`] hands back a path, both
//! patterns must really match it. That makes a positive answer **self-verifying**
//! — no reference implementation of intersection is needed for the half of the
//! problem that is easy to get wrong quietly.
//!
//! ## Which direction is dangerous
//!
//! A false **disjoint** is a missed deny. A false **intersects** is at worst a
//! spurious one. So the weight of this file is on the first: most of it
//! constructs pairs that are *known* to intersect and insists the matcher finds
//! a witness.
//!
//! ## The separator trap
//!
//! `globset`'s `*` crosses `/` unless `literal_separator(true)` is set — its
//! default disagrees with the semantics this matcher implements, and with what
//! anyone writing `/etc/*` means. Building the oracle without that flag makes
//! every comparison fail for a reason that has nothing to do with the code under
//! test. `oracle()` sets it; `the_oracle_uses_the_semantics_we_claim` pins it, so
//! a future globset default cannot quietly move the goalposts.

use globset::GlobBuilder;
use lictor::globs::{self, Pattern};

fn oracle(pattern: &str) -> globset::GlobMatcher {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .unwrap_or_else(|e| panic!("globset rejected {pattern:?}: {e}"))
        .compile_matcher()
}

fn witness(a: &str, b: &str) -> Option<String> {
    globs::witness(&Pattern::parse(a), &Pattern::parse(b))
}

#[test]
fn the_oracle_uses_the_semantics_we_claim() {
    // If this ever fails, every other assertion here is comparing against the
    // wrong thing: globset's DEFAULT lets `*` cross `/`, which is not what
    // `/etc/*` means to anyone writing a rule.
    assert!(
        !oracle("/etc/*").is_match("/etc/a/b"),
        "`*` must not cross a separator"
    );
    assert!(
        oracle("/etc/**").is_match("/etc/a/b"),
        "`**` must cross separators"
    );
}

#[test]
fn every_witness_is_matched_by_both_patterns() {
    // the self-verifying half: a positive answer is checkable outright
    let mut checked = 0usize;
    for a in PATTERNS {
        for b in PATTERNS {
            let Some(found) = witness(a, b) else { continue };
            assert!(
                oracle(a).is_match(&found),
                "witness {found:?} for ({a:?}, {b:?}) is not matched by {a:?}"
            );
            assert!(
                oracle(b).is_match(&found),
                "witness {found:?} for ({a:?}, {b:?}) is not matched by {b:?}"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 100,
        "expected many intersecting pairs, got {checked}"
    );
    println!("{checked} witnesses verified against globset");
}

#[test]
fn patterns_that_share_a_known_path_are_never_called_disjoint() {
    // THE dangerous direction. Rather than trusting a hand-written list of
    // "these should intersect", build the guarantee: take a concrete path,
    // derive several patterns that provably match it (globset confirms), and
    // insist every pair of them finds a witness.
    let mut checked = 0usize;
    for path in PATHS {
        let matching: Vec<&str> = PATTERNS
            .iter()
            .copied()
            .filter(|p| oracle(p).is_match(path))
            .collect();
        for a in &matching {
            for b in &matching {
                assert!(
                    witness(a, b).is_some(),
                    "MISSED DENY: {a:?} and {b:?} both match {path:?}, \
                     but the matcher called them disjoint"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > 100,
        "expected many known-intersecting pairs, got {checked}"
    );
    println!("{checked} known-intersecting pairs confirmed");
}

#[test]
fn generated_patterns_covering_a_path_always_intersect() {
    // The same guarantee, but with the patterns generated FROM each path rather
    // than drawn from a fixed list — so the corpus cannot quietly stop
    // exercising a construct.
    let mut checked = 0usize;
    for path in PATHS {
        let derived = patterns_matching(path);
        for a in &derived {
            assert!(
                oracle(a).is_match(path),
                "derived pattern {a:?} does not match {path:?} — the generator is wrong"
            );
        }
        for a in &derived {
            for b in &derived {
                let found = witness(a, b).unwrap_or_else(|| {
                    panic!("MISSED DENY: {a:?} and {b:?} both match {path:?}, called disjoint")
                });
                assert!(oracle(a).is_match(&found) && oracle(b).is_match(&found));
                checked += 1;
            }
        }
    }
    println!("{checked} generated pairs confirmed");
}

/// Patterns that provably match `path`, built by weakening it a piece at a time.
fn patterns_matching(path: &str) -> Vec<String> {
    let trimmed = path.trim_start_matches('/');
    let segments: Vec<&str> = trimmed.split('/').collect();
    let lead = if path.starts_with('/') { "/" } else { "" };
    let mut out = vec![path.to_string()];

    // replace each segment with `*`
    for i in 0..segments.len() {
        let mut copy: Vec<String> = segments.iter().map(|s| (*s).to_string()).collect();
        copy[i] = "*".to_string();
        out.push(format!("{lead}{}", copy.join("/")));
    }
    // a `**` prefix, and a `**` in the middle
    out.push(format!("**/{}", segments.last().unwrap()));
    if segments.len() > 1 {
        out.push(format!("{lead}{}/**", segments[0]));
    }
    // an extension glob, when there is an extension to glob
    if let Some((_, ext)) = segments.last().unwrap().rsplit_once('.') {
        out.push(format!("**/*.{ext}"));
        // ...and one anchored to the parent, only when there IS a parent:
        // a single-segment path would produce `/*.pem`, which matches nothing
        if segments.len() > 1 {
            let parent = segments[..segments.len() - 1].join("/");
            out.push(format!("{lead}{parent}/*.{ext}"));
        }
    }
    out.retain(|p| !p.contains("//"));
    out
}

#[test]
fn disjoint_answers_survive_a_search_for_a_counterexample() {
    // The other direction is not directly checkable — there is no way to
    // enumerate every path. So when the matcher says "disjoint", search a
    // generated space for something that would disprove it.
    let mut pairs = 0usize;
    for a in PATTERNS {
        for b in PATTERNS {
            if witness(a, b).is_some() {
                continue;
            }
            let (ma, mb) = (oracle(a), oracle(b));
            for candidate in PATHS {
                assert!(
                    !(ma.is_match(candidate) && mb.is_match(candidate)),
                    "MISSED DENY: {a:?} and {b:?} were called disjoint, \
                     but both match {candidate:?}"
                );
            }
            pairs += 1;
        }
    }
    println!("{pairs} disjoint verdicts survived the counterexample search");
}

#[test]
fn a_pattern_never_fails_to_intersect_itself() {
    // the weakest possible sanity property, and the one whose failure would
    // make every deny unreliable at once
    for pattern in PATTERNS {
        let found = witness(pattern, pattern)
            .unwrap_or_else(|| panic!("{pattern:?} does not intersect itself"));
        assert!(
            oracle(pattern).is_match(&found),
            "{pattern:?} produced a self-witness {found:?} it does not match"
        );
    }
}

const PATTERNS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/*",
    "/etc/**",
    "/etc/ssh/*",
    "/etc/ssh/**",
    "/etc/ssh/id_rsa",
    "**/*.pem",
    "**/*.key",
    "**/*.rs",
    "**/id_*",
    "/var/log/*.log",
    "/var/**/*.log",
    "src/**",
    "src/*.rs",
    "src/**/mod.rs",
    "src/modules/*.rs",
    "**",
    "*",
    "/home/*/.ssh/*",
    "/home/**/.ssh/id_*",
    "/etc/[a-z]*",
    "/etc/?????wd",
    "build/**/*.o",
];

const PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/ssh/id_rsa",
    "/etc/ssh/id_rsa.pem",
    "/etc/ssh/sshd_config",
    "/var/log/syslog.log",
    "/var/log/nginx/access.log",
    "src/main.rs",
    "src/modules/jail.rs",
    "src/modules/mod.rs",
    "/home/u/.ssh/id_ed25519",
    "/home/u/.ssh/config",
    "build/a/b.o",
    "secrets.pem",
    "a.key",
];
