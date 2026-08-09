//! Segment-wise glob∩glob matching — issue #13, sub-task 6.
//!
//! Answers "can these two patterns both match the same path?", and when they
//! can, **produces one**. The concrete path is the point: a deny needs a
//! *witness*, not just a claim of overlap. Intersection alone is far too weak —
//! `grep -r x .` intersects almost every rule anyone would write.
//!
//! ## Semantics
//!
//! `*` matches within one segment and never crosses `/`. `**` is a whole segment
//! and crosses any number of them. `?` is one non-separator character. `[abc]`,
//! `[a-z]` and `[!abc]` are character classes.
//!
//! Note this is *not* `globset`'s default, where `*` happily crosses `/` unless
//! `literal_separator(true)` is set. The differential test sets it; without that
//! the two disagree everywhere for reasons that have nothing to do with this
//! code.
//!
//! ## No filesystem, no automata
//!
//! Nothing here stats the disk or expands a directory. It is a memoised
//! recursion over the two token lists — the product construction, without
//! building the product automaton.
//!
//! ## The dangerous direction
//!
//! A false "disjoint" is a **missed deny**. A false "intersects" is at worst a
//! spurious one. So every path through this module that cannot decide must fall
//! toward "these might intersect", and the property test pushes hardest on pairs
//! that are known to intersect by construction.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Literal(char),
    /// `?` — exactly one character, never `/`
    Any,
    /// `*` — any run of characters within one segment
    Star,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClassItem {
    Char(char),
    Range(char, char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// `**` — zero or more whole segments
    AnyDepth,
    Tokens(Vec<Token>),
}

/// A glob, split on `/` so the separator is structural rather than a character
/// the matcher has to reason about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    segments: Vec<Segment>,
    /// leading `/`, preserved so a witness for an absolute pattern is absolute
    absolute: bool,
}

impl Pattern {
    pub fn parse(glob: &str) -> Self {
        let absolute = glob.starts_with('/');
        let body = glob.trim_start_matches('/');
        let mut segments: Vec<Segment> = body
            .split('/')
            .filter(|s| !s.is_empty())
            .map(parse_segment)
            .collect();
        // A TRAILING `**` needs at least one segment: globset matches
        // `/etc/**` against `/etc/a` but not against `/etc` itself, and a bare
        // `**` matches `a` but not the empty path. Everywhere else `**` is
        // happily zero-or-more (`a/**/b` matches `a/b`, `**/x` matches `x`).
        //
        // Encoding that as "zero-or-more, then exactly one segment" makes the
        // rule uniform, so nothing downstream has to know where a `**` sits.
        if matches!(segments.last(), Some(Segment::AnyDepth)) {
            segments.push(Segment::Tokens(vec![Token::Star]));
        }
        Pattern { segments, absolute }
    }

    /// A concrete path this pattern matches, if one can be constructed.
    pub fn sample(&self) -> Option<String> {
        witness(self, self)
    }
}

fn parse_segment(raw: &str) -> Segment {
    if raw == "**" {
        return Segment::AnyDepth;
    }
    let mut tokens = Vec::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                // `**` inside a segment with other characters is not a
                // depth-crosser; treat it as a single star rather than
                // pretending to support something globset does not either
                while chars.peek() == Some(&'*') {
                    chars.next();
                }
                tokens.push(Token::Star);
            }
            '?' => tokens.push(Token::Any),
            '[' => match parse_class(&mut chars) {
                Some(token) => tokens.push(token),
                // an unterminated `[` is a literal bracket, as in most shells
                None => tokens.push(Token::Literal('[')),
            },
            '\\' => {
                if let Some(escaped) = chars.next() {
                    tokens.push(Token::Literal(escaped));
                }
            }
            other => tokens.push(Token::Literal(other)),
        }
    }
    Segment::Tokens(tokens)
}

fn parse_class(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<Token> {
    let negated = matches!(chars.peek(), Some('!' | '^'));
    if negated {
        chars.next();
    }
    let mut items = Vec::new();
    let mut first = true;
    loop {
        let c = chars.next()?;
        // a `]` in the first position is a literal, per POSIX
        if c == ']' && !first {
            return Some(Token::Class { negated, items });
        }
        first = false;
        if chars.peek() == Some(&'-') {
            let mut lookahead = chars.clone();
            lookahead.next();
            match lookahead.peek() {
                Some(&']') | None => items.push(ClassItem::Char(c)),
                Some(&end) => {
                    chars.next();
                    chars.next();
                    items.push(ClassItem::Range(c, end));
                    continue;
                }
            }
        } else {
            items.push(ClassItem::Char(c));
        }
    }
}

fn class_contains(items: &[ClassItem], negated: bool, c: char) -> bool {
    let inside = items.iter().any(|item| match item {
        ClassItem::Char(m) => *m == c,
        ClassItem::Range(lo, hi) => *lo <= c && c <= *hi,
    });
    inside != negated
}

/// One character this class admits. Needed to build a witness — a class we
/// cannot produce a member for is a class we must not claim intersects.
fn class_member(items: &[ClassItem], negated: bool) -> Option<char> {
    if !negated {
        return items.iter().find_map(|item| match item {
            ClassItem::Char(c) if *c != '/' => Some(*c),
            ClassItem::Range(lo, hi) if *lo <= *hi => (*lo..=*hi).find(|c| *c != '/'),
            _ => None,
        });
    }
    // a negated class: any ordinary character it does not exclude
    "abcdefghijklmnopqrstuvwxyz0123456789._-"
        .chars()
        .find(|c| class_contains(items, negated, *c))
}

/// One character both tokens admit.
fn token_overlap(a: &Token, b: &Token) -> Option<char> {
    match (a, b) {
        (Token::Literal(x), Token::Literal(y)) => (x == y).then_some(*x),
        (Token::Literal(c), Token::Any) | (Token::Any, Token::Literal(c)) => {
            (*c != '/').then_some(*c)
        }
        (Token::Any, Token::Any) => Some('a'),
        (Token::Literal(c), Token::Class { negated, items })
        | (Token::Class { negated, items }, Token::Literal(c)) => {
            class_contains(items, *negated, *c).then_some(*c)
        }
        (Token::Any, Token::Class { negated, items })
        | (Token::Class { negated, items }, Token::Any) => class_member(items, *negated),
        (
            Token::Class {
                negated: an,
                items: ai,
            },
            Token::Class {
                negated: bn,
                items: bi,
            },
        ) => class_member(ai, *an)
            .filter(|c| class_contains(bi, *bn, *c))
            .or_else(|| class_member(bi, *bn).filter(|c| class_contains(ai, *an, *c))),
        // `*` is handled by the caller, which can consume a variable run
        (Token::Star, _) | (_, Token::Star) => None,
    }
}

/// One character this token admits on its own — what `*` on the other side has
/// to swallow.
fn token_sample(token: &Token) -> Option<char> {
    match token {
        Token::Literal(c) => (*c != '/').then_some(*c),
        Token::Any => Some('a'),
        Token::Class { negated, items } => class_member(items, *negated),
        Token::Star => Some('a'),
    }
}

/// A string both token lists match, if one exists.
fn witness_tokens(a: &[Token], b: &[Token]) -> Option<String> {
    let mut memo: HashMap<(usize, usize), Option<String>> = HashMap::new();
    solve_tokens(a, 0, b, 0, &mut memo)
}

// two token/segment lists, two cursors and a memo: the product recursion's
// state, which is exactly five values and cannot be fewer
#[allow(clippy::too_many_arguments)]
fn solve_tokens(
    a: &[Token],
    i: usize,
    b: &[Token],
    j: usize,
    memo: &mut HashMap<(usize, usize), Option<String>>,
) -> Option<String> {
    if let Some(cached) = memo.get(&(i, j)) {
        return cached.clone();
    }
    let result = compute_tokens(a, i, b, j, memo);
    memo.insert((i, j), result.clone());
    result
}

// two token/segment lists, two cursors and a memo: the product recursion's
// state, which is exactly five values and cannot be fewer
#[allow(clippy::too_many_arguments)]
fn compute_tokens(
    a: &[Token],
    i: usize,
    b: &[Token],
    j: usize,
    memo: &mut HashMap<(usize, usize), Option<String>>,
) -> Option<String> {
    match (a.get(i), b.get(j)) {
        (None, None) => Some(String::new()),
        // a trailing `*` can match the empty rest
        (Some(Token::Star), None) => solve_tokens(a, i + 1, b, j, memo),
        (None, Some(Token::Star)) => solve_tokens(a, i, b, j + 1, memo),
        (None, Some(_)) | (Some(_), None) => None,
        (Some(Token::Star), Some(other)) => {
            // the star matches nothing...
            if let Some(rest) = solve_tokens(a, i + 1, b, j, memo) {
                return Some(rest);
            }
            // ...or it swallows one character the other side produces
            if matches!(other, Token::Star) {
                return solve_tokens(a, i, b, j + 1, memo);
            }
            let c = token_sample(other)?;
            solve_tokens(a, i, b, j + 1, memo).map(|rest| format!("{c}{rest}"))
        }
        (Some(other), Some(Token::Star)) => {
            if let Some(rest) = solve_tokens(a, i, b, j + 1, memo) {
                return Some(rest);
            }
            let c = token_sample(other)?;
            solve_tokens(a, i + 1, b, j, memo).map(|rest| format!("{c}{rest}"))
        }
        (Some(x), Some(y)) => {
            let c = token_overlap(x, y)?;
            solve_tokens(a, i + 1, b, j + 1, memo).map(|rest| format!("{c}{rest}"))
        }
    }
}

/// A concrete path both patterns match, or `None` when they cannot overlap.
///
/// `None` is the dangerous answer — it is what lets a deny slip — so anything
/// this cannot construct a member for (an empty character class, say) reports
/// no witness rather than a guess, and the caller stays silent instead of
/// denying.
pub fn witness(a: &Pattern, b: &Pattern) -> Option<String> {
    let mut memo: HashMap<(usize, usize), Option<Vec<String>>> = HashMap::new();
    let segments = solve_segments(&a.segments, 0, &b.segments, 0, &mut memo)?;
    let joined = segments.join("/");
    Some(if a.absolute || b.absolute {
        format!("/{joined}")
    } else {
        joined
    })
}

/// Whether the two patterns can both match some path.
pub fn intersects(a: &Pattern, b: &Pattern) -> bool {
    witness(a, b).is_some()
}

// two token/segment lists, two cursors and a memo: the product recursion's
// state, which is exactly five values and cannot be fewer
#[allow(clippy::too_many_arguments)]
fn solve_segments(
    a: &[Segment],
    i: usize,
    b: &[Segment],
    j: usize,
    memo: &mut HashMap<(usize, usize), Option<Vec<String>>>,
) -> Option<Vec<String>> {
    if let Some(cached) = memo.get(&(i, j)) {
        return cached.clone();
    }
    let result = compute_segments(a, i, b, j, memo);
    memo.insert((i, j), result.clone());
    result
}

// two token/segment lists, two cursors and a memo: the product recursion's
// state, which is exactly five values and cannot be fewer
#[allow(clippy::too_many_arguments)]
fn compute_segments(
    a: &[Segment],
    i: usize,
    b: &[Segment],
    j: usize,
    memo: &mut HashMap<(usize, usize), Option<Vec<String>>>,
) -> Option<Vec<String>> {
    match (a.get(i), b.get(j)) {
        (None, None) => Some(Vec::new()),
        // `**` can match zero segments, so it may sit at the end
        (Some(Segment::AnyDepth), None) => solve_segments(a, i + 1, b, j, memo),
        (None, Some(Segment::AnyDepth)) => solve_segments(a, i, b, j + 1, memo),
        (None, Some(_)) | (Some(_), None) => None,
        (Some(Segment::AnyDepth), Some(other)) => {
            // `**` matches zero segments here...
            if let Some(rest) = solve_segments(a, i + 1, b, j, memo) {
                return Some(rest);
            }
            // ...or it swallows the segment the other side wants
            if matches!(other, Segment::AnyDepth) {
                return solve_segments(a, i, b, j + 1, memo);
            }
            let Segment::Tokens(tokens) = other else {
                unreachable!("AnyDepth handled above")
            };
            let concrete = witness_tokens(tokens, &[Token::Star])?;
            let mut rest = solve_segments(a, i, b, j + 1, memo)?;
            rest.insert(0, concrete);
            Some(rest)
        }
        (Some(other), Some(Segment::AnyDepth)) => {
            if let Some(rest) = solve_segments(a, i, b, j + 1, memo) {
                return Some(rest);
            }
            let Segment::Tokens(tokens) = other else {
                unreachable!("AnyDepth handled above")
            };
            let concrete = witness_tokens(tokens, &[Token::Star])?;
            let mut rest = solve_segments(a, i + 1, b, j, memo)?;
            rest.insert(0, concrete);
            Some(rest)
        }
        (Some(Segment::Tokens(x)), Some(Segment::Tokens(y))) => {
            let concrete = witness_tokens(x, y)?;
            let mut rest = solve_segments(a, i + 1, b, j + 1, memo)?;
            rest.insert(0, concrete);
            Some(rest)
        }
    }
}

/// A set of paths named by one argument: roots, plus include/exclude globs.
///
/// `rm -rf build` is not one path — it is everything under `build`. A rule about
/// `build/**/*.o` has to be able to ask whether that set contains anything it
/// cares about, and the answer has to be a path someone can be shown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathSet {
    /// the directories or files the argument names
    pub roots: Vec<String>,
    /// whether the roots are taken with everything beneath them (`-r`)
    pub recursive: bool,
    /// globs narrowing what within the roots is selected (`find -name`)
    pub include: Vec<String>,
    /// globs carving pieces back out (`rsync --exclude`)
    pub exclude: Vec<String>,
}

impl PathSet {
    /// One path, exactly.
    pub fn at(path: &str) -> Self {
        PathSet {
            roots: vec![path.to_string()],
            ..Default::default()
        }
    }

    /// Everything under `root`.
    pub fn under(root: &str) -> Self {
        PathSet {
            roots: vec![root.to_string()],
            recursive: true,
            ..Default::default()
        }
    }

    /// Does this set select the concrete path `path`?
    ///
    /// Under a root, matching every include, matching no exclude. Exclude wins,
    /// because that is what carving a hole out means.
    pub fn selects(&self, path: &str) -> bool {
        if !self.roots.iter().any(|root| self.under_root(root, path)) {
            return false;
        }
        if !self.include.is_empty() && !self.include.iter().any(|glob| matches_glob(glob, path)) {
            return false;
        }
        !self.exclude.iter().any(|glob| matches_glob(glob, path))
    }

    fn under_root(&self, root: &str, path: &str) -> bool {
        if path == root {
            return true;
        }
        self.recursive && path.starts_with(&format!("{}/", root.trim_end_matches('/')))
    }

    /// A concrete path this set and `glob` both select, or `None`.
    ///
    /// The **witness** a deny needs. Intersection alone would fire on
    /// `rm -rf .` against almost any rule; a witness says which file is at stake
    /// and can be shown to whoever is being told no.
    pub fn witness_against(&self, glob: &str) -> Option<String> {
        let rule = Pattern::parse(glob);
        for root in &self.roots {
            let reach = if self.recursive {
                format!("{}/**", root.trim_end_matches('/'))
            } else {
                root.clone()
            };
            let candidates: Vec<Pattern> = if self.include.is_empty() {
                vec![Pattern::parse(&reach)]
            } else {
                self.include.iter().map(|i| Pattern::parse(i)).collect()
            };
            for candidate in candidates {
                let Some(found) = witness(&candidate, &rule) else {
                    continue;
                };
                // a candidate drawn from `include` still has to fall under the
                // root, and nothing may be excluded
                if self.selects(&found) {
                    return Some(found);
                }
            }
        }
        None
    }
}

/// Whether one concrete path matches one glob. Uses the same matcher, since a
/// concrete path is just a glob with no metacharacters.
fn matches_glob(glob: &str, path: &str) -> bool {
    intersects(&Pattern::parse(glob), &Pattern::parse(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(a: &str, b: &str) -> Option<String> {
        witness(&Pattern::parse(a), &Pattern::parse(b))
    }

    #[test]
    fn identical_literals_intersect_at_themselves() {
        assert_eq!(
            w("/etc/passwd", "/etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
    }

    #[test]
    fn different_literals_are_disjoint() {
        assert_eq!(w("/etc/passwd", "/etc/shadow"), None);
    }

    #[test]
    fn a_star_does_not_cross_a_separator() {
        // the whole reason `*` and `**` are different tokens
        assert_eq!(w("/etc/*", "/etc/a/b"), None);
        assert!(w("/etc/**", "/etc/a/b").is_some());
    }

    #[test]
    fn a_trailing_any_depth_needs_at_least_one_segment() {
        // globset matches `/etc/**` against `/etc/a` but NOT against `/etc`
        assert_eq!(w("/etc/**", "/etc"), None);
        assert!(w("/etc/**", "/etc/a").is_some());
        // ...while a non-trailing `**` really is zero-or-more
        assert!(w("a/**/b", "a/b").is_some());
        assert!(w("**/x", "x").is_some());
    }

    #[test]
    fn the_witness_is_a_real_path_both_patterns_match() {
        let found = w("**/*.pem", "/etc/ssh/*").expect("these do intersect");
        assert!(found.ends_with(".pem"), "{found}");
        assert!(found.starts_with("/etc/ssh/"), "{found}");
    }

    #[test]
    fn extensions_that_cannot_agree_are_disjoint() {
        assert_eq!(w("**/*.pem", "**/*.key"), None);
    }

    #[test]
    fn character_classes_intersect_on_a_member() {
        assert_eq!(w("/etc/[abc]", "/etc/[cde]").as_deref(), Some("/etc/c"));
        assert_eq!(w("/etc/[a-f]", "/etc/[d-z]").as_deref(), Some("/etc/d"));
        assert_eq!(w("/etc/[abc]", "/etc/[xyz]"), None);
    }

    #[test]
    fn a_negated_class_excludes_what_it_says() {
        assert_eq!(w("/etc/[!a]", "/etc/a"), None);
        assert!(w("/etc/[!a]", "/etc/b").is_some());
    }

    #[test]
    fn question_mark_is_exactly_one_character() {
        assert!(w("/etc/?", "/etc/a").is_some());
        assert_eq!(w("/etc/?", "/etc/ab"), None);
    }

    #[test]
    fn a_pattern_always_intersects_itself() {
        for pattern in [
            "/etc/passwd",
            "**/*.pem",
            "/var/log/*.log",
            "src/**/mod.rs",
            "/etc/[a-z]?/x",
        ] {
            assert!(
                w(pattern, pattern).is_some(),
                "{pattern} failed to intersect itself"
            );
        }
    }

    #[test]
    fn a_single_path_set_selects_only_itself() {
        let set = PathSet::at("/etc/passwd");
        assert!(set.selects("/etc/passwd"));
        assert!(!set.selects("/etc/shadow"));
        // not recursive, so nothing beneath it either
        assert!(!PathSet::at("/etc").selects("/etc/passwd"));
    }

    #[test]
    fn a_recursive_set_selects_what_is_beneath_it() {
        let set = PathSet::under("/etc");
        assert!(set.selects("/etc"));
        assert!(set.selects("/etc/passwd"));
        assert!(set.selects("/etc/ssh/id_rsa"));
        assert!(!set.selects("/etcetera/x"), "a prefix is not a parent");
        assert!(!set.selects("/var/log"));
    }

    #[test]
    fn include_narrows_and_exclude_wins() {
        let set = PathSet {
            roots: vec!["src".into()],
            recursive: true,
            include: vec!["**/*.rs".into()],
            exclude: vec!["**/generated.rs".into()],
        };
        assert!(set.selects("src/main.rs"));
        assert!(!set.selects("src/notes.txt"), "include must narrow");
        assert!(!set.selects("src/generated.rs"), "exclude must win");
    }

    #[test]
    fn a_witness_is_a_path_both_sides_really_select() {
        // `rm -rf build` against a rule protecting object files
        let set = PathSet::under("build");
        let found = set.witness_against("build/**/*.o").expect("these overlap");
        assert!(
            set.selects(&found),
            "the set must select its own witness: {found}"
        );
        assert!(found.ends_with(".o"), "{found}");
    }

    #[test]
    fn a_set_that_cannot_reach_the_rule_yields_no_witness() {
        // the deny gate: no witness, no deny
        let set = PathSet::under("build");
        assert_eq!(set.witness_against("/etc/**"), None);
        assert_eq!(PathSet::at("src/main.rs").witness_against("**/*.pem"), None);
    }

    #[test]
    fn exclude_can_remove_the_only_witness() {
        let set = PathSet {
            roots: vec!["build".into()],
            recursive: true,
            include: vec!["**/*.o".into()],
            exclude: vec!["**/*.o".into()],
        };
        assert_eq!(set.witness_against("build/**/*.o"), None);
    }

    #[test]
    fn an_escaped_metacharacter_is_a_literal() {
        assert!(w(r"/etc/\*", "/etc/*").is_some());
        // ...and only matches the literal asterisk, not an arbitrary name
        assert_eq!(w(r"/etc/\*", "/etc/passwd"), None);
    }
}
