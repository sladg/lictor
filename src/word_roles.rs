use crate::bash::{Command, basename};

// which argument slots hold program text (a regex, a filter, a script) rather
// than a filesystem path — `sed -n '/needle/p' README.md` denies on
// `/needle/p` today because looks_like_path only sees "starts with /". This is
// a standalone pass over Command::words so it can be reused wherever else
// word-level intent matters (jail today; a future read/write/delete intent
// pass for [[path]] `on = [...]` wants the same tagging).
struct RoleRule {
    program: &'static str,
    // flags whose VALUE is a non-path expression (sed -e SCRIPT, grep -e PATTERN)
    expression_flags: &'static [&'static str],
    // flags whose value IS a real path (sed/awk's `-f FILE`) — also counts as
    // "the script/pattern is already supplied", same as expression_flags
    path_flags: &'static [&'static str],
    // known flags that take a value but are neither of the above (rg's -A/-m/
    // -g/...); skipped along with their value, never marked
    other_flags_with_arg: &'static [&'static str],
    // known flags that take NO value; safe to step over one at a time
    bare_flags: &'static [&'static str],
    // the first bare positional is the expression, UNLESS the pattern/script
    // already arrived via expression_flags/path_flags, or an unrecognized flag
    // appeared first — an unknown flag might have swallowed a value, so its
    // neighbor is not trustworthy as "the" first positional (fail safe: leave
    // it as a path candidate rather than risk hiding a real one)
    first_positional_is_expression: bool,
}

const ROLES: &[RoleRule] = &[
    RoleRule {
        program: "sed",
        expression_flags: &["-e", "--expression"],
        path_flags: &["-f", "--file"],
        other_flags_with_arg: &[],
        bare_flags: &[
            "-n", "-i", "-r", "-E", "-s", "-u", "-z", "--posix", "--quiet", "--silent",
            "--regexp-extended", "--separate", "--unbuffered", "--null-data",
        ],
        first_positional_is_expression: true,
    },
    RoleRule {
        program: "awk",
        expression_flags: &["-e"],
        path_flags: &["-f"],
        other_flags_with_arg: &["-v"],
        bare_flags: &["--posix", "--traditional"],
        first_positional_is_expression: true,
    },
    RoleRule {
        program: "rg",
        expression_flags: &["-e", "--regexp"],
        path_flags: &["-f", "--file"],
        other_flags_with_arg: &[
            "-A", "-B", "-C", "-g", "--glob", "--iglob", "-m", "--max-count", "-M",
            "--max-columns", "-t", "--type", "-T", "--type-not", "-r", "--replace",
            "--colors", "--color", "-j", "--threads", "--path-separator",
        ],
        bare_flags: &[
            "-i", "--ignore-case", "-v", "--invert-match", "-w", "--word-regexp", "-x",
            "--line-regexp", "-U", "--multiline", "-s", "--case-sensitive", "-S",
            "--smart-case", "-F", "--fixed-strings", "-P", "--pcre2", "-n", "--line-number",
            "-N", "--no-line-number", "-H", "--with-filename", "-I", "--no-ignore", "-o",
            "--only-matching", "-q", "--quiet", "-c", "--count", "-l", "--files-with-matches",
            "-L", "--files-without-match", "--hidden", "-a", "--text", "-z", "--search-zip",
            "--json", "--vimgrep", "-u", "--unrestricted", "--follow", "-0", "--null",
        ],
        first_positional_is_expression: true,
    },
    RoleRule {
        program: "grep",
        expression_flags: &["-e", "--regexp"],
        path_flags: &["-f", "--file"],
        other_flags_with_arg: &["-A", "-B", "-C", "--color", "--colour"],
        bare_flags: &[
            "-i", "--ignore-case", "-v", "--invert-match", "-w", "--word-regexp", "-x",
            "--line-regexp", "-c", "--count", "-l", "--files-with-matches", "-L",
            "--files-without-match", "-n", "--line-number", "-H", "--with-filename", "-h",
            "--no-filename", "-o", "--only-matching", "-q", "--quiet", "-s", "--no-messages",
            "-r", "-R", "--recursive", "-a", "--text", "-z", "--null-data", "-P",
            "--perl-regexp", "-E", "--extended-regexp", "-F", "--fixed-strings",
        ],
        first_positional_is_expression: true,
    },
    RoleRule {
        program: "find",
        expression_flags: &["-name", "-path", "-regex", "-iname"],
        path_flags: &[],
        other_flags_with_arg: &[],
        bare_flags: &[],
        first_positional_is_expression: false, // find's own first positional is the search root
    },
    RoleRule {
        program: "jq",
        expression_flags: &[],
        path_flags: &[],
        other_flags_with_arg: &[],
        bare_flags: &["-r", "-c", "-e", "-n", "-s", "-S", "-C", "-M", "-a", "--tab", "-j"],
        first_positional_is_expression: true,
    },
    RoleRule {
        program: "yq",
        expression_flags: &[],
        path_flags: &[],
        other_flags_with_arg: &[],
        bare_flags: &["-r", "-c", "-e", "-n", "-P", "-J", "-M", "-I"],
        first_positional_is_expression: true,
    },
];

// indices of `command.words` that hold program text, not a path — the caller
// (jail::walk_words) skips these when scanning for local filesystem escapes
pub(crate) fn expression_word_indices(command: &Command) -> Vec<usize> {
    let Some(program) = command.words.first().and_then(|w| w.text.as_deref()) else {
        return Vec::new();
    };
    let Some(rule) = ROLES.iter().find(|r| r.program == basename(program)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut script_supplied = false;
    let mut saw_positional = false;
    // stays true only while every flag seen so far is a recognized one — an
    // unrecognized flag might have consumed the next word as its own value
    let mut positional_trustworthy = true;
    let mut i = 1;
    while i < command.words.len() {
        let Some(text) = command.words[i].text.as_deref() else {
            i += 1;
            continue;
        };
        if rule.expression_flags.contains(&text) {
            script_supplied = true;
            if i + 1 < command.words.len() {
                out.push(i + 1);
            }
            i += 2;
            continue;
        }
        if rule.path_flags.contains(&text) {
            script_supplied = true;
            i += 2; // flag + its (real) path value, left untouched
            continue;
        }
        if rule.other_flags_with_arg.contains(&text) {
            i += 2; // flag + an unrelated value, left untouched
            continue;
        }
        if text.starts_with('-') && text != "-" {
            if !rule.bare_flags.contains(&text) {
                positional_trustworthy = false;
            }
            i += 1;
            continue;
        }
        // first bare positional
        if !saw_positional {
            saw_positional = true;
            if rule.first_positional_is_expression && !script_supplied && positional_trustworthy {
                out.push(i);
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bash;

    fn roles(command: &str) -> Vec<usize> {
        let extraction = bash::extract(command);
        expression_word_indices(&extraction.commands[0])
    }

    #[test]
    fn sed_script_is_first_positional_when_no_flag() {
        assert_eq!(roles("sed -n '/needle/p' README.md"), vec![2]);
        assert_eq!(roles("sed 's/foo/bar/g' README.md"), vec![1]);
    }

    #[test]
    fn sed_dash_e_marks_every_expression_value() {
        assert_eq!(roles("sed -e s/a/b/ -e s/c/d/ file.txt"), vec![2, 4]);
    }

    #[test]
    fn sed_dash_f_is_a_real_path_not_an_expression() {
        // the file supplies the script; README.md is a real edit target, not a script
        assert!(roles("sed -f /etc/scripts/x.sed README.md").is_empty());
    }

    #[test]
    fn awk_script_is_first_positional() {
        assert_eq!(roles("awk '/error/ {print $2}' log.txt"), vec![1]);
    }

    #[test]
    fn grep_and_rg_dash_e_pattern_marked() {
        assert_eq!(roles("grep -e '/api/v1' src/"), vec![2]);
        assert_eq!(roles("rg '/api/v1/users' src/"), vec![1]);
    }

    #[test]
    fn grep_with_dash_e_leaves_first_positional_a_path() {
        // the pattern already arrived via -e (index 2); file.txt (index 3) is a
        // plain file argument, not a second pattern
        assert_eq!(roles("grep -e foo file.txt"), vec![2]);
    }

    #[test]
    fn unknown_flag_with_arg_is_not_mistaken_for_the_pattern() {
        // rg's own arg-taking flags list can't be exhaustive; an unrecognized
        // one must not let its value be mistaken for the pattern (the
        // motivating regression: `rg --files --cwd /some/path`)
        assert!(roles("rg --files --cwd /Users/nobody/project").is_empty());
    }

    #[test]
    fn find_name_value_marked_but_search_root_is_not() {
        let indices = roles("find src -name '*.rs'");
        assert!(!indices.contains(&1)); // "src", the search root, stays a path
        assert!(indices.contains(&3)); // "*.rs", the -name value
    }

    #[test]
    fn jq_filter_is_first_positional() {
        assert_eq!(roles("jq .foo data.json"), vec![1]);
    }

    #[test]
    fn unrelated_program_untouched() {
        assert!(roles("cat /etc/hosts").is_empty());
    }
}
