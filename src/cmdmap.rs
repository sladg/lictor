//! Per-program argument maps — issue #13, sub-task 5.
//!
//! The one question the 13 hand-maintained tables in `bash.rs` were all
//! fragments of: **what does this argument mean to this program?**
//!
//! A map says which slots are paths, which flags consume the next word, and what
//! the program does to what it names. The graph turns that into reference edges;
//! rules query the edges. Nothing here is a heuristic — a program either has a
//! map or it does not.
//!
//! ## The inverted default
//!
//! **No map → no reference edges → lictor says nothing about that program.**
//!
//! An unmapped command cannot produce a false positive, which is the whole point
//! of #13: today every `/`-leading word is assumed to be a filesystem path, and
//! four layers of heuristic exist to walk that assumption back. The cost is
//! silence on unmapped programs, and silence is the honest failure direction —
//! a parser can never be a security boundary, only a lint.
//!
//! ## Deliberately not Turing-complete
//!
//! Slots, kinds and effects, and nothing else. No conditionals, no expressions,
//! no escape hatch to arbitrary code. A map that cannot express something is a
//! map that gets extended after review, not a map that grows a scripting
//! language.
//!
//! ## Trust
//!
//! Hand-written and reviewed only. There are no provenance tiers, and `--help`
//! output is never consulted at runtime. The recipes live in `recipes/`, one file
//! per program; see `recipes/README.md` for the format and the review rule.

use serde::Deserialize;
use std::collections::HashMap;

// `RECIPES: &[(&str, &str)]` — every `recipes/*.toml`, embedded at build time.
// One file per program: `aws` and `kubectl` will each dwarf every current
// recipe, and a single map file would not survive them.
include!(concat!(env!("OUT_DIR"), "/recipes.rs"));

#[derive(Debug, Default, Deserialize)]
pub struct Maps {
    #[serde(default, rename = "cmd")]
    programs: Vec<Program>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub name: String,
    /// when set, this map only applies if the leading positionals match
    /// (`git rm` behaves nothing like `git log`).
    ///
    /// Space-separated for a nested tree: `subcommand = "s3 cp"` matches
    /// `aws s3 cp`. Depth matters because the alternative is guessing a slot
    /// number — `aws s3 cp SRC DST` and `aws s3 rm KEY` share `s3` and agree
    /// about nothing after it.
    #[serde(default)]
    pub subcommand: Option<String>,
    #[serde(default)]
    pub flags: HashMap<String, Flag>,
    #[serde(default, rename = "args")]
    pub args: Vec<Arg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flag {
    /// this flag consumes the following word, so that word is not a positional.
    /// Getting this wrong shifts every slot after it, which is why it is a map
    /// fact and not a guess about leading dashes.
    #[serde(default)]
    pub takes: bool,
    #[serde(default)]
    pub kind: Kind,
    #[serde(default)]
    pub effect: Vec<Effect>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arg {
    pub slots: Slots,
    #[serde(default)]
    pub kind: Kind,
    #[serde(default)]
    pub effect: Vec<Effect>,
    /// only apply this entry when the flags present say so
    #[serde(default)]
    pub when: Option<When>,
    /// this argument always names a tree, with no flag needed (`find` descends
    /// by definition)
    #[serde(default)]
    pub recursive: bool,
    /// flags that turn this argument from one path into everything beneath it.
    /// `rm build` names a file; `rm -r build` names a tree, and a rule about
    /// `build/**/*.o` has to be able to see the difference.
    #[serde(default)]
    pub recursive_with: Vec<String>,
}

/// A guard on an argument entry.
///
/// Not decoration: `grep PATTERN file` and `grep -e PATTERN file` disagree about
/// what slot 0 *is*. Without a way to say "slot 0 is the pattern only when no
/// `-e` was given", grep's map is wrong in one direction or the other — either
/// the pattern is read as a path (the #4 false positive) or a real file loses
/// its read edge.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct When {
    /// every one of these flags must be present
    #[serde(default)]
    pub with: Vec<String>,
    /// none of these flags may be present
    #[serde(default)]
    pub without: Vec<String>,
}

impl When {
    pub fn holds(&self, flags: &[String]) -> bool {
        self.with.iter().all(|f| flags.iter().any(|p| p == f))
            && !self.without.iter().any(|f| flags.iter().any(|p| p == f))
    }
}

/// Which positional slots an entry covers, counted **after** flag arguments have
/// been removed — `grep -e pat file` has one positional, not two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum Slots {
    /// every positional
    All,
    /// slot 0
    First,
    /// the final positional (`cp src dst`'s destination)
    Last,
    /// every positional but the final one (`cp src... dst`'s sources)
    ExceptLast,
    /// from slot `n` onward, taken together as a nested command. `rest` is
    /// `From(0)` — `sudo`, `xargs`, `env`. `1+` is `From(1)`, which is what
    /// `ssh HOST command…` needs: slot 0 names the machine, and the payload
    /// starts after it.
    From(usize),
    /// one specific slot
    At(usize),
}

impl Slots {
    /// Where a nested command's program word sits, if this is a `rest`-shaped
    /// entry.
    pub fn payload_start(self) -> Option<usize> {
        match self {
            Slots::From(n) => Some(n),
            _ => None,
        }
    }
}

impl TryFrom<String> for Slots {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        match raw.as_str() {
            "all" => Ok(Slots::All),
            "first" => Ok(Slots::First),
            "last" => Ok(Slots::Last),
            "except-last" => Ok(Slots::ExceptLast),
            "rest" => Ok(Slots::From(0)),
            other => match other.strip_suffix('+') {
                Some(n) => n.parse::<usize>().map(Slots::From).map_err(|_| {
                    format!("unknown slots value `{other}` — `N+` needs a slot number before the +")
                }),
                None => other.parse::<usize>().map(Slots::At).map_err(|_| {
                    format!(
                        "unknown slots value `{other}` — expected all, first, last, \
                         except-last, rest, `N+`, or a slot number"
                    )
                }),
            },
        }
    }
}

/// What an argument *is*. Only the kinds that currently produce edges are acted
/// on; the rest are accepted so a map can be written ahead of the code that
/// consumes it, and are listed here so the vocabulary is one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// carries no reference at all — a message, a count, a format string
    #[default]
    None,
    /// a single filesystem path
    Path,
    /// a nested command
    Cmd,
    /// a **shell script**, as a single string: `bash -c '…'`, `eval '…'`.
    ///
    /// Distinct from [`Kind::Code`] on purpose. `code` says "this is source in
    /// some language", which is all a rule needs in order to leave it alone.
    /// `shell` additionally says "and this parser can read it", which is what
    /// licenses re-parsing the string and grafting the result behind a `Spawns`
    /// edge. Lowering `python3 -c 'open("/etc/passwd")'` as bash would
    /// manufacture claims about a language the graph cannot parse, so the
    /// interpreters keep `code` and only the shells get `shell`.
    ///
    /// Inferring this from the program name instead would reintroduce the
    /// `SHELLS` table in `src/bash.rs` — one of the hand-maintained lists issue
    /// #13 exists to delete.
    Shell,
    /// a leading run of `NAME=val` arguments that precede a nested command,
    /// as in `env FOO=1 rm x` or `sudo BAR=2 rm x`. Consumed words produce no
    /// edges — symmetric with prefix assignments (`FOO=1 rm x`).
    Assignment,
    // ── declared, not yet consumed ──
    /// a set of paths: a root taken with what is beneath it
    PathSet,
    Glob,
    Regex,
    Code,
    Url,
    Host,
    Container,
}

impl Kind {
    /// Whether this kind names something on the filesystem today.
    pub fn is_path(self) -> bool {
        matches!(self, Kind::Path | Kind::PathSet)
    }
}

/// What the program does to what the argument names. A **set**, because one
/// argument is often several things at once: `mv`'s source is read *and*
/// deleted, and a rule about either has to see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Read,
    Write,
    Delete,
    Create,
    Exec,
}

impl Maps {
    /// Parse a map file, rejecting anything it cannot represent rather than
    /// ignoring it — a silently dropped map entry is a program the graph stays
    /// quiet about for no stated reason.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let maps: Maps = toml::from_str(raw).map_err(|e| format!("command map: {e}"))?;
        maps.validate()?;
        Ok(maps)
    }

    /// Every shipped recipe, merged, parsed **once** per process.
    ///
    /// [`Maps::builtin`] parses forty-odd TOML files. That was tolerable when
    /// one module called it once per command; now that every extraction carries
    /// a graph, it would run on every hook invocation. A recipe that fails to
    /// parse is a build-time bug — a test asserts every shipped file is valid —
    /// so the fallback here is an empty map rather than a panic on the hot path.
    pub fn shipped() -> &'static Maps {
        static SHIPPED: std::sync::OnceLock<Maps> = std::sync::OnceLock::new();
        SHIPPED.get_or_init(|| Maps::builtin().unwrap_or_default())
    }

    /// Every shipped recipe, merged.
    ///
    /// Each file is parsed on its own so an error names the recipe it came
    /// from — with one concatenated blob, a bad entry in `kubectl.toml` would
    /// report a line number in a file nobody can open.
    pub fn builtin() -> Result<Self, String> {
        let mut merged = Maps::default();
        for (file, raw) in RECIPES {
            let maps = Maps::parse(raw).map_err(|e| format!("recipes/{file}: {e}"))?;
            merged.programs.extend(maps.programs);
        }
        merged.check_for_duplicates()?;
        Ok(merged)
    }

    /// Two recipes claiming the same program (or the same subcommand of one)
    /// means `lookup` silently picks whichever loaded first. Better to refuse.
    fn check_for_duplicates(&self) -> Result<(), String> {
        let mut seen: Vec<(&str, Option<&str>)> = Vec::new();
        for program in &self.programs {
            let key = (program.name.as_str(), program.subcommand.as_deref());
            if seen.contains(&key) {
                return Err(match key.1 {
                    Some(sub) => format!("recipes: `{} {sub}` is mapped twice", key.0),
                    None => format!("recipes: `{}` is mapped twice", key.0),
                });
            }
            seen.push(key);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        for program in &self.programs {
            let label = match &program.subcommand {
                Some(sub) => format!("{} {sub}", program.name),
                None => program.name.clone(),
            };
            if program.name.is_empty() {
                return Err("command map: an entry has an empty `name`".to_string());
            }
            // a subcommand path is compared word for word and, as a string, for
            // duplicates — so `"s3  cp"` and `"s3 cp"` would be two entries for
            // one subcommand that never compare equal
            if let Some(sub) = &program.subcommand
                && (sub.is_empty() || *sub != sub.split_whitespace().collect::<Vec<_>>().join(" "))
            {
                return Err(format!(
                    "command map: `{}` has the subcommand path `{sub}` — write it as single \
                     space-separated words (`s3 cp`)",
                    program.name
                ));
            }
            // an `exec` effect on anything the graph cannot point an edge at is
            // a map bug. `cmd` names a program; `shell` names a script that is
            // re-parsed into programs. Both end up with something executable.
            let executable = |kind: Kind| matches!(kind, Kind::Cmd | Kind::Shell);
            for (name, flag) in &program.flags {
                if flag.effect.contains(&Effect::Exec) && !executable(flag.kind) {
                    return Err(format!(
                        "command map: `{label}` flag `{name}` gives an `exec` effect to a \
                         `{:?}` argument — only `cmd` and `shell` can be executed",
                        flag.kind
                    ));
                }
            }
            for arg in &program.args {
                if arg.effect.contains(&Effect::Exec) && !executable(arg.kind) {
                    return Err(format!(
                        "command map: `{label}` gives an `exec` effect to a `{:?}` argument — \
                         only `cmd` and `shell` can be executed",
                        arg.kind
                    ));
                }
                if (arg.recursive || !arg.recursive_with.is_empty()) && arg.kind != Kind::PathSet {
                    return Err(format!(
                        "command map: `{label}` marks a `{:?}` argument recursive — \
                         only `pathset` can be",
                        arg.kind
                    ));
                }
                if arg.kind == Kind::Cmd && arg.slots.payload_start().is_none() {
                    return Err(format!(
                        "command map: `{label}` binds a `cmd` argument to `{:?}` — a nested \
                         command runs to the end of the line, so it must use `rest` or `N+`",
                        arg.slots
                    ));
                }
                if arg.kind == Kind::Assignment && !arg.effect.is_empty() {
                    return Err(format!(
                        "command map: `{label}` assignment entry carries an effect — \
                         assignment-shaped arguments produce no edges"
                    ));
                }
            }
            for (name, flag) in &program.flags {
                if !flag.takes && flag.kind != Kind::None {
                    return Err(format!(
                        "command map: `{label}` flag `{name}` has a kind but does not take an \
                         argument — set `takes = true` or drop the kind"
                    ));
                }
            }
        }
        Ok(())
    }

    /// The map for a program, preferring the most specific subcommand entry.
    ///
    /// `git rm` and `git log` share a binary and share nothing else, so a
    /// subcommand entry always wins over the bare one. `leading` is the
    /// program's first few positionals, flag arguments already removed; the
    /// entry whose subcommand path is the **longest** prefix of them wins, so
    /// `aws s3 cp` beats a hypothetical `aws s3`.
    pub fn lookup(&self, program: &str, leading: &[String]) -> Option<&Program> {
        let name = basename(program);
        let specific = self
            .programs
            .iter()
            .filter(|p| p.name == name && p.matches_subcommand(leading))
            .max_by_key(|p| p.subcommand_depth());
        specific.or_else(|| {
            self.programs
                .iter()
                .find(|p| p.name == name && p.subcommand.is_none())
        })
    }

    pub fn len(&self) -> usize {
        self.programs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }
}

impl Program {
    /// Which entry covers positional `slot`, given how many positionals there
    /// are in total. Later entries win, so a specific `last` can follow a broad
    /// `all`.
    // `self` counts toward the total, so this three-argument method trips a
    // threshold of 3
    #[allow(clippy::too_many_arguments)]
    pub fn arg_for(&self, slot: usize, total: usize, flags: &[String]) -> Option<&Arg> {
        self.args.iter().rev().find(|arg| {
            arg.when.as_ref().is_none_or(|w| w.holds(flags))
                && match arg.slots {
                    Slots::All => true,
                    Slots::First => slot == 0,
                    Slots::Last => total > 0 && slot == total - 1,
                    Slots::ExceptLast => total > 0 && slot < total - 1,
                    Slots::From(n) => slot == n,
                    Slots::At(n) => slot == n,
                }
        })
    }

    /// The words of this entry's subcommand path — `["s3", "cp"]` for
    /// `subcommand = "s3 cp"`, empty for the bare entry.
    pub fn subcommand_words(&self) -> Vec<&str> {
        self.subcommand
            .as_deref()
            .map(|s| s.split(' ').collect())
            .unwrap_or_default()
    }

    /// How many positionals the subcommand itself occupies. They are not
    /// arguments to anything, so every slot number is counted after them.
    pub fn subcommand_depth(&self) -> usize {
        self.subcommand_words().len()
    }

    /// Whether this entry's subcommand path is a prefix of `leading`.
    ///
    /// The bare entry (no subcommand) matches nothing here — it is the fallback
    /// `lookup` reaches for only when no specific entry applies.
    pub fn matches_subcommand(&self, leading: &[String]) -> bool {
        let words = self.subcommand_words();
        !words.is_empty()
            && words.len() <= leading.len()
            && words.iter().zip(leading).all(|(w, got)| *w == got)
    }

    /// The entry that swallows the rest of the line as a nested command, if any.
    pub fn nested_command(&self) -> Option<&Arg> {
        self.args
            .iter()
            .find(|a| a.kind == Kind::Cmd && a.slots.payload_start().is_some())
    }

    /// Whether this program's recipe declares that leading `NAME=val` positionals
    /// should be consumed before the payload.
    pub fn assignment_entry(&self) -> Option<&Arg> {
        self.args.iter().find(|a| a.kind == Kind::Assignment)
    }

    /// The slot naming the machine a nested command runs on, if this program has
    /// one.
    ///
    /// A recipe that says "slot 0 is a machine" **and** "the rest is a command"
    /// has already said the command runs on that machine — those two statements
    /// together mean nothing else. So there is no third field to set and no way
    /// to write a recipe where they disagree.
    pub fn machine_slot(&self) -> Option<usize> {
        self.args.iter().find_map(|a| match (a.kind, a.slots) {
            (Kind::Host | Kind::Container, Slots::At(n)) => Some(n),
            (Kind::Host | Kind::Container, Slots::First) => Some(0),
            _ => None,
        })
    }
}

fn basename(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words<const N: usize>(raw: [&str; N]) -> Vec<String> {
        raw.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_shipped_recipe_parses_and_validates() {
        let maps = Maps::builtin().expect("shipped recipes are valid");
        assert!(
            maps.len() > 5,
            "expected a starter set of maps, got {}",
            maps.len()
        );
    }

    #[test]
    fn every_recipe_file_contributes_at_least_one_entry() {
        // a file that parses to nothing is a recipe someone wrote and the binary
        // ignores
        for (file, raw) in RECIPES {
            let maps = Maps::parse(raw).unwrap_or_else(|e| panic!("recipes/{file}: {e}"));
            assert!(
                !maps.is_empty(),
                "recipes/{file} defines no [[cmd]] entries"
            );
        }
    }

    #[test]
    fn a_recipe_filename_matches_the_program_it_maps() {
        // `recipes/grep.toml` mapping `rg` would be findable by nobody
        for (file, raw) in RECIPES {
            let stem = file.trim_end_matches(".toml");
            let maps = Maps::parse(raw).unwrap();
            for program in &maps.programs {
                assert_eq!(
                    program.name, stem,
                    "recipes/{file} maps `{}`, which belongs in recipes/{}.toml",
                    program.name, program.name
                );
            }
        }
    }

    #[test]
    fn mapping_the_same_program_twice_is_rejected() {
        let mut maps = Maps::parse("[[cmd]]\nname = \"rm\"\n").unwrap();
        let extra = Maps::parse("[[cmd]]\nname = \"rm\"\n").unwrap();
        maps.programs.extend(extra.programs);
        let err = maps.check_for_duplicates().expect_err("must reject");
        assert!(err.contains("mapped twice"), "{err}");
    }

    #[test]
    fn a_subcommand_entry_beats_the_bare_one() {
        let maps = Maps::parse(
            r#"
[[cmd]]
name = "git"

[[cmd]]
name = "git"
subcommand = "rm"
[[cmd.args]]
slots = "all"
kind = "path"
effect = ["delete"]
"#,
        )
        .expect("parses");
        let bare = maps.lookup("git", &words(["log"])).expect("bare git");
        assert!(bare.subcommand.is_none());
        let specific = maps.lookup("git", &words(["rm"])).expect("git rm");
        assert_eq!(specific.subcommand.as_deref(), Some("rm"));
    }

    #[test]
    fn a_nested_subcommand_beats_a_shallower_one() {
        // `aws s3 cp SRC DST` and `aws s3 rm KEY` share `s3` and agree about
        // nothing after it, so the deepest matching entry has to win
        let maps = Maps::parse(
            r#"
[[cmd]]
name = "aws"

[[cmd]]
name = "aws"
subcommand = "s3"

[[cmd]]
name = "aws"
subcommand = "s3 cp"
"#,
        )
        .expect("parses");
        let deep = maps.lookup("aws", &words(["s3", "cp"])).expect("aws s3 cp");
        assert_eq!(deep.subcommand.as_deref(), Some("s3 cp"));
        assert_eq!(deep.subcommand_depth(), 2);
        // a sibling with no entry of its own falls back to the shallower map,
        // not to the bare one
        let shallow = maps.lookup("aws", &words(["s3", "ls"])).expect("aws s3");
        assert_eq!(shallow.subcommand.as_deref(), Some("s3"));
        // and a subcommand tree nobody mapped falls all the way back
        assert!(
            maps.lookup("aws", &words(["ec2", "describe-instances"]))
                .expect("bare aws")
                .subcommand
                .is_none()
        );
    }

    #[test]
    fn a_subcommand_path_must_be_written_in_single_spaces() {
        // it is compared word for word AND as a string for duplicates, so
        // `"s3  cp"` would be a second entry for one subcommand
        let err = Maps::parse("[[cmd]]\nname = \"aws\"\nsubcommand = \"s3  cp\"\n")
            .expect_err("must reject");
        assert!(err.contains("space-separated"), "{err}");
    }

    #[test]
    fn lookup_uses_the_basename() {
        let maps = Maps::parse("[[cmd]]\nname = \"rm\"\n").expect("parses");
        assert!(maps.lookup("/usr/bin/rm", &[]).is_some());
    }

    #[test]
    fn an_unmapped_program_has_no_map() {
        let maps = Maps::builtin().unwrap();
        assert!(maps.lookup("some-tool-nobody-mapped", &[]).is_none());
    }

    #[test]
    fn later_arg_entries_win() {
        let program = &Maps::parse(
            r#"
[[cmd]]
name = "cp"
[[cmd.args]]
slots = "all"
kind = "path"
effect = ["read"]
[[cmd.args]]
slots = "last"
kind = "path"
effect = ["write", "create"]
"#,
        )
        .unwrap()
        .programs[0];
        // slot 1 of 2 is the destination, so the narrower `last` entry applies
        assert_eq!(
            program.arg_for(1, 2, &[]).unwrap().effect,
            vec![Effect::Write, Effect::Create]
        );
        assert_eq!(
            program.arg_for(0, 2, &[]).unwrap().effect,
            vec![Effect::Read]
        );
    }

    #[test]
    fn unknown_slots_value_is_rejected() {
        let err = Maps::parse("[[cmd]]\nname = \"x\"\n[[cmd.args]]\nslots = \"middle\"\n")
            .expect_err("must reject");
        assert!(err.contains("unknown slots value"), "{err}");
    }

    #[test]
    fn unknown_field_is_rejected() {
        // a typo'd key would otherwise be a map entry that quietly does nothing
        let err =
            Maps::parse("[[cmd]]\nname = \"x\"\nsubcomand = \"y\"\n").expect_err("must reject");
        assert!(
            err.contains("subcomand") || err.contains("unknown field"),
            "{err}"
        );
    }

    #[test]
    fn exec_on_a_non_command_argument_is_rejected() {
        let err = Maps::parse(
            "[[cmd]]\nname = \"x\"\n[[cmd.args]]\nslots = \"all\"\nkind = \"path\"\neffect = [\"exec\"]\n",
        )
        .expect_err("must reject");
        assert!(
            err.contains("only `cmd` and `shell` can be executed"),
            "{err}"
        );
    }

    #[test]
    fn exec_on_a_non_command_flag_is_rejected_too() {
        // the flag side went unchecked until `shell` gave a flag an `exec`
        // effect for the first time — `bash -c` — so a typo'd kind on a flag
        // used to pass validation by omission
        let err = Maps::parse(
            "[[cmd]]\nname = \"x\"\n[cmd.flags]\n\"-c\" = { takes = true, kind = \"path\", effect = [\"exec\"] }\n",
        )
        .expect_err("must reject");
        assert!(
            err.contains("only `cmd` and `shell` can be executed"),
            "{err}"
        );
    }

    #[test]
    fn a_shell_argument_may_be_executed() {
        Maps::parse(
            "[[cmd]]\nname = \"x\"\n[cmd.flags]\n\"-c\" = { takes = true, kind = \"shell\", effect = [\"exec\"] }\n",
        )
        .expect("shell is executable");
    }

    #[test]
    fn a_command_argument_must_take_the_rest_of_the_line() {
        let err =
            Maps::parse("[[cmd]]\nname = \"x\"\n[[cmd.args]]\nslots = \"first\"\nkind = \"cmd\"\n")
                .expect_err("must reject");
        assert!(err.contains("must use `rest`"), "{err}");
    }

    #[test]
    fn a_flag_with_a_kind_must_take_an_argument() {
        let err =
            Maps::parse("[[cmd]]\nname = \"x\"\n[cmd.flags]\n\"-e\" = { kind = \"regex\" }\n")
                .expect_err("must reject");
        assert!(err.contains("does not take an argument"), "{err}");
    }
}
