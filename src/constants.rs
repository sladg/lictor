//! Tunable detection lists, gathered in one place so hardening is a one-line edit.
//! Add a banned env var, a device path, a wrapper name, etc. here — the logic that
//! consumes each list lives in `bash.rs` / `rules.rs`.

// ── env vars whose mere assignment prefixing a command injects code / hijacks
//    resolution (GTFOBins "E" vectors + loader/interpreter hijacks) ──
pub const DANGEROUS_ENV: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "PS4",
    "BASH_FUNC",
    "PROMPT_COMMAND",
    "GLOBIGNORE",
    "IFS",
    "LESSOPEN",
    "LESSCLOSE",
    "PAGER",
    "VISUAL",
    "EDITOR",
    "SPELL",
    "PERL5OPT",
    "PERL5DB",
    "PERL5LIB",
    "PERLLIB",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "RUBYOPT",
    "RUBYLIB",
    "NODE_OPTIONS",
    "BUNDLE_GEMFILE",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_EDITOR",
    "GIT_CONFIG",
];

// ── redirect targets that corrupt disks/memory; matched by prefix, always denied ──
pub const DEVICE_WRITE_GLOBS: &[&str] = &[
    "/dev/sd",
    "/dev/nvme",
    "/dev/hd",
    "/dev/vd",
    "/dev/disk",
    "/dev/mapper/",
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/dev/sda",
    "/proc/sysrq-trigger",
];

// ── content emitters: writing a file with one of these via redirection is
//    file-authoring the agent should do with the Write/Edit tool (on_shell_write) ──
pub const CONTENT_EMITTERS: &[&str] = &["cat", "echo", "printf", "tee"];

// ── absolute/home bin dirs whose executables are safe to shorten to a basename
//    (strip_program_paths); `~` is expanded against $HOME at use. ──
pub const DEFAULT_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/bin",
    "/sbin",
    "/usr/sbin",
    "/opt/homebrew/bin",
    "/opt/local/bin",
    "~/.cargo/bin",
    "~/.local/bin",
    "~/.proto/shims",
    "~/.proto/bin",
    "~/.bun/bin",
    "~/.deno/bin",
    "~/go/bin",
    "~/.volta/bin",
];
