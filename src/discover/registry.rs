//! Matches shell commands against known RTK rewrite rules to decide how to handle them.

use lazy_static::lazy_static;
use regex::{Regex, RegexSet};

use super::lexer::{split_on_operators, tokenize, TokenKind};
use super::rules::{IGNORED_EXACT, IGNORED_PREFIXES, RULES};

/// Result of classifying a command.
#[derive(Debug, PartialEq)]
pub enum Classification {
    Supported {
        rtk_equivalent: &'static str,
        category: &'static str,
        estimated_savings_pct: f64,
        status: super::report::RtkStatus,
    },
    Unsupported {
        base_command: String,
    },
    Ignored,
}

/// Average token counts per category for estimation when no output_len available.
pub fn category_avg_tokens(category: &str, subcmd: &str) -> usize {
    match category {
        "Git" => match subcmd {
            "log" | "diff" | "show" => 200,
            _ => 40,
        },
        "Cargo" => match subcmd {
            "test" => 500,
            _ => 150,
        },
        "Tests" => 800,
        "Files" => 100,
        "Build" => 300,
        "Infra" => 120,
        "Network" => 150,
        "GitHub" => 200,
        "GitLab" => 200,
        "PackageManager" => 150,
        _ => 150,
    }
}

lazy_static! {
    static ref REGEX_SET: RegexSet =
        RegexSet::new(RULES.iter().map(|r| r.pattern)).expect("invalid regex patterns");
    static ref COMPILED: Vec<Regex> = RULES
        .iter()
        .map(|r| Regex::new(r.pattern).expect("invalid regex"))
        .collect();
    static ref ENV_PREFIX: Regex = {
        let double_quoted = r#""(?:[^"\\]|\\.)*""#;
        let single_quoted = r#"'(?:[^'\\]|\\.)*'"#;
        let unquoted = r#"[^\s]*"#;
        let env_value = format!("(?:{}|{}|{})", double_quoted, single_quoted, unquoted);
        let env_assign = format!(r#"[A-Z_][A-Z0-9_]*={}"#, env_value);
        Regex::new(&format!(r#"^(?:sudo\s+|env\s+|{}\s+)+"#, env_assign)).unwrap()
    };
    // Git global options that appear before the subcommand: -C <path>, -c <key=val>,
    // --git-dir <dir>, --work-tree <dir>, and flag-only options (#163)
    static ref GIT_GLOBAL_OPT: Regex =
        Regex::new(r"^(?:(?:-C\s+\S+|-c\s+\S+|--git-dir(?:=\S+|\s+\S+)|--work-tree(?:=\S+|\s+\S+)|--no-pager|--no-optional-locks|--bare|--literal-pathspecs)\s+)+").unwrap();
    // Issue #1362: each capture expects a SINGLE file argument (`\S+$`). Multi-file
    // invocations like `head -3 a b c` fail to match so the segment is passed through
    // to the native `head`/`tail` binary — which already handles multi-file with
    // `==> name <==` banners that `rtk read --max-lines` cannot reproduce.
    static ref HEAD_N: Regex = Regex::new(r"^head\s+-(\d+)\s+(\S+)$").unwrap();
    static ref HEAD_LINES: Regex = Regex::new(r"^head\s+--lines=(\d+)\s+(\S+)$").unwrap();
    static ref TAIL_N: Regex = Regex::new(r"^tail\s+-(\d+)\s+(\S+)$").unwrap();
    static ref TAIL_N_SPACE: Regex = Regex::new(r"^tail\s+-n\s+(\d+)\s+(\S+)$").unwrap();
    static ref TAIL_LINES_EQ: Regex = Regex::new(r"^tail\s+--lines=(\d+)\s+(\S+)$").unwrap();
    static ref TAIL_LINES_SPACE: Regex = Regex::new(r"^tail\s+--lines\s+(\d+)\s+(\S+)$").unwrap();
}

const GOLANGCI_GLOBAL_OPT_WITH_VALUE: &[&str] = &[
    "-c",
    "--color",
    "--config",
    "--cpu-profile-path",
    "--mem-profile-path",
    "--trace-path",
];

#[derive(Debug, Clone, Copy)]
struct GolangciRunParts<'a> {
    run_segment: &'a str,
}

/// Classify a single (already-split) command.
pub fn classify_command(cmd: &str) -> Classification {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return Classification::Ignored;
    }

    // Check ignored
    for exact in IGNORED_EXACT {
        if trimmed == *exact {
            return Classification::Ignored;
        }
    }
    for prefix in IGNORED_PREFIXES {
        if trimmed.starts_with(prefix) {
            return Classification::Ignored;
        }
    }

    // Strip env prefixes (sudo, env VAR=val, VAR=val)
    let stripped = ENV_PREFIX.replace(trimmed, "");
    let cmd_clean = stripped.trim();
    if cmd_clean.is_empty() {
        return Classification::Ignored;
    }

    // Normalize absolute binary paths: /usr/bin/grep → grep (#485)
    let cmd_normalized = strip_absolute_path(cmd_clean);
    // Strip git global options: git -C /tmp status → git status (#163)
    let cmd_normalized = strip_git_global_opts(&cmd_normalized);
    // Strip golangci-lint global options before `run` so classify/rewrite stays
    // aligned with the runtime wrapper behavior.
    let cmd_normalized = strip_golangci_global_opts(&cmd_normalized);
    let cmd_clean = cmd_normalized.as_str();

    // Exclude cat/head/tail with redirect operators — these are writes, not reads (#315)
    if cmd_clean.starts_with("cat ")
        || cmd_clean.starts_with("head ")
        || cmd_clean.starts_with("tail ")
    {
        let has_redirect = cmd_clean
            .split_whitespace()
            .skip(1)
            .any(|t| t.starts_with('>') || t == "<" || t.starts_with(">>"));
        if has_redirect {
            return Classification::Unsupported {
                base_command: cmd_clean
                    .split_whitespace()
                    .next()
                    .unwrap_or("cat")
                    .to_string(),
            };
        }
    }

    // Fast check with RegexSet — take the last (most specific) match
    let matches: Vec<usize> = REGEX_SET.matches(cmd_clean).into_iter().collect();
    if let Some(&idx) = matches.last() {
        let rule = &RULES[idx];

        // Extract subcommand for savings override and status detection
        let (savings, status) = if let Some(caps) = COMPILED[idx].captures(cmd_clean) {
            if let Some(sub) = caps.get(1) {
                let subcmd = sub.as_str();
                // Check if this subcommand has a special status
                let status = rule
                    .subcmd_status
                    .iter()
                    .find(|(s, _)| *s == subcmd)
                    .map(|(_, st)| *st)
                    .unwrap_or(super::report::RtkStatus::Existing);

                // Check if this subcommand has custom savings
                let savings = rule
                    .subcmd_savings
                    .iter()
                    .find(|(s, _)| *s == subcmd)
                    .map(|(_, pct)| *pct)
                    .unwrap_or(rule.savings_pct);

                (savings, status)
            } else {
                (rule.savings_pct, super::report::RtkStatus::Existing)
            }
        } else {
            (rule.savings_pct, super::report::RtkStatus::Existing)
        };

        Classification::Supported {
            rtk_equivalent: rule.rtk_cmd,
            category: rule.category,
            estimated_savings_pct: savings,
            status,
        }
    } else {
        // Extract base command for unsupported
        let base = extract_base_command(cmd_clean);
        if base.is_empty() {
            Classification::Ignored
        } else {
            Classification::Unsupported {
                base_command: base.to_string(),
            }
        }
    }
}

/// Extract the base command (first word, or first two if it looks like a subcommand pattern).
fn extract_base_command(cmd: &str) -> &str {
    let parts: Vec<&str> = cmd.splitn(3, char::is_whitespace).collect();
    match parts.len() {
        0 => "",
        1 => parts[0],
        _ => {
            let second = parts[1];
            // If the second token looks like a subcommand (no leading -)
            if !second.starts_with('-') && !second.contains('/') && !second.contains('.') {
                // Return "cmd subcmd"
                let end = cmd
                    .find(char::is_whitespace)
                    .and_then(|i| {
                        let rest = &cmd[i..];
                        let trimmed = rest.trim_start();
                        trimmed
                            .find(char::is_whitespace)
                            .map(|j| i + (rest.len() - trimmed.len()) + j)
                    })
                    .unwrap_or(cmd.len());
                &cmd[..end]
            } else {
                parts[0]
            }
        }
    }
}

/// Quote-aware heredoc detection — `<<` inside quotes is not a heredoc.
pub fn has_heredoc(cmd: &str) -> bool {
    tokenize(cmd)
        .iter()
        .any(|t| t.kind == TokenKind::Redirect && t.value.starts_with("<<"))
}

pub fn split_command_chain(cmd: &str) -> Vec<&str> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return vec![];
    }

    // Lexer-based for `<<`; string-based for `$((` (lexer splits it across tokens).
    if has_heredoc(trimmed) || trimmed.contains("$((") {
        return vec![trimmed];
    }

    split_on_operators(trimmed, true)
}

/// Strip git global options before the subcommand (#163).
/// `git -C /tmp status` → `git status`, preserving the rest.
/// Returns the original string unchanged if not a git command.
fn strip_git_global_opts(cmd: &str) -> String {
    // Only applies to commands starting with "git "
    if !cmd.starts_with("git ") {
        return cmd.to_string();
    }
    let after_git = &cmd[4..]; // skip "git "
    let stripped = GIT_GLOBAL_OPT.replace(after_git, "");
    format!("git {}", stripped.trim())
}

/// Strip golangci-lint global options before the `run` subcommand.
/// `golangci-lint --color never run ./...` → `golangci-lint run ./...`
/// Returns the original string unchanged if this is not a supported compact `run` invocation.
fn strip_golangci_global_opts(cmd: &str) -> String {
    match parse_golangci_run_parts(cmd) {
        Some(parts) => format!("golangci-lint {}", parts.run_segment),
        None => cmd.to_string(),
    }
}

/// Parse supported golangci-lint invocations with optional global flags before `run`.
fn parse_golangci_run_parts(cmd: &str) -> Option<GolangciRunParts<'_>> {
    let tokens = split_token_spans(cmd);
    let first = tokens.first()?;
    if first.0 != "golangci-lint" && first.0 != "golangci" {
        return None;
    }

    let mut i = 1;
    while i < tokens.len() {
        let token = tokens[i].0;

        if token == "--" {
            return None;
        }

        if !token.starts_with('-') {
            if token == "run" {
                let run_segment = cmd[tokens[i].1..].trim();
                return Some(GolangciRunParts { run_segment });
            }
            return None;
        }

        if let Some(flag) = split_golangci_flag_name(token) {
            if golangci_flag_takes_separate_value(token, flag) {
                i += 1;
            }
        }

        i += 1;
    }

    None
}

fn split_golangci_flag_name(arg: &str) -> Option<&str> {
    if arg.starts_with("--") {
        return Some(arg.split_once('=').map(|(flag, _)| flag).unwrap_or(arg));
    }

    if arg.starts_with('-') {
        return Some(arg);
    }

    None
}

fn golangci_flag_takes_separate_value(arg: &str, flag: &str) -> bool {
    if !GOLANGCI_GLOBAL_OPT_WITH_VALUE.contains(&flag) {
        return false;
    }

    if arg.starts_with("--") && arg.contains('=') {
        return false;
    }

    true
}

fn split_token_spans(cmd: &str) -> Vec<(&str, usize, usize)> {
    let mut tokens = Vec::new();
    let mut start = None;

    for (idx, ch) in cmd.char_indices() {
        if ch.is_whitespace() {
            if let Some(token_start) = start.take() {
                tokens.push((&cmd[token_start..idx], token_start, idx));
            }
        } else if start.is_none() {
            start = Some(idx);
        }
    }

    if let Some(token_start) = start {
        tokens.push((&cmd[token_start..], token_start, cmd.len()));
    }

    tokens
}

/// Normalize absolute binary paths: `/usr/bin/grep -rn foo` → `grep -rn foo` (#485)
/// Only strips if the first word contains a `/` (Unix path).
fn strip_absolute_path(cmd: &str) -> String {
    let first_space = cmd.find(' ');
    let first_word = match first_space {
        Some(pos) => &cmd[..pos],
        None => cmd,
    };
    if first_word.contains('/') {
        // Extract basename
        let basename = first_word.rsplit('/').next().unwrap_or(first_word);
        if basename.is_empty() {
            return cmd.to_string();
        }
        match first_space {
            Some(pos) => format!("{}{}", basename, &cmd[pos..]),
            None => basename.to_string(),
        }
    } else {
        cmd.to_string()
    }
}

pub fn prefix_contains_rtk_disabled(prefix_part: &str) -> bool {
    prefix_part.contains("RTK_DISABLED=")
}

/// Check if a command has RTK_DISABLED= prefix in its env prefix portion.
pub fn cmd_has_rtk_disabled_prefix(cmd: &str) -> bool {
    let (prefix_part, _) = strip_disabled_prefix(cmd);
    prefix_contains_rtk_disabled(prefix_part)
}

/// Strip RTK_DISABLED=X and other env prefixes, returns `(env_prefix, actual_command)`.
pub fn strip_disabled_prefix(cmd: &str) -> (&str, &str) {
    let trimmed = cmd.trim();
    let stripped = ENV_PREFIX.replace(trimmed, "");
    // stripped is a Cow<str> that borrows from trimmed when no replacement happens.
    // We need to return a &str into the original, so compute the offset.
    let prefix_len = trimmed.len() - stripped.len();
    let prefix_part = &trimmed[..prefix_len];
    let rest = trimmed[prefix_len..].trim();
    (prefix_part, rest)
}







lazy_static! {
    /// Matches a bash line-continuation: a backslash immediately followed by
    /// `\n` or `\r\n`, *plus* any horizontal whitespace on the line before AND
    /// after the break. This is what bash already collapses to a single space
    /// before executing the command — rtk's hook matcher needs to do the same
    /// so commands authored across multiple lines still hit the rewrite rules.
    /// Consuming the trailing whitespace prevents double spaces in cases like
    /// `git diff \<NL>HEAD~1`.
    static ref LINE_CONTINUATION_RE: Regex =
        Regex::new(r"(?m)[ \t\x0B\x0C]*\\\r?\n[ \t\x0B\x0C]*").unwrap();
}














#[cfg(test)]
mod tests {
    use super::super::report::RtkStatus;
    use super::*;


    #[test]
    fn test_classify_git_status() {
        assert_eq!(
            classify_command("git status"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_yadm_status() {
        assert_eq!(
            classify_command("yadm status"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_yadm_diff() {
        assert_eq!(
            classify_command("yadm diff"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 80.0,
                status: RtkStatus::Existing,
            }
        );
    }


    #[test]
    fn test_classify_git_diff_cached() {
        assert_eq!(
            classify_command("git diff --cached"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 80.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cargo_test_filter() {
        assert_eq!(
            classify_command("cargo test filter::"),
            Classification::Supported {
                rtk_equivalent: "rtk cargo",
                category: "Cargo",
                estimated_savings_pct: 90.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_npx_tsc() {
        assert_eq!(
            classify_command("npx tsc --noEmit"),
            Classification::Supported {
                rtk_equivalent: "rtk tsc",
                category: "Build",
                estimated_savings_pct: 83.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cat_file() {
        assert_eq!(
            classify_command("cat src/main.rs"),
            Classification::Supported {
                rtk_equivalent: "rtk read",
                category: "Files",
                estimated_savings_pct: 60.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cat_redirect_not_supported() {
        // cat > file and cat >> file are writes, not reads — should not be classified as supported
        let write_commands = [
            "cat > /tmp/output.txt",
            "cat >> /tmp/output.txt",
            "cat file.txt > output.txt",
            "cat -n file.txt >> log.txt",
            "head -10 README.md > output.txt",
            "tail -f app.log > /dev/null",
        ];
        for cmd in &write_commands {
            if let Classification::Supported { .. } = classify_command(cmd) {
                panic!("{} should NOT be classified as Supported", cmd)
            }
            // Unsupported or Ignored is fine
        }
    }

    #[test]
    fn test_classify_cd_ignored() {
        assert_eq!(classify_command("cd /tmp"), Classification::Ignored);
    }

    #[test]
    fn test_classify_rtk_already() {
        assert_eq!(classify_command("rtk git status"), Classification::Ignored);
    }

    #[test]
    fn test_classify_echo_ignored() {
        assert_eq!(
            classify_command("echo hello world"),
            Classification::Ignored
        );
    }

    #[test]
    fn test_classify_htop_unsupported() {
        match classify_command("htop -d 10") {
            Classification::Unsupported { base_command } => {
                assert_eq!(base_command, "htop");
            }
            other => panic!("expected Unsupported, got {:?}", other),
        }
    }

    #[test]
    fn test_classify_env_prefix_stripped() {
        assert_eq!(
            classify_command("GIT_SSH_COMMAND=ssh git push"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_sudo_stripped() {
        assert_eq!(
            classify_command("sudo docker ps"),
            Classification::Supported {
                rtk_equivalent: "rtk docker",
                category: "Infra",
                estimated_savings_pct: 85.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cargo_check() {
        assert_eq!(
            classify_command("cargo check"),
            Classification::Supported {
                rtk_equivalent: "rtk cargo",
                category: "Cargo",
                estimated_savings_pct: 80.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cargo_check_all_targets() {
        assert_eq!(
            classify_command("cargo check --all-targets"),
            Classification::Supported {
                rtk_equivalent: "rtk cargo",
                category: "Cargo",
                estimated_savings_pct: 80.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_cargo_fmt_passthrough() {
        assert_eq!(
            classify_command("cargo fmt"),
            Classification::Supported {
                rtk_equivalent: "rtk cargo",
                category: "Cargo",
                estimated_savings_pct: 80.0,
                status: RtkStatus::Passthrough,
            }
        );
    }

    #[test]
    fn test_classify_cargo_clippy_savings() {
        assert_eq!(
            classify_command("cargo clippy --all-targets"),
            Classification::Supported {
                rtk_equivalent: "rtk cargo",
                category: "Cargo",
                estimated_savings_pct: 80.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_registry_covers_all_cargo_subcommands() {
        // Verify that every CargoCommand variant (Build, Test, Clippy, Check, Fmt)
        // except Other has a matching pattern in the registry
        for subcmd in ["build", "test", "clippy", "check", "fmt"] {
            let cmd = format!("cargo {subcmd}");
            match classify_command(&cmd) {
                Classification::Supported { .. } => {}
                other => panic!("cargo {subcmd} should be Supported, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_registry_covers_all_git_subcommands() {
        // Verify that every GitCommand subcommand has a matching pattern
        for subcmd in [
            "status", "log", "diff", "show", "add", "commit", "push", "pull", "branch", "fetch",
            "stash", "worktree",
        ] {
            let cmd = format!("git {subcmd}");
            match classify_command(&cmd) {
                Classification::Supported { .. } => {}
                other => panic!("git {subcmd} should be Supported, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_classify_find_not_blocked_by_fi() {
        // Regression: "fi" in IGNORED_PREFIXES used to shadow "find" commands
        // because "find".starts_with("fi") is true. "fi" should only match exactly.
        assert_eq!(
            classify_command("find . -name foo"),
            Classification::Supported {
                rtk_equivalent: "rtk find",
                category: "Files",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_fi_still_ignored_exact() {
        // Bare "fi" (shell keyword) should still be ignored
        assert_eq!(classify_command("fi"), Classification::Ignored);
    }

    #[test]
    fn test_done_still_ignored_exact() {
        // Bare "done" (shell keyword) should still be ignored
        assert_eq!(classify_command("done"), Classification::Ignored);
    }

    #[test]
    fn test_split_chain_and() {
        assert_eq!(split_command_chain("a && b"), vec!["a", "b"]);
    }

    #[test]
    fn test_split_chain_semicolon() {
        assert_eq!(split_command_chain("a ; b"), vec!["a", "b"]);
    }

    #[test]
    fn test_split_pipe_first_only() {
        assert_eq!(split_command_chain("a | b"), vec!["a"]);
    }

    #[test]
    fn test_split_single() {
        assert_eq!(split_command_chain("git status"), vec!["git status"]);
    }

    #[test]
    fn test_split_quoted_and() {
        assert_eq!(
            split_command_chain(r#"echo "a && b""#),
            vec![r#"echo "a && b""#]
        );
    }

    #[test]
    fn test_split_heredoc_no_split() {
        let cmd = "cat <<'EOF'\nhello && world\nEOF";
        assert_eq!(split_command_chain(cmd), vec![cmd]);
    }

    #[test]
    fn test_classify_mypy() {
        assert_eq!(
            classify_command("mypy src/"),
            Classification::Supported {
                rtk_equivalent: "rtk mypy",
                category: "Build",
                estimated_savings_pct: 80.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_python_m_mypy() {
        assert_eq!(
            classify_command("python3 -m mypy --strict"),
            Classification::Supported {
                rtk_equivalent: "rtk mypy",
                category: "Build",
                estimated_savings_pct: 80.0,
                status: RtkStatus::Existing,
            }
        );
    }

    // --- rewrite_command tests ---



    // --- git -C <path> support (#555) ---




    #[test]
    fn test_classify_git_dash_c() {
        let result = classify_command("git -C /tmp status");
        assert!(
            matches!(
                result,
                Classification::Supported {
                    rtk_equivalent: "rtk git",
                    ..
                }
            ),
            "git -C should be classified as supported, got: {:?}",
            result
        );
    }

























    // --- #345: RTK_DISABLED ---





    #[test]
    fn test_rewrite_rtk_disabled_subprocess_warns() {
        let rtk_bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("debug")
            .join("rtk");
        if !rtk_bin.exists() {
            return;
        }
        let rtk_mtime = std::fs::metadata(&rtk_bin)
            .ok()
            .and_then(|m| m.modified().ok());
        let test_mtime = std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok());
        if let (Some(rtk_t), Some(test_t)) = (rtk_mtime, test_mtime) {
            if rtk_t < test_t {
                return;
            }
        }

        let output = std::process::Command::new(&rtk_bin)
            .args(["rewrite", "RTK_DISABLED=1 git status"])
            .output()
            .expect("Failed to run rtk");

        assert!(
            !output.status.success(),
            "Should exit non-zero (no rewrite)"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("RTK_DISABLED=1 detected"),
            "Should warn on stderr, got: {}",
            stderr
        );
    }






    #[test]
    fn test_classify_env_quoted_value_stripped() {
        assert_eq!(
            classify_command(r#"GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git push"#),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    // --- #346: 2>&1 and &> redirect detection ---





    // Both of these used to assert a rewrite, and the change is deliberate
    // rather than a regression: a redirect of fd 1 now declines the rewrite,
    // because re-appending it would put rtk's condensed rendering into the
    // caller's file instead of the command's own bytes.
    //
    // These two are the cases where declining costs something rather than
    // nothing, and the cost is named rather than waved away. `&>/dev/null`
    // discards both streams, so there was never any output to shrink and the
    // lost rewrite is worth nothing. `2>&1 >/dev/null` is NOT the same: the
    // redirects apply in order, so stderr is duplicated onto the ORIGINAL
    // stdout before stdout is sent to /dev/null — visible stderr remains, and
    // rtk could have shrunk it. An earlier version of this comment claimed
    // otherwise and a reviewer caught it. The rewrite is given up anyway,
    // because a rule with no exception carved into it is worth more than one
    // command's saving.














    // --- P0.2: head -N rewrite ---











    // --- Issue #1362: head/tail with multiple files falls back to native command ---
    //
    // `rtk read <file> --max-lines N` only accepts a single positional file path in
    // a shape that maps cleanly to `head -N`. Rewriting `head -N a b c` to
    // `rtk read a b c --max-lines N` previously produced a command where `rtk read`
    // would concatenate the files without the `==> name <==` banners that native
    // `head` emits, so the fix is to skip the rewrite and let the shell run the
    // real `head`/`tail` binary.







    // --- New registry entries ---

    #[test]
    fn test_classify_gh_release() {
        assert!(matches!(
            classify_command("gh release list"),
            Classification::Supported {
                rtk_equivalent: "rtk gh",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_glab_mr() {
        assert!(matches!(
            classify_command("glab mr list"),
            Classification::Supported {
                rtk_equivalent: "rtk glab",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_glab_ci() {
        assert!(matches!(
            classify_command("glab ci list"),
            Classification::Supported {
                rtk_equivalent: "rtk glab",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_glab_release() {
        assert!(matches!(
            classify_command("glab release list"),
            Classification::Supported {
                rtk_equivalent: "rtk glab",
                ..
            }
        ));
    }



    #[test]
    fn test_classify_cargo_install() {
        assert!(matches!(
            classify_command("cargo install rtk"),
            Classification::Supported {
                rtk_equivalent: "rtk cargo",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_docker_run() {
        assert!(matches!(
            classify_command("docker run --rm ubuntu bash"),
            Classification::Supported {
                rtk_equivalent: "rtk docker",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_docker_exec() {
        assert!(matches!(
            classify_command("docker exec -it mycontainer bash"),
            Classification::Supported {
                rtk_equivalent: "rtk docker",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_docker_build() {
        assert!(matches!(
            classify_command("docker build -t myimage ."),
            Classification::Supported {
                rtk_equivalent: "rtk docker",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_kubectl_describe() {
        assert!(matches!(
            classify_command("kubectl describe pod mypod"),
            Classification::Supported {
                rtk_equivalent: "rtk kubectl",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_kubectl_apply() {
        assert!(matches!(
            classify_command("kubectl apply -f deploy.yaml"),
            Classification::Supported {
                rtk_equivalent: "rtk kubectl",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_tree() {
        assert!(matches!(
            classify_command("tree src/"),
            Classification::Supported {
                rtk_equivalent: "rtk tree",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_diff() {
        assert!(matches!(
            classify_command("diff file1.txt file2.txt"),
            Classification::Supported {
                rtk_equivalent: "rtk diff",
                ..
            }
        ));
    }







    #[test]
    fn test_classify_swift_test() {
        assert!(matches!(
            classify_command("swift test"),
            Classification::Supported {
                rtk_equivalent: "rtk swift",
                category: "Build",
                estimated_savings_pct: 90.0,
                status: RtkStatus::Existing,
            }
        ));
    }


    // --- #336: docker compose supported subcommands rewritten, unsupported skipped ---







    // --- AWS / psql (PR #216) ---

    #[test]
    fn test_classify_aws() {
        assert!(matches!(
            classify_command("aws s3 ls"),
            Classification::Supported {
                rtk_equivalent: "rtk aws",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_aws_ec2() {
        assert!(matches!(
            classify_command("aws ec2 describe-instances"),
            Classification::Supported {
                rtk_equivalent: "rtk aws",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_psql() {
        assert!(matches!(
            classify_command("psql -U postgres"),
            Classification::Supported {
                rtk_equivalent: "rtk psql",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_psql_url() {
        assert!(matches!(
            classify_command("psql postgres://localhost/mydb"),
            Classification::Supported {
                rtk_equivalent: "rtk psql",
                ..
            }
        ));
    }




    // --- Python tooling ---

    #[test]
    fn test_classify_ruff_check() {
        assert!(matches!(
            classify_command("ruff check ."),
            Classification::Supported {
                rtk_equivalent: "rtk ruff",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_ruff_format() {
        assert!(matches!(
            classify_command("ruff format src/"),
            Classification::Supported {
                rtk_equivalent: "rtk ruff",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_pytest() {
        assert!(matches!(
            classify_command("pytest tests/"),
            Classification::Supported {
                rtk_equivalent: "rtk pytest",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_python_m_pytest() {
        assert!(matches!(
            classify_command("python -m pytest tests/"),
            Classification::Supported {
                rtk_equivalent: "rtk pytest",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_pip_list() {
        assert!(matches!(
            classify_command("pip list"),
            Classification::Supported {
                rtk_equivalent: "rtk pip",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_uv_pip_list() {
        assert!(matches!(
            classify_command("uv pip list"),
            Classification::Supported {
                rtk_equivalent: "rtk pip",
                ..
            }
        ));
    }








    // --- Go tooling ---

    #[test]
    fn test_classify_go_test() {
        assert!(matches!(
            classify_command("go test ./..."),
            Classification::Supported {
                rtk_equivalent: "rtk go",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_go_build() {
        assert!(matches!(
            classify_command("go build ./..."),
            Classification::Supported {
                rtk_equivalent: "rtk go",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_go_vet() {
        assert!(matches!(
            classify_command("go vet ./..."),
            Classification::Supported {
                rtk_equivalent: "rtk go",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint() {
        assert!(matches!(
            classify_command("golangci-lint run"),
            Classification::Supported {
                rtk_equivalent: "rtk golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_with_flag_before_run() {
        assert!(matches!(
            classify_command("golangci-lint -v run ./..."),
            Classification::Supported {
                rtk_equivalent: "rtk golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_with_value_flag_before_run() {
        assert!(matches!(
            classify_command("golangci-lint --color never run ./..."),
            Classification::Supported {
                rtk_equivalent: "rtk golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_with_inline_value_flag_before_run() {
        assert!(matches!(
            classify_command("golangci-lint --color=never run ./..."),
            Classification::Supported {
                rtk_equivalent: "rtk golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_with_inline_config_flag_before_run() {
        assert!(matches!(
            classify_command("golangci-lint --config=foo.yml run ./..."),
            Classification::Supported {
                rtk_equivalent: "rtk golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_bare_is_not_compact_wrapper() {
        assert!(!matches!(
            classify_command("golangci-lint"),
            Classification::Supported {
                rtk_equivalent: "rtk golangci-lint run",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_golangci_lint_other_subcommand_is_not_compact_wrapper() {
        assert!(!matches!(
            classify_command("golangci-lint version"),
            Classification::Supported {
                rtk_equivalent: "rtk golangci-lint run",
                ..
            }
        ));
    }













    // --- JS/TS tooling ---

    #[test]
    fn test_classify_lint() {
        let commands = vec![
            "npm exec biome",
            "npm exec eslint",
            "npm rum biome",
            "npm rum eslint",
            "npm rum lint",
            "npm run biome",
            "npm run eslint",
            "npm run lint",
            "npm run-script biome",
            "npm run-script eslint",
            "npm run-script lint",
            "npm urn biome",
            "npm urn eslint",
            "npm urn lint",
            "npm x biome",
            "npm x eslint",
            "pnpm dlx biome",
            "pnpm dlx eslint",
            "pnpm exec biome",
            "pnpm exec eslint",
            "pnpm run biome",
            "pnpm run eslint",
            "pnpm run lint",
            "pnpm run-script biome",
            "pnpm run-script eslint",
            "pnpm run-script lint",
            "npm biome",
            "npm eslint",
            "npm lint",
            "npx biome",
            "npx eslint",
            "npx lint",
            "pnpm biome",
            "pnpm eslint",
            "pnpm lint",
            "pnpx biome",
            "pnpx eslint",
            "pnpx lint",
            "biome",
            "eslint",
            "lint",
        ];
        for command in commands {
            assert!(
                matches!(
                    classify_command(command),
                    Classification::Supported {
                        rtk_equivalent: "rtk lint",
                        ..
                    }
                ),
                "Failed for command: {}",
                command
            );
        }
    }


    #[test]
    fn test_classify_jest() {
        let commands = vec![
            "jest run",
            "jest",
            "npm exec jest run",
            "npm exec jest",
            "npm jest run",
            "npm jest",
            "npm rum jest run",
            "npm rum jest",
            "npm run jest run",
            "npm run jest",
            "npm run-script jest run",
            "npm run-script jest",
            "npm urn jest run",
            "npm urn jest",
            "npm x jest run",
            "npm x jest",
            "npx jest run",
            "npx jest",
            "pnpm dlx jest run",
            "pnpm dlx jest",
            "pnpm exec jest run",
            "pnpm exec jest",
            "pnpm jest run",
            "pnpm jest",
            "pnpm run jest run",
            "pnpm run jest",
            "pnpm run-script jest run",
            "pnpm run-script jest",
            "pnpx jest run",
            "pnpx jest",
        ];
        for command in commands {
            assert!(
                matches!(
                    classify_command(command),
                    Classification::Supported {
                        rtk_equivalent: "rtk jest",
                        ..
                    }
                ),
                "Failed for command: {}",
                command
            );
        }
    }


    #[test]
    fn test_classify_vitest() {
        let commands = vec![
            "npm exec vitest run",
            "npm exec vitest",
            "npm rum vitest run",
            "npm rum vitest",
            "npm run vitest run",
            "npm run vitest",
            "npm run-script vitest run",
            "npm run-script vitest",
            "npm urn vitest run",
            "npm urn vitest",
            "npm vitest run",
            "npm vitest",
            "npm x vitest run",
            "npm x vitest",
            "npx vitest run",
            "npx vitest",
            "pnpm dlx vitest run",
            "pnpm dlx vitest",
            "pnpm exec vitest run",
            "pnpm exec vitest",
            "pnpm run vitest run",
            "pnpm run vitest",
            "pnpm run-script vitest run",
            "pnpm run-script vitest",
            "pnpm vitest run",
            "pnpm vitest",
            "pnpx vitest run",
            "pnpx vitest",
            "vitest run",
            "vitest",
        ];
        for command in commands {
            assert!(
                matches!(
                    classify_command(command),
                    Classification::Supported {
                        rtk_equivalent: "rtk vitest",
                        ..
                    }
                ),
                "Failed for command: {}",
                command
            );
        }
    }


    #[test]
    fn test_classify_prisma() {
        let commands = vec![
            "npm exec prisma",
            "npm rum prisma",
            "npm run prisma",
            "npm run-script prisma",
            "npm urn prisma",
            "npm x prisma",
            "pnpm dlx prisma",
            "pnpm exec prisma",
            "pnpm run prisma",
            "pnpm run-script prisma",
            "npm prisma",
            "npx prisma",
            "pnpm prisma",
            "pnpx prisma",
            "prisma",
        ];
        for command in commands {
            assert!(
                matches!(
                    classify_command(format!("{command} migrate dev").as_str()),
                    Classification::Supported {
                        rtk_equivalent: "rtk prisma",
                        ..
                    }
                ),
                "Failed for command: {}",
                command
            );
        }
    }







    // --- Gradle ---

    #[test]
    fn test_classify_gradlew() {
        assert!(matches!(
            classify_command("./gradlew assembleDebug"),
            Classification::Supported {
                rtk_equivalent: "rtk gradlew",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_gradlew_no_dot_slash() {
        assert!(matches!(
            classify_command("gradlew build"),
            Classification::Supported {
                rtk_equivalent: "rtk gradlew",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_gradlew_bat() {
        assert!(matches!(
            classify_command("gradlew.bat clean"),
            Classification::Supported {
                rtk_equivalent: "rtk gradlew",
                ..
            }
        ));
    }

    #[test]
    fn test_classify_gradle() {
        assert!(matches!(
            classify_command("gradle build"),
            Classification::Supported {
                rtk_equivalent: "rtk gradlew",
                ..
            }
        ));
    }





    #[test]
    fn test_rewrite_gradlew_test_savings() {
        assert_eq!(
            classify_command("./gradlew test"),
            Classification::Supported {
                rtk_equivalent: "rtk gradlew",
                category: "Build",
                estimated_savings_pct: 90.0,
                status: RtkStatus::Existing,
            }
        );
    }

    // --- Compound operator edge cases ---








    // --- sudo / env prefix + rewrite ---



    // --- find with native flags ---


    #[test]
    fn test_all_rules_are_complete() {
        for rule in RULES {
            assert!(
                !rule.pattern.is_empty(),
                "Rule '{}' has empty pattern",
                rule.rtk_cmd
            );
            assert!(!rule.rtk_cmd.is_empty(), "Rule with empty rtk_cmd found");
            assert!(
                rule.rtk_cmd.starts_with("rtk "),
                "rtk_cmd '{}' must start with 'rtk '",
                rule.rtk_cmd
            );
        }
    }

    // --- exclude_commands (#243) ---













    #[test]
    fn test_all_patterns_are_valid_regex() {
        use regex::Regex;
        for (i, rule) in RULES.iter().enumerate() {
            assert!(
                Regex::new(rule.pattern).is_ok(),
                "RULES[{i}] ({}) has invalid pattern '{}'",
                rule.rtk_cmd,
                rule.pattern
            );
        }
    }

    // --- #196: gh --json/--jq/--template passthrough ---






    // --- #508: RTK_DISABLED detection helpers ---

    #[test]
    fn test_cmd_has_rtk_disabled_prefix() {
        assert!(cmd_has_rtk_disabled_prefix("RTK_DISABLED=1 git status"));
        assert!(cmd_has_rtk_disabled_prefix(
            "FOO=1 RTK_DISABLED=1 cargo test"
        ));
        assert!(cmd_has_rtk_disabled_prefix(
            "RTK_DISABLED=true git log --oneline"
        ));
        assert!(!cmd_has_rtk_disabled_prefix("git status"));
        assert!(!cmd_has_rtk_disabled_prefix("rtk git status"));
        assert!(!cmd_has_rtk_disabled_prefix("SOME_VAR=1 git status"));
    }

    #[test]
    fn test_strip_disabled_prefix() {
        assert_eq!(
            strip_disabled_prefix("RTK_DISABLED=1 git status"),
            ("RTK_DISABLED=1 ", "git status")
        );
        assert_eq!(
            strip_disabled_prefix("FOO=1 RTK_DISABLED=1 cargo test"),
            ("FOO=1 RTK_DISABLED=1 ", "cargo test")
        );
        assert_eq!(strip_disabled_prefix("git status"), ("", "git status"));
    }

    // --- #485: absolute path normalization ---

    #[test]
    fn test_classify_absolute_path_grep() {
        assert_eq!(
            classify_command("/usr/bin/grep -rni pattern"),
            Classification::Supported {
                rtk_equivalent: "rtk grep",
                category: "Files",
                estimated_savings_pct: 75.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_absolute_path_ls() {
        assert_eq!(
            classify_command("/bin/ls -la"),
            Classification::Supported {
                rtk_equivalent: "rtk ls",
                category: "Files",
                estimated_savings_pct: 65.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_absolute_path_git() {
        assert_eq!(
            classify_command("/usr/local/bin/git status"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_absolute_path_no_args() {
        // /usr/bin/find alone → still classified
        assert_eq!(
            classify_command("/usr/bin/find ."),
            Classification::Supported {
                rtk_equivalent: "rtk find",
                category: "Files",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_strip_absolute_path_helper() {
        assert_eq!(strip_absolute_path("/usr/bin/grep -rn foo"), "grep -rn foo");
        assert_eq!(strip_absolute_path("/bin/ls -la"), "ls -la");
        assert_eq!(strip_absolute_path("grep -rn foo"), "grep -rn foo");
        assert_eq!(strip_absolute_path("/usr/local/bin/git"), "git");
    }

    // --- #163: git global options ---

    #[test]
    fn test_classify_git_with_dash_c_path() {
        assert_eq!(
            classify_command("git -C /tmp status"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_git_no_pager_log() {
        assert_eq!(
            classify_command("git --no-pager log -5"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_git_git_dir() {
        assert_eq!(
            classify_command("git --git-dir /tmp/.git status"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }



    #[test]
    fn test_strip_git_global_opts_helper() {
        assert_eq!(strip_git_global_opts("git -C /tmp status"), "git status");
        assert_eq!(strip_git_global_opts("git --no-pager log"), "git log");
        assert_eq!(strip_git_global_opts("git status"), "git status");
        assert_eq!(strip_git_global_opts("cargo test"), "cargo test");
    }

    #[test]
    fn test_strip_golangci_global_opts_helper() {
        assert_eq!(
            strip_golangci_global_opts("golangci-lint -v run ./..."),
            "golangci-lint run ./..."
        );
        assert_eq!(
            strip_golangci_global_opts("golangci-lint --color never run ./..."),
            "golangci-lint run ./..."
        );
        assert_eq!(
            strip_golangci_global_opts("golangci-lint --color=never run ./..."),
            "golangci-lint run ./..."
        );
        assert_eq!(
            strip_golangci_global_opts("golangci-lint --config=foo.yml run ./..."),
            "golangci-lint run ./..."
        );
        assert_eq!(
            strip_golangci_global_opts("golangci-lint version"),
            "golangci-lint version"
        );
        assert_eq!(strip_golangci_global_opts("cargo test"), "cargo test");
    }

    // --- #wc: wc filter was silently ignored by the hook ---

    #[test]
    fn test_classify_wc_supported() {
        // BUG: "wc " was in IGNORED_PREFIXES despite wc_cmd.rs having a full filter.
        // This test documents the bug: it must FAIL before the fix and PASS after.
        assert_eq!(
            classify_command("wc -l src/main.rs"),
            Classification::Supported {
                rtk_equivalent: "rtk wc",
                category: "Files",
                estimated_savings_pct: 60.0,
                status: RtkStatus::Existing,
            }
        );
    }

    #[test]
    fn test_classify_wc_multi_file() {
        assert_eq!(
            classify_command("wc src/*.rs"),
            Classification::Supported {
                rtk_equivalent: "rtk wc",
                category: "Files",
                estimated_savings_pct: 60.0,
                status: RtkStatus::Existing,
            }
        );
    }



    #[test]
    fn test_classify_command_substitution_passthrough() {
        assert_eq!(
            classify_command("git log $(git rev-parse HEAD~1)"),
            Classification::Supported {
                rtk_equivalent: "rtk git",
                category: "Git",
                estimated_savings_pct: 70.0,
                status: RtkStatus::Existing,
            }
        );
    }


    #[test]
    fn test_split_command_substitution_no_split() {
        assert_eq!(
            split_command_chain("git log $(git rev-parse HEAD~1)"),
            vec!["git log $(git rev-parse HEAD~1)"]
        );
    }





    // --- transparent_prefixes tests ---




















    #[test]
    fn test_command_no_longer_ignored() {
        assert_ne!(
            classify_command("command git status"),
            Classification::Ignored
        );
    }

    // --- Pipe + operator rewrite ---







    // --- line-continuation handling (issue #1564) -------------------






}
