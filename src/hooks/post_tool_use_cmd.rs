//! PostToolUse hook: condense what the model READS, never what the shell RAN.
//!
//! The whole reason this exists as a separate entry is a three-round failure
//! of the alternative. The old PreToolUse layer rewrote the command string
//! before the shell saw it, which put rtk between the program and the file:
//! `ps aux > ps.txt` became `rtk ps aux > ps.txt` and the file received an
//! abbreviated rendering ending in `... (1462 lines truncated)`. Deciding
//! from a command string which redirects are safe cannot be done — the
//! distinction between "output the caller stores" and "output the model
//! reads" is not in the string, and each review round found a fresh shape
//! that broke the classifier (`sort -of`, `sed -n 'w f'`, `./sort`,
//! `exec >f`).
//!
//! Here the question does not arise. The command has already run, untouched;
//! files hold its own bytes by construction. This hook sees only the
//! captured `tool_response` and replaces only that, so the model receives a
//! condensed rendering while every file on disk stays exact. The harness
//! feature it needs (`updatedToolOutput` for any tool, applied after hooks
//! run) was added alongside this hook.
//!
//! Uses `writeln!(stdout, ...)` instead of `println!` — accidental
//! stdout/stderr corrupts the JSON protocol (Claude Code bug #4669
//! silently disables the hook).

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

use crate::core::config::Config;
use crate::core::toml_filter::{apply_filter, find_matching_filter};

const STDIN_CAP: usize = 1_048_576; // 1 MiB

fn read_stdin_limited() -> Result<String> {
    let mut input = String::new();
    io::stdin()
        .take((STDIN_CAP + 1) as u64)
        .read_to_string(&mut input)
        .context("Failed to read stdin")?;
    if input.len() > STDIN_CAP {
        anyhow::bail!("hook stdin exceeds {} byte limit", STDIN_CAP);
    }
    Ok(input)
}

/// Is this a single simple command, whose output a filter can be trusted with?
///
/// Bash hands back ONE stdout for the whole command line, so a filter chosen
/// from one part of a compound would be applied to the whole of it. That is not
/// a missed saving, it is a wrong answer: measured, `ps aux; cargo test` had the
/// ps filter's 30-line cap applied to all 1963 lines and every one of the 400
/// `cargo test` result lines was destroyed. The model would have been shown a
/// plausible-looking process list and no test results at all.
///
/// The same holds for a pipe — the output belongs to the last stage, not the
/// first — and for anything that could run a second program. So the filter is
/// applied only when the command is one program with its arguments.
///
/// This is the same conclusion the deleted PreToolUse layer reached the hard
/// way: what a filter may safely touch cannot be inferred from a shell string
/// beyond the simplest case. The difference is that here the fallback is to
/// show the output as it is, which costs tokens, rather than to write an
/// abbreviation into someone's file.
///
/// A pipeline needs no help anyway: `ps aux | head -5` has already been cut to
/// five lines by the time this sees it.
fn is_single_simple_command(command: &str) -> bool {
    let c = command.trim();
    if c.is_empty() {
        return false;
    }
    // Operators that join programs, and substitutions that hide one.
    const COMPOUND: &[&str] = &["|", ";", "&", "\n", "$(", "`", "<(", ">("];
    !COMPOUND.iter().any(|m| c.contains(m))
}

/// Strip a configured wrapper so the filter is chosen by the real command.
///
/// `transparent_prefixes = ["docker exec mycontainer"]` means every command in
/// that project arrives wrapped, and without this none of them would match a
/// filter. The old layer stripped the prefix, rewrote, and put the prefix back;
/// here there is nothing to put back — only the lookup needs it.
///
/// Literal and strict, as documented: `"foo bar"` matches a command that equals
/// it or starts with `"foo bar "`, nothing else.
fn strip_transparent_prefix<'a>(command: &'a str, prefixes: &[String]) -> &'a str {
    let c = command.trim();
    for p in prefixes {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        if c == p {
            return "";
        }
        if let Some(rest) = c.strip_prefix(p) {
            if rest.starts_with(' ') {
                return rest.trim_start();
            }
        }
    }
    c
}

/// Is this command one the user asked to be left alone?
///
/// `exclude_commands = ["curl", "playwright"]` is the documented way to opt a
/// command out of shortening, and it nearly died with the rewrite layer: the key
/// still parsed and the documentation still promised it, but nothing read it any
/// more. A reviewer noticed. It is the only per-command opt-out there is —
/// `RTK_DISABLED=1` has to be typed every single time — so losing it quietly
/// would have taken something that had nothing to do with guessing at redirects.
fn is_excluded_command(command: &str, excludes: &[String]) -> bool {
    let c = command.trim();
    excludes.iter().any(|e| {
        let e = e.trim();
        !e.is_empty() && (c == e || c.strip_prefix(e).is_some_and(|r| r.starts_with(' ')))
    })
}

/// Would this command's output be shown raw even under the OLD layer?
///
/// `RTK_DISABLED=1` is a promise to the caller: the bytes come back uncut.
/// Stripping the prefix and filtering anyway would break that promise while
/// appearing to honour it — the first version of `filter_lookup_key` did
/// exactly that, and a unit test caught it before anything shipped.
fn is_disabled(command: &str) -> bool {
    command.trim_start().starts_with("RTK_DISABLED=")
}

/// Condense one captured stdout according to the matching filter.
///
/// Returns `None` when there is nothing to do — no filter, empty output, or a
/// command already condensed by an explicit `rtk …` call. A hook that does
/// nothing prints nothing and exits 0; the harness then keeps the original
/// output.
///
/// Note it is `is_empty()` that declines, not `len() < some cap`: the filters
/// themselves carry the size policy (head/tail/max_lines), and second-guessing
/// them here would fork the policy in two places.
pub fn condense(command: &str, stdout: &str) -> Option<String> {
    if stdout.is_empty() || is_disabled(command) {
        return None;
    }
    if !is_single_simple_command(command) {
        return None;
    }
    let cfg = Config::load().unwrap_or_default();
    let key = strip_transparent_prefix(command, &cfg.hooks.transparent_prefixes);
    if is_excluded_command(key, &cfg.hooks.exclude_commands) {
        return None;
    }
    if key == "rtk" || key.starts_with("rtk ") {
        // Already condensed by an explicit `rtk …` invocation; the person (or
        // agent) asked for that rendering and a second pass would compound
        // truncation.
        return None;
    }
    let filter = find_matching_filter(key)?;
    let filtered = apply_filter(filter, stdout);
    if filtered == stdout {
        // No filter changed anything — do not round-trip the output through a
        // replacement the harness must then re-render for nothing.
        None
    } else {
        Some(filtered)
    }
}

/// Run the PostToolUse hook: read the payload, condense `tool_response.stdout`
/// if a filter matches, and emit an `updatedToolOutput` replacement.
pub fn run() -> Result<()> {
    let input = read_stdin_limited()?;
    let input = input.trim();
    if input.is_empty() {
        return Ok(());
    }
    let v: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return Ok(()), // not our protocol — stay silent, exit 0
    };

    // Only the Bash tool's response has a `stdout` field. Other tools get
    // their own shapes, and this hook has nothing to say about them yet.
    let command = v
        .get("tool_input")
        .and_then(|t| t.get("command"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let response = match v.get("tool_response") {
        Some(r) if r.is_object() => r.clone(),
        _ => return Ok(()),
    };
    let stdout = response
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or("");

    let Some(condensed) = condense(command, stdout) else {
        return Ok(());
    };

    // Preserve every other field of the response — `interrupted`,
    // `isImage`, `returnCodeInterpretation` and whatever else the tool adds —
    // and replace only `stdout`. The replacement must have the SAME SHAPE the
    // tool itself returns; a bare string made the client's renderer fail with
    // `undefined is not an object (evaluating 'stderr.trim')`, measured.
    let mut updated = response;
    updated["stdout"] = json!(condensed);

    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": updated,
        }
    });
    let stdout_io = io::stdout();
    let mut lock = stdout_io.lock();
    writeln!(lock, "{}", out).ok(); // protocol: never fail the hook on a write
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn many(n: usize) -> String {
        (0..n).map(|i| format!("root {i:6}  0.1  0.2 /very/long/process/number/{i}/with/padding\n")).collect()
    }

    /// The reason this entry exists: a redirect must not stop the model's copy
    /// from being condensed, because this hook never touches the command.
    /// With the old PreToolUse layer the same shape CORRUPTED the file.
    #[test]
    fn condenses_even_when_the_output_went_to_a_file() {
        let c = condense("ps -eo pid,args > out.txt", &many(100));
        assert!(c.is_some(), "a redirect must not disable condensing");
    }

    /// A compound or a pipeline is declined, and this test replaced one that
    /// asserted the opposite. Bash returns a single stdout for the whole line,
    /// so a filter picked from one part is applied to all of it: measured,
    /// `ps aux; cargo test` had the ps filter's 30-line cap applied to 1963
    /// lines and all 400 test-result lines were destroyed. Showing the output
    /// whole costs tokens; showing a confident abbreviation of the wrong thing
    /// costs the answer.
    #[test]
    fn declines_anything_that_is_not_one_simple_command() {
        for cmd in [
            "ps aux; cargo test",
            "cargo test; ps aux",
            "ps aux | head -5",
            "ps aux | grep python",
            "ps aux && echo done",
            "ps aux & ",
            "echo $(ps aux)",
        ] {
            assert_eq!(condense(cmd, &many(100)), None, "must decline: {}", cmd);
        }
    }

    /// The control: a single simple command still condenses, redirect or not.
    /// The redirect case is the point of the whole redesign — the file already
    /// holds the real bytes, so only the model's copy is shortened.
    #[test]
    fn condenses_one_simple_command() {
        assert!(condense("ps aux", &many(100)).is_some());
        assert!(condense("ps -eo pid,args", &many(100)).is_some());
    }

    #[test]
    fn leaves_short_output_alone() {
        // The ps filter's own test: a short list passes through unchanged.
        assert_eq!(
            condense(
                "ps aux",
                "USER   PID %CPU COMMAND\nroot     1  0.0 /sbin/init"
            ),
            None
        );
    }

    #[test]
    fn never_condenses_an_explicit_rtk_invocation() {
        assert_eq!(condense("rtk git diff", &many(100)), None);
        assert_eq!(condense("RTK_DISABLED=1 ps aux", &many(100)), None);
    }

    #[test]
    fn empty_stdout_is_left_alone() {
        assert_eq!(condense("ps aux", ""), None);
    }

    #[test]
    fn simple_command_detection() {
        assert!(is_single_simple_command("ps aux"));
        assert!(is_single_simple_command("git status --short"));
        for c in ["a | b", "a; b", "a && b", "a & b", "echo $(x)", "echo `x`", "a\nb"] {
            assert!(!is_single_simple_command(c), "should be compound: {:?}", c);
        }
    }

    /// `RTK_DISABLED=1` promises the caller raw bytes. The first version of
    /// this hook stripped the prefix and filtered anyway; this test is what
    /// caught it.
    #[test]
    fn rtk_disabled_means_raw_bytes_not_a_different_lookup() {
        assert!(!is_disabled("ps aux"));
        assert!(is_disabled("RTK_DISABLED=1 ps aux"));
        assert_eq!(condense("RTK_DISABLED=1 ps aux", &many(100)), None);
    }

    /// The opt-out that nearly died with the rewrite layer: the key still
    /// parsed and the docs still promised it, but nothing read it. Tested
    /// against the pure functions rather than through `condense`, which reads
    /// the user's real config file.
    #[test]
    fn exclude_commands_matches_a_command_and_its_arguments() {
        let ex = vec!["curl".to_string(), "docker compose".to_string()];
        assert!(is_excluded_command("curl", &ex));
        assert!(is_excluded_command("curl -sS https://x", &ex));
        assert!(is_excluded_command("docker compose up", &ex));
        // Not a prefix match on a longer word — `curlie` is a different program.
        assert!(!is_excluded_command("curlie -sS https://x", &ex));
        assert!(!is_excluded_command("git status", &ex));
        assert!(!is_excluded_command("git status", &[]));
    }

    /// Without this a project that wraps every command never matches a filter.
    #[test]
    fn transparent_prefixes_are_stripped_for_the_lookup_only() {
        let pfx = vec!["docker exec mycontainer".to_string()];
        assert_eq!(
            strip_transparent_prefix("docker exec mycontainer git status", &pfx),
            "git status"
        );
        // Strict: a longer container name is not the configured prefix.
        assert_eq!(
            strip_transparent_prefix("docker exec othercontainer git status", &pfx),
            "docker exec othercontainer git status"
        );
        assert_eq!(strip_transparent_prefix("git status", &pfx), "git status");
        assert_eq!(strip_transparent_prefix("git status", &[]), "git status");
    }
}
