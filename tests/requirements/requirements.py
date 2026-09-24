#!/usr/bin/env python3
"""What we require of rtk, stated so that any build can be asked.

This is a black-box suite. It never imports rtk, never looks at its source and
never names a subcommand that only one design has. That is deliberate: it exists
to compare two designs that disagree about the mechanism — one substitutes the
command before the shell runs it, the other shortens the result afterwards — and
a suite that knew about either would answer for the design rather than for the
requirement.

So every check is phrased against what a person can observe:

  * what ends up in a file the command was told to write
  * whether the command the shell is actually asked to run still parses
  * whether a long output is still shortened for the model
  * whether output belonging to one command survives another's shortening
  * whether the documented opt-out is honoured
  * whether an ordinary `cmd | head` looks like a failure

Where a build cannot answer a question at all, the result is SKIP with the
reason. It is never PASS. A suite that scores an unanswerable question as a pass
is how a missing feature comes to look like a working one.

Usage:
    requirements.py /path/to/rtk [--verbose]

Exit code is the number of failures, so it is 0 exactly when every stated
requirement holds.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

# A line rtk emits when it has shortened something. If one of these turns up in
# a file the user asked a command to write, the file holds rtk's rendering
# instead of the command's own bytes.
ABBREVIATION_MARKS = ("... (", "[+", "more lines]", "lines truncated", "lines omitted")


def abbreviated(text: str) -> str | None:
    """The first line that looks like rtk talking rather than the command."""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("... (") or "lines truncated" in s or "more lines]" in s:
            return s
    return None


class Rtk:
    """A build of rtk, asked only what it can be asked.

    `rewrite` exists in the substituting design and not in the other; the
    post-tool-use entry is the reverse. Both are probed once, and the answers
    decide which requirements this build can be held to.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.version = self._run(["--version"]).stdout.strip() or "unknown"
        self.has_rewrite = self._probe(["rewrite", "true"])
        self.has_post_hook = self._probe(["hook", "post-tool-use", "--help"])

    def _run(self, args, **kw):
        return subprocess.run(
            [self.path, *args], capture_output=True, text=True, timeout=120, **kw
        )

    def _probe(self, args) -> bool:
        """Does this subcommand exist? An unknown one is a usage error, not a
        failure of the command itself, so the message is what distinguishes
        them."""
        try:
            r = self._run(args)
        except Exception:
            return False
        blob = (r.stderr + r.stdout).lower()
        return not ("unrecognized subcommand" in blob or "unexpected argument" in blob)

    def command_the_shell_will_run(self, command: str) -> str:
        """What the shell is actually asked to execute.

        For a build that substitutes commands this is rtk's replacement; for one
        that does not, it is the command unchanged. This is the single place the
        two designs differ, and confining the difference here is what lets every
        requirement below be stated once.
        """
        if not self.has_rewrite:
            return command
        r = self._run(["rewrite", command])
        out = r.stdout.strip()
        # 0 and 3 both mean "use this"; 3 additionally asks the caller to
        # confirm. Taking 3 for a refusal made the whole suite lie: every
        # command came back unrewritten, so the file checks passed while
        # testing nothing, and the shortening check failed while the build was
        # in fact shortening. The client's own contract is the authority here
        # (free-code src/utils/shell/bashProvider.ts:68).
        return out if r.returncode in (0, 3) and out else command

    def what_the_model_sees(self, command: str) -> tuple[str, str]:
        """Run `command` the way this build would, and return (raw, seen).

        `raw` is what the command prints when nothing interferes; `seen` is what
        reaches the model. One primitive serves both designs, because the
        question is about the result and not about where the shortening
        happened: a substituting build shortens by running something else, a
        post-hook build by replacing the captured text.

        Both halves come from actually running something. An earlier version
        handed the checks a synthetic output instead, and against a substituting
        build that was meaningless — it compared text that nothing had printed,
        so a sentinel counted as destroyed when it had simply never existed.
        """
        raw = subprocess.run(["bash", "-c", command], capture_output=True,
                             text=True, timeout=300).stdout
        to_run = self.command_the_shell_will_run(command)
        seen = subprocess.run(["bash", "-c", to_run], capture_output=True,
                              text=True, timeout=300).stdout
        if self.has_post_hook:
            replaced = self._post_hook(command, seen)
            if replaced is not None:
                seen = replaced
        return raw, seen

    def _post_hook(self, command: str, output: str) -> str | None:
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": output, "stderr": "",
                              "interrupted": False, "isImage": False},
        })
        r = subprocess.run([self.path, "hook", "post-tool-use"], input=payload,
                           capture_output=True, text=True, timeout=120)
        if not r.stdout.strip():
            return None
        try:
            doc = json.loads(r.stdout)
        except json.JSONDecodeError:
            return None
        replaced = doc.get("hookSpecificOutput", {}).get("updatedToolOutput")
        if isinstance(replaced, dict):
            return replaced.get("stdout")
        return replaced if isinstance(replaced, str) else None



class Report:
    def __init__(self, verbose: bool) -> None:
        self.verbose = verbose
        self.failures: list[str] = []
        self.skips: list[str] = []
        self.passes = 0

    def record(self, req: str, case: str, ok: bool | None, detail: str = "") -> None:
        if ok is None:
            self.skips.append(f"{req}: {case} — {detail}")
            mark = "SKIP"
        elif ok:
            self.passes += 1
            mark = "pass"
        else:
            self.failures.append(f"{req}: {case} — {detail}")
            mark = "FAIL"
        if self.verbose or mark != "pass":
            line = f"  [{mark}] {case}"
            if detail and mark != "pass":
                line += f"\n         {detail}"
            print(line)


# --------------------------------------------------------------------------
# R1. A file the command was told to write holds the command's own bytes.
#
# This is the requirement the whole redesign exists for. Each shape below was a
# real defect, found by running rather than by reading: the file ended up with a
# 31-line rendering whose last line was `... (1462 lines truncated)`, and a
# reader believed it. They are kept as one list because the lesson is that the
# list has no end — flags, embedded languages, logging options and arbitrary
# local programs all persist their input without any redirect a parser can see.
# --------------------------------------------------------------------------

WRITER_SHAPES = [
    ("plain redirect", "{probe} > {f}"),
    ("redirect before the arguments", "{probe_head} > {f} {probe_tail}"),
    ("append", "{probe} >> {f}"),
    ("explicit fd 1", "{probe} 1> {f}"),
    ("both streams", "{probe} &> {f}"),
    ("noclobber override", "{probe} >| {f}"),
    ("downstream cat", "{probe} | cat > {f}"),
    ("tee", "{probe} | tee {f}"),
    ("tee with a prefix", "{probe} | command tee {f}"),
    ("tee behind env", "{probe} | env X=1 tee {f}"),
    ("tee in a subshell", "{probe} | (tee {f})"),
    ("sort -o", "{probe} | sort -o {f}"),
    ("sort with an attached -o", "{probe} | sort -o{f}"),
    ("dd of=", "{probe} | dd of={f} status=none"),
    ("sh -c with a redirect", "{probe} | sh -c 'cat > {f}'"),
    ("awk writing from its program", "{probe} | awk '{{print > \"{f}\"}}'"),
    ("sed w command", "{probe} | sed -n 'w {f}'"),
    ("redirect that outlives its clause", "exec > {f}; {probe}"),
]


def check_file_integrity(rtk: Rtk, rep: Report, workdir: str) -> None:
    print("\nR1  a file the command wrote holds the command's own bytes")
    # `ps` is the probe because rtk has a filter for it, so a build that
    # shortens will visibly shorten this and the check can tell the two apart.
    probe = "ps -eo pid,args"
    probe_head, probe_tail = "ps", "-eo pid,args"

    for name, template in WRITER_SHAPES:
        target = os.path.join(workdir, "out.txt")
        if os.path.exists(target):
            os.unlink(target)
        command = template.format(probe=probe, probe_head=probe_head,
                                  probe_tail=probe_tail, f=target)
        to_run = rtk.command_the_shell_will_run(command)

        syntax = subprocess.run(["bash", "-n", "-c", to_run], capture_output=True, text=True)
        if syntax.returncode != 0:
            rep.record("R1", name, False,
                       f"the command to be run does not parse: {to_run!r} "
                       f"({syntax.stderr.strip()})")
            continue

        subprocess.run(["bash", "-c", to_run], capture_output=True, text=True, timeout=120)
        if not os.path.exists(target):
            rep.record("R1", name, None, "the shape wrote no file on this system")
            continue
        body = open(target, errors="replace").read()
        mark = abbreviated(body)
        if mark:
            rep.record("R1", name, False,
                       f"file holds rtk's rendering: {mark!r} (ran: {to_run!r})")
        elif len(body.splitlines()) < 10:
            rep.record("R1", name, False,
                       f"file has only {len(body.splitlines())} lines (ran: {to_run!r})")
        else:
            rep.record("R1", name, True)


# --------------------------------------------------------------------------
# R2. Whatever the shell is asked to run must parse.
#
# A build that substitutes commands has to rebuild the line, and rebuilding is
# where `>|` became `> |`. Nothing is gained by shortening a command into a
# syntax error.
# --------------------------------------------------------------------------

SYNTAX_SHAPES = [
    "ps aux >| out.txt",
    "git status && ps aux >| out.txt",
    "ps aux 2>&1 | head -5",
    "ps aux <> out.txt",
    "ps aux 1>&2",
    "cat <<'EOF' | ps aux\nx\nEOF",
    "ps aux | awk '{print $1 \"|\" $2}'",
    "ps aux; ps aux",
]


def check_syntax_preserved(rtk: Rtk, rep: Report, workdir: str) -> None:
    print("\nR2  the command the shell is asked to run still parses")
    if not rtk.has_rewrite:
        rep.record("R2", "all shapes", None,
                   "this build never substitutes the command, so there is "
                   "nothing it could mangle")
        return
    for command in SYNTAX_SHAPES:
        to_run = rtk.command_the_shell_will_run(command)
        r = subprocess.run(["bash", "-n", "-c", to_run], capture_output=True, text=True)
        label = command.replace("\n", "\\n")
        if r.returncode != 0:
            rep.record("R2", label, False,
                       f"became {to_run!r}: {r.stderr.strip()}")
        else:
            rep.record("R2", label, True)


# --------------------------------------------------------------------------
# R3. A long output is still shortened.
#
# The counterweight to everything above. Every requirement here could be met by
# a build that does nothing at all, and this is the one that says so.
# --------------------------------------------------------------------------

def check_shortening_happens(rtk: Rtk, rep: Report, workdir: str) -> None:
    print("\nR3  a long output is still shortened for the model")
    raw, seen = rtk.what_the_model_sees("ps -eo pid,args")
    original = len(raw.splitlines())
    if original < 50:
        rep.record("R3", "simple command", None,
                   f"only {original} processes on this machine; nothing to shorten")
        return
    got = len(seen.splitlines())
    if got >= original:
        rep.record("R3", "simple command", False,
                   f"{original} lines in, {got} out — rtk is doing nothing")
    else:
        rep.record("R3", "simple command", True, f"{original} -> {got}")


# --------------------------------------------------------------------------
# R4. One command's shortening must not eat another's output.
#
# Bash returns a single stdout for a whole command line. A build that picks a
# filter from one part and applies it to all of it destroys the rest: measured,
# `ps aux; cargo test` had a 30-line cap applied to 1963 lines and every one of
# 400 test-result lines went. The requirement is about the result, so it holds
# for either design — a substituting build satisfies it by rewriting only the
# part it understands.
# --------------------------------------------------------------------------

def check_foreign_output_survives(rtk: Rtk, rep: Report, workdir: str) -> None:
    print("\nR4  shortening one command does not destroy another's output")
    # The second command really prints these, so a missing sentinel means it
    # was destroyed rather than never produced.
    tail = "seq -f SENTINEL-%04g 0 399"
    for label, joiner in [("second command after ;", ";"),
                          ("second command after &&", "&&")]:
        command = f"ps -eo pid,args {joiner} {tail}"
        raw, seen = rtk.what_the_model_sees(command)
        produced = sum(1 for l in raw.splitlines() if l.startswith("SENTINEL-"))
        if produced != 400:
            rep.record("R4", label, None,
                       f"the fixture printed {produced} sentinels, not 400")
            continue
        kept = sum(1 for l in seen.splitlines() if l.startswith("SENTINEL-"))
        if kept == 400:
            rep.record("R4", label, True, "all 400 survived")
        else:
            rep.record("R4", label, False,
                       f"{400 - kept} of 400 lines of the second command's "
                       f"output were destroyed ({len(raw.splitlines())} -> "
                       f"{len(seen.splitlines())} lines)")


# --------------------------------------------------------------------------
# R5. The documented per-command opt-out is honoured.
#
# `exclude_commands` is the only way to turn shortening off for one command and
# have it stay off; the environment switch has to be typed every time. It once
# survived as a key that still parsed and documentation that still promised it
# while nothing read it any more.
# --------------------------------------------------------------------------

def check_opt_out(rtk: Rtk, rep: Report, workdir: str) -> None:
    print("\nR5  the documented per-command opt-out is honoured")
    long_output = subprocess.run(["ps", "-eo", "pid,args"],
                                 capture_output=True, text=True).stdout
    if len(long_output.splitlines()) < 50:
        rep.record("R5", "exclude_commands", None, "not enough output to judge")
        return

    home = os.path.join(workdir, "home")
    os.makedirs(os.path.join(home, ".config", "rtk"), exist_ok=True)
    with open(os.path.join(home, ".config", "rtk", "config.toml"), "w") as fh:
        fh.write('[hooks]\nexclude_commands = ["ps"]\n')

    env = dict(os.environ, HOME=home, XDG_CONFIG_HOME=os.path.join(home, ".config"))
    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "ps -eo pid,args"},
        "tool_response": {"stdout": long_output, "stderr": "",
                          "interrupted": False, "isImage": False},
    })

    if rtk.has_post_hook:
        r = subprocess.run([rtk.path, "hook", "post-tool-use"], input=payload,
                           capture_output=True, text=True, env=env, timeout=120)
        excluded = not r.stdout.strip()
    elif rtk.has_rewrite:
        r = subprocess.run([rtk.path, "rewrite", "ps -eo pid,args"],
                           capture_output=True, text=True, env=env, timeout=120)
        excluded = r.returncode != 0 or not r.stdout.strip() \
            or r.stdout.strip() == "ps -eo pid,args"
    else:
        rep.record("R5", "exclude_commands", None, "build offers neither entry point")
        return

    rep.record("R5", "exclude_commands", excluded,
               "" if excluded else "an excluded command was shortened anyway")


# --------------------------------------------------------------------------
# R6. An ordinary `cmd | head` must not look like a failure.
#
# The reader closing the pipe is how that line always ends. Announcing it sent
# people looking for a fault above a correct result.
# --------------------------------------------------------------------------

def check_sigpipe_quiet(rtk: Rtk, rep: Report, workdir: str) -> None:
    print("\nR6  a pipeline ending early is not announced as a failure")
    big = os.path.join(workdir, "big.txt")
    with open(big, "w") as fh:
        for i in range(200_000):
            fh.write(f"line {i}\n")

    r = subprocess.run(
        f"{shlex_quote(rtk.path)} cat {shlex_quote(big)} | head -2",
        shell=True, capture_output=True, text=True, timeout=120,
    )
    noisy = [l for l in r.stderr.splitlines() if "signal 13" in l or "SIGPIPE" in l]
    rep.record("R6", "cmd | head", not noisy,
               f"stderr said: {noisy[0]!r}" if noisy else "")

    # The control. Without it, deleting the report entirely would score a pass.
    r = subprocess.run([rtk.path, "sh", "-c", "kill -TERM $$"],
                       capture_output=True, text=True, timeout=120)
    reported = "signal 15" in r.stderr or r.returncode == 143
    rep.record("R6", "a real signal is still reported", reported,
               "" if reported else f"rc={r.returncode} stderr={r.stderr.strip()!r}")


def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rtk", help="path to the rtk binary under test")
    ap.add_argument("--verbose", action="store_true", help="show passing cases too")
    args = ap.parse_args()

    if not os.access(args.rtk, os.X_OK):
        print(f"not executable: {args.rtk}", file=sys.stderr)
        return 2

    rtk = Rtk(os.path.abspath(args.rtk))
    print(f"binary   {rtk.path}")
    print(f"version  {rtk.version}")
    print(f"entries  rewrite={'yes' if rtk.has_rewrite else 'no'}  "
          f"post-tool-use={'yes' if rtk.has_post_hook else 'no'}")

    rep = Report(args.verbose)
    workdir = tempfile.mkdtemp(prefix="rtk-requirements-")
    try:
        for check in (check_file_integrity, check_syntax_preserved,
                      check_shortening_happens, check_foreign_output_survives,
                      check_opt_out, check_sigpipe_quiet):
            check(rtk, rep, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\n{rep.passes} pass, {len(rep.failures)} fail, {len(rep.skips)} skip")
    if rep.skips:
        print("\nnot answerable by this build:")
        for s in rep.skips:
            print(f"  - {s}")
    if rep.failures:
        print("\nunmet requirements:")
        for f in rep.failures:
            print(f"  - {f}")
    return len(rep.failures)


if __name__ == "__main__":
    sys.exit(main())
