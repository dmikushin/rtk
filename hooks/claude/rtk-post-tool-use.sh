#!/usr/bin/env bash
# rtk-hook-version: 4
# RTK Claude Code hook — condenses the OUTPUT a tool returns, after it ran.
# Requires: rtk >= 0.41.0
#
# A thin delegating hook: all condensing logic lives in
# `rtk hook post-tool-use` (src/hooks/post_tool_use_cmd.rs), which is the
# single source of truth. To change what gets condensed, edit the Rust —
# not this file.
#
# Why PostToolUse and not PreToolUse: the old layer rewrote the command before
# the shell ran it, which put rtk between the program and the file —
# `ps aux > ps.txt` wrote an abbreviated rendering into ps.txt. No classifier
# can tell "output the caller stores" from "output the model reads" by looking
# at a command string, and three review rounds proved it by example
# (`sort -of`, `sed -n 'w f'`, `./sort`, `exec >f`). Here the command has
# already run untouched; only the copy travelling to the model is replaced.
# Requires the client to apply `updatedToolOutput` for non-MCP tools after
# hooks run.

# A failure here must never fail the tool call: print nothing, exit 0, and the
# harness keeps the original output. That is the contract the whole script
# follows — every warning goes to stderr, every exit is 0.

if ! command -v rtk &>/dev/null; then
  echo "[rtk] WARNING: rtk is not installed or not in PATH; output will not be condensed." >&2
  exit 0
fi

# Version guard: `rtk hook post-tool-use` was added in 0.41.0.
# Cached so we do not spawn a version check on every tool call.
CACHE_DIR=${XDG_CACHE_HOME:-$HOME/.cache}
CACHE_FILE="$CACHE_DIR/rtk-hook-ptu-version-ok"
if [ ! -f "$CACHE_FILE" ]; then
  RTK_VERSION=$(rtk --version 2>/dev/null)
  RTK_VERSION=${RTK_VERSION#rtk }
  RTK_VERSION=${RTK_VERSION%% *}
  if [ -n "$RTK_VERSION" ]; then
    IFS=. read -r MAJOR MINOR PATCH <<<"$RTK_VERSION"
    # Require >= 0.41.0
    if [ "$MAJOR" -eq 0 ] && [ "$MINOR" -lt 41 ]; then
      echo "[rtk] WARNING: rtk $RTK_VERSION is too old for the PostToolUse hook (need >= 0.41.0); output will not be condensed." >&2
      exit 0
    fi
  fi
  mkdir -p "$CACHE_DIR" 2>/dev/null
  touch "$CACHE_FILE" 2>/dev/null
fi

# Delegate everything to the Rust binary. It reads the payload from stdin and
# prints the JSON protocol answer on stdout — or nothing, when the original
# output should stand.
rtk hook post-tool-use
