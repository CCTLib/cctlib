# Git hooks

Versioned git hooks for CCTLib. Installed via `make install-hooks`
(from the repo root), which sets `core.hooksPath` for the current
clone. One-time setup per checkout; nothing runs until you install.

## Hooks

### `pre-commit`

**Phase 1 — clang-format** (always runs):
Runs `clang-format-15` on every staged `.cpp` / `.H` / `.h` / `.hpp`
file. Any file that clang-format changes is auto-re-staged (with a
notice printed to stderr). The commit proceeds without prompting.

If `clang-format-15` is not on PATH, the hook prints an install hint
and continues (no format check).

**Phase 2 — clang-tidy** (runs when available):
If `clang-tidy-15`, `compile_commands.json`, and `$PIN_ROOT` are all
present, the hook runs clang-tidy with `--fix` on staged files.
Auto-fixable issues are applied and re-staged. Unfixable diagnostics
block the commit with an error message.

If any of the three prerequisites are missing, the phase is silently
skipped — CI catches lint drift on push.

## Install

    make install-hooks

## Prerequisites for clang-tidy in the hook

    sudo apt install clang-15 clang-tidy-15
    export PIN_ROOT=/path/to/pin
    make clean && bear -- make    # produces compile_commands.json

## Bypass a single commit

    git commit --no-verify

## Uninstall

    git config --unset core.hooksPath
