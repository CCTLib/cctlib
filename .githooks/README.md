# Git hooks

Versioned git hooks for CCTLib. Installed via `make install-hooks`
(from the repo root), which sets `core.hooksPath` for the current
clone. One-time setup per checkout; nothing runs until you install.

## Hooks

### `pre-commit`

Runs `clang-format-15` on every staged `.cpp` / `.H` / `.h` / `.hpp`
file. Any file that clang-format changes is auto-re-staged (with a
notice printed to stderr). The commit proceeds without prompting.

If `clang-format-15` is not on PATH, the hook prints an install hint
and exits 0 (no format check). Override the binary via
`CLANG_FORMAT=...`.

`clang-tidy` is intentionally NOT run here — it needs
`compile_commands.json` (produced by `bear -- make`) and a working
`$PIN_ROOT`, both of which are workstation-only. CI runs
`make format-check` on push/PR as a safety net; `make lint` is a
manual step on a workstation with the Pin toolchain available.

## Install

    make install-hooks

## Bypass a single commit

    git commit --no-verify

## Uninstall

    git config --unset core.hooksPath
