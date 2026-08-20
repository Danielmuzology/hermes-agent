# Official Codex guidance snapshot — 2026-08-20

Primary sources:

- CLI reference: https://developers.openai.com/codex/cli/reference/
- Non-interactive mode: https://developers.openai.com/codex/noninteractive.md
- Sandboxing: https://developers.openai.com/codex/concepts/sandboxing.md
- Skills: https://developers.openai.com/codex/skills.md
- AGENTS.md: https://developers.openai.com/codex/guides/agents-md.md
- Open-source repository/releases: https://github.com/openai/codex
- Agent Skills specification: https://agentskills.io/specification

## Verified local state

At the 2026-08-20 audit:

- Embedded binary: `/Applications/ChatGPT.app/Contents/Resources/codex`
- Version: `codex-cli 0.144.2`
- Authentication: `Logged in using ChatGPT`
- Stable host wrapper: `/Users/marcagent/.local/bin/codex`
- Latest upstream release observed during audit: `0.148.0`; it was not installed automatically.

The ChatGPT application may replace the embedded binary during application updates. Re-run `--version`, `login status`, `doctor --json`, and both canaries after any version change.

## Version-sensitive command layout

The locally installed `0.144.2` binary required global flags before `exec` during the read-only canary:

```bash
codex -C /repo --sandbox read-only --ask-for-approval never exec --ephemeral --json "..."
```

Do not copy command ordering from a community skill without checking the installed CLI help.

## Non-interactive behavior

Official guidance defines `codex exec` as the automation interface. It streams progress to `stderr`; final output goes to `stdout`. `--json` changes stdout to JSONL events. `--output-last-message` writes the final answer to a separate file. `--output-schema` can constrain structured final output.

A PTY is not required for ordinary `exec`. Use one only for interactive TUI or supervised approvals.

## Sandboxing and approvals

Sandbox and approval policy are separate:

- `read-only`: inspect only.
- `workspace-write`: permit changes within the workspace boundary.
- `danger-full-access`: no filesystem sandbox; forbidden as a routine fallback.
- `never`: never pauses for approval; failures return to the model.
- `on-request`: model can request escalation; use only when someone can answer.

For unattended bounded work, prefer `workspace-write + never`. For supervised work, use `workspace-write + on-request`. Never convert a sandbox failure into automatic full access.

## Skills

Codex loads native skills from repository `.agents/skills/`, user `$HOME/.agents/skills/`, admin `/etc/codex/skills`, and bundled system locations. A skill requires `SKILL.md` with `name` and `description`; optional `scripts/`, `references/`, and `assets/` support progressive disclosure.

Use `skills-ref validate <skill-dir>` when that validator is installed. Keep native Codex skills focused on repeated repository workflows. This Hermes skill remains the supervisory layer.

## AGENTS.md

Codex reads global `~/.codex/AGENTS.md`, then repository and nested `AGENTS.md`/`AGENTS.override.md` files from root to working directory. Closer instructions take precedence. The default combined project-doc limit is 32 KiB.

Do not assume other coding agents consume these files identically. Keep `AGENTS.md` canonical for Codex and provide thin adapters where other tools require different filenames.

## Security exclusions

Never expose these to Codex:

- `~/.codex/auth.json`
- `~/.hermes/auth.json`
- `.env` or secret files
- `MuzologyAI/data/**/sessions/`
- request dumps and gateway captures
- peer-mailbox credentials
- production tokens

A credential-bearing request dump surfaced during historical searching before this skill was installed. Treat broad runtime-history searches as unsafe. If a live credential entered model-visible output, preserve evidence without reproducing the value and escalate rotation to Daniel.
