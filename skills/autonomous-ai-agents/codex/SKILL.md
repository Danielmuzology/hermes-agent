---
name: codex
description: Use when Engineering Specialist C executes or reviews bounded coding work through the authenticated OpenAI Codex CLI. Covers safe invocation, worktrees, evidence capture, sandbox modes, and Manager handoff.
version: 2.0.0
compatibility: Marc Mac mini; requires Git and the authenticated ChatGPT.app Codex CLI exposed through ~/.local/bin/codex.
metadata:
  author: Muzology
  owner: specialist_c
---

# Codex engineering worker

Use this skill only from Marc Assistant's Engineering profile (`specialist_c`). Darwinsky's Manager owns the human conversation, scope, approvals, and final report. Engineering owns Codex invocation, worktree isolation, evidence, diff inspection, tests, and return-to-Manager handoff.

## Provider boundary

- This Mac mini assistant uses OpenAI Codex OAuth. OpenRouter policy is VM-only and must not be applied here.
- Hermes/Darwinsky authentication and standalone Codex CLI authentication are separate stores. Never copy, print, or merge auth files.
- Never expose `~/.codex/auth.json`, `~/.hermes/auth.json`, `.env` files, request dumps, gateway sessions, peer-mailbox secrets, or credential bundles to Codex.

## Stable command

Use `/Users/marcagent/.local/bin/codex`. It resolves the signed binary embedded in ChatGPT.app without copying it out of the app bundle.

Before first use in a session:

```bash
/Users/marcagent/.local/bin/codex --version
/Users/marcagent/.local/bin/codex login status
/Users/marcagent/.local/bin/codex doctor --json
```

Report installed version and auth/doctor status without exposing tokens.

## Required execution boundary

1. Receive one Manager-approved engineering slice with repository, acceptance criteria, tests, and non-goals.
2. Verify the repository is a Git worktree and record clean/dirty status.
3. Refuse broad roots such as `~/.hermes`, `~/.codex`, employee profile/session directories, runtime request dumps, or secret stores.
4. Use a dedicated branch/worktree for implementation. Parallel Codex runs require separate worktrees.
5. Load repository `AGENTS.md` plus the applicable engineering/test skills.
6. Invoke Codex with explicit working directory, sandbox, approval mode, JSONL events, and final-message file.
7. Preserve `stderr`; never suppress diagnostic evidence.
8. Independently inspect the diff and run the relevant tests after Codex exits.
9. Do not commit, push, merge, deploy, publish, rotate credentials, or contact humans.
10. Return a status package to Manager: scope, files changed, tests, Codex exit/events, risks, blockers, and recommendation.

## Execution modes

### Read-only inspection

Use for code review, repo analysis, planning, and deterministic canaries:

```bash
/Users/marcagent/.local/bin/codex \
  -C /absolute/repo \
  --sandbox read-only \
  --ask-for-approval never \
  exec --ephemeral --json \
  --output-last-message /absolute/evidence/final.md \
  "<bounded request>" \
  > /absolute/evidence/events.jsonl \
  2> /absolute/evidence/stderr.log
```

No PTY is required for ordinary `codex exec` automation.

### Unattended workspace-write

Use when all needed work fits inside the worktree and no interactive escalation is expected:

```bash
/Users/marcagent/.local/bin/codex \
  -C /absolute/worktree \
  --sandbox workspace-write \
  --ask-for-approval never \
  exec --ephemeral --json \
  --output-last-message /absolute/evidence/final.md \
  "<one approved implementation slice>" \
  > /absolute/evidence/events.jsonl \
  2> /absolute/evidence/stderr.log
```

`never` means out-of-bound actions fail and are returned to the model. It does not grant full access.

### Supervised approval mode

Use `--ask-for-approval on-request` only when a live supervisor can inspect and answer approvals through an interactive PTY. Never use it for unattended background automation.

## Forbidden defaults

- No `danger-full-access` or approval/sandbox bypass as a fallback.
- No routine `--skip-git-repo-check` for real work.
- No broad `--add-dir` grants.
- No hidden stderr.
- No automatic network expansion.
- No automatic commit, push, PR, merge, deploy, or publication.
- No direct access to Muzology production credentials or private runtime history.

A sandbox failure is a diagnosis and blocker, not permission to remove the sandbox.

## Evidence contract

Every implementation run must preserve:

- `command.json` with secrets excluded
- `version.txt`
- `git-before.txt`
- `events.jsonl`
- `stderr.log`
- `final.md`
- `git-after.txt`
- `diff.patch`
- `result.json`

Use `scripts/run-codex-bounded.sh` when possible. Read `references/official-codex-guidance-2026-08.md` for version-specific notes and primary sources.

## Native Codex skills and AGENTS.md

- Hermes skills tell Engineering how to supervise Codex.
- Native Codex skills under `.agents/skills/` teach Codex repeated repository workflows.
- Create a native Codex skill only after the workflow repeats and has stable acceptance criteria.
- `AGENTS.md` owns repository invariants, architecture, approved commands, prohibited changes, and review requirements.
- Do not assume Claude Code or other tools consume `AGENTS.md` identically; use thin tool-specific adapters when needed.

## Verification

Completion requires all of the following:

- Codex exit code captured.
- No `turn.failed` or `error` JSONL event.
- Diff inspected independently.
- Target tests run independently.
- Unexpected changes reported and reverted only with Manager authorization.
- Manager receives the evidence summary and decides the next action.
