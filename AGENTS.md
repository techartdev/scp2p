# AGENTS.md

Guidance for future coding agents working in this repository.

## Scope
This file applies to the entire repository.

## Mission
Implement SCP2P from `SPECIFICATION.md` in milestone-oriented increments, prioritizing correctness of cryptographic validation and protocol interoperability over feature breadth.

## Workflow requirements
1. Before coding, map requested work to spec sections and call out gaps.
2. Keep changes incremental and compileable.
3. Every protocol type must include at least one round-trip encode/decode or verification test.
4. Prefer explicit data structures over dynamic maps for wire payloads.
5. Keep wire-compatibility in mind: changing serialized structures requires a short migration note in commit body.

## Project layout conventions
- `crates/scp2p-core`: shared protocol/data logic.
- `crates/scp2p-cli`: reference CLI and manual test harness.
- Add additional crates only when separation is meaningful (e.g., `scp2p-dht`, `scp2p-transport`).

## Coding conventions
- Rust edition 2021.
- Avoid panics in library code; return `anyhow::Result` or custom errors.
- Keep public API documented for major modules and types.
- Use `serde` structs for network payloads and persistable records.

## Validation checklist for each PR
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

If any check cannot run due to environment limitations, explain exactly why in the final report.

## Skills
A skill is a set of local instructions to follow that is stored in a `SKILL.md` file. Below is the list of skills that can be used. Each entry includes a name, description, and file path so you can open the source for full instructions when using a specific skill.

### Available skills
- skill-creator: Guide for creating effective skills. This skill should be used when users want to create a new skill (or update an existing skill) that extends Codex's capabilities with specialized knowledge, workflows, or tool integrations. (file: /opt/codex/skills/.system/skill-creator/SKILL.md)
- skill-installer: Install Codex skills into $CODEX_HOME/skills from a curated list or a GitHub repo path. Use when a user asks to list installable skills, install a curated skill, or install a skill from another repo (including private repos). (file: /opt/codex/skills/.system/skill-installer/SKILL.md)

### How to use skills
- Discovery: The list above is the skills available in this session (name + description + file path). Skill bodies live on disk at the listed paths.
- Trigger rules: If the user names a skill (with `$SkillName` or plain text) OR the task clearly matches a skill's description shown above, you must use that skill for that turn. Multiple mentions mean use them all. Do not carry skills across turns unless re-mentioned.
- Missing/blocked: If a named skill isn't in the list or the path can't be read, say so briefly and continue with the best fallback.
- How to use a skill (progressive disclosure):
  1) After deciding to use a skill, open its `SKILL.md`. Read only enough to follow the workflow.
  2) If `SKILL.md` points to extra folders such as `references/`, load only the specific files needed for the request; don't bulk-load everything.
  3) If `scripts/` exist, prefer running or patching them instead of retyping large code blocks.
  4) If `assets/` or templates exist, reuse them instead of recreating from scratch.
- Coordination and sequencing:
  - If multiple skills apply, choose the minimal set that covers the request and state the order you'll use them.
  - Announce which skill(s) you're using and why (one short line). If you skip an obvious skill, say why.
- Context hygiene:
  - Keep context small: summarize long sections instead of pasting them; only load extra files when needed.
  - Avoid deep reference-chasing: prefer opening only files directly linked from `SKILL.md` unless you're blocked.
  - When variants exist (frameworks, providers, domains), pick only the relevant reference file(s) and note that choice.
- Safety and fallback: If a skill can't be applied cleanly (missing files, unclear instructions), state the issue, pick the next-best approach, and continue.
