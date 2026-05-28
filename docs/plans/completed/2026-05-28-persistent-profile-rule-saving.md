# Guardian Persistent Profile Rule Saving

Status: Completed.

## Overview
- Change Guardian profile-scope approvals from runtime-only grants into durable profile rules saved to configuration.
- Keep Guardian as the owner of policy semantics: TUI provides user intent, Guardian normalizes constraints, rejects unsafe broadening, saves config, reloads policy, and publishes snapshots.
- Make saved rules gradual and safe: exact file, directory, project, exact command, command prefix, command family, network host, or explicit broad action type.

## Context (from discovery)
- Files/components involved:
  - `guardian.go` registers with `sdk.RegisterExtensionWithScope`, so it currently receives only read access.
  - `Config` contains `Profile`, `AskFallback`, `ApprovalTimeout`, and `Profiles map[string]sdk.GuardianProfile`.
  - `applyGrant` stores both session and profile approvals as in-memory `sdk.GuardianGrant` values.
  - `grantConstraintsForRequest` already derives reusable constraints: working dir, path exact/prefix, command family, network host, and version metadata.
  - `grantMatchesRequest` already matches runtime grants against those constraints.
  - `resolveProfiles` and `resolveCustomProfile` compile configured profile rules, but current rules are mostly keyed by action type and built-in profile names return before custom additions can be applied.
  - `guardian_test.go` already has broad coverage for profiles, overlays, grants, approval resolutions, and snapshots.
- Related patterns found:
  - Hard-blocked action types are protected by `hardBlockRule` and overlay hard-block override handling.
  - Runtime grants use metadata keys such as `grant_constraints_version`, `grant_action_type`, `grant_working_dir`, `grant_path_prefix`, `grant_path_exact`, `grant_command_family`, and `grant_network_host`.
  - Profile extension uses `metadata.extends` for custom profile inheritance.
- Dependencies identified:
  - Root `weave` SDK/settings support for active-layer scoped config saving and `GuardianResolution.RuleScope` is available through `github.com/weave-agent/weave v0.0.14`.
  - `weave-tui-guardian` will send selected rule scope in approval resolutions.

## Development Approach
- **Testing approach**: Regular (code first, then tests in the same task)
- Complete each task fully before moving to the next.
- Make small, focused changes.
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task.
- **CRITICAL: all tests must pass before starting next task**.
- **CRITICAL: update this plan file when scope changes during implementation**.
- Run tests after each change.
- Maintain backward compatibility with existing config rules and runtime grants.

## Testing Strategy
- **Unit tests**: required for every task.
- Add focused tests in `guardian_test.go` for persistent rule creation, matching, hard-block safety, built-in profile extension, and save failures.
- Promote useful desired grant-scope fixtures from `classifier_eval_test.go` only if they become locked behavior.
- Run `go test ./...` after each task in this repo.

## Progress Tracking
- Mark completed items with `[x]` immediately when done.
- Add newly discovered tasks with ➕ prefix.
- Document issues/blockers with ⚠️ prefix.
- Update plan if implementation deviates from original scope.
- Keep plan in sync with actual work done.

## What Goes Where
- **Implementation Steps** (`[ ]` checkboxes): tasks achievable within this codebase - code changes, tests, documentation updates.
- **Post-Completion** (no checkboxes): items requiring external action - manual testing, changes in consuming projects, deployment configs, third-party verifications.
- **Checkbox placement**: Checkboxes belong only in Task sections.

## Implementation Steps

### Task 1: Give Guardian scoped config writer access
- [x] change extension registration in `guardian.go` to `sdk.RegisterExtensionWithScopeAndWriter`
- [x] add a writer field to `Guardian` using the optional scoped config writer interface from the root SDK
- [x] preserve `New(Config)` behavior for tests by using a no-op writer when none is provided
- [x] write tests that extension construction accepts writer-capable and writerless configs
- [x] run `go test ./...` - must pass before next task

### Task 2: Convert approval rule scope into constrained profile rules
- [x] add a function that builds `sdk.GuardianProfileRule` from approval, decision, active profile, and `GuardianResolution.RuleScope`
- [x] map file scopes to `grant_path_exact`, `grant_path_prefix`, project root prefix, or explicit action-type-only metadata
- [x] map command scopes to exact command metadata, command prefix metadata, command family plus working dir, or explicit action-type-only metadata
- [x] map network scopes to host constraints or explicit action-type-only metadata
- [x] default missing rule scope to a conservative scope derived from the request type
- [x] reject persisted allow rules for hard-blocked action types
- [x] write tests for file exact, file directory, file project, command exact, command family, network host, and broad action rules
- [x] write tests for hard-block rejection and unknown/unsupported rule-scope fallback
- [x] run `go test ./...` - must pass before next task

### Task 3: Persist profile rules to active config
- [x] change `applyGrant` so `GuardianGrantScopeProfile` saves a profile rule instead of only appending an in-memory grant
- [x] preserve `GuardianGrantScopeSession` as runtime-only grants
- [x] append rules to `Config.Profiles[activeProfile].Rules`, creating the profile if needed
- [x] preserve existing profile metadata and set default `metadata.extends` when saving into a built-in profile name
- [x] call scoped config save with the updated Guardian config and handle save errors by not silently broadening policy
- [x] reload `g.profiles` from the updated config after a successful save
- [x] publish an updated Guardian snapshot after a successful save
- [x] write tests that profile approvals call the writer with expected guardian config
- [x] write tests that save failures do not add runtime grants or policy allows
- [x] run `go test ./...` - must pass before next task

### Task 4: Match constrained persisted profile rules
- [x] extend compiled policy rules to carry constraint metadata, not only decision and reason
- [x] update profile rule compilation to retain persisted grant constraints from rule metadata
- [x] update policy decision matching so constrained rules use the same matching semantics as runtime grants
- [x] keep legacy action-type-only rules working as broad rules for existing configs
- [x] ensure broad action-type-only rules only occur when config already has no constraints or user explicitly selected broad action scope
- [x] write tests that constrained saved file rules do not allow unrelated files
- [x] write tests that constrained saved command rules do not allow unrelated command families or working dirs
- [x] write tests that constrained saved network rules do not allow unrelated hosts
- [x] run `go test ./...` - must pass before next task

### Task 5: Allow saved additions to built-in profiles
- [x] update `resolveCustomProfile` so custom config entries named `ask`, `auto`, or `yolo` can extend/override their built-in base instead of being ignored
- [x] avoid inheritance cycles when a built-in-name profile has missing or self-referential `extends` metadata
- [x] preserve existing custom profile inheritance semantics
- [x] write tests that `guardian.profiles.ask.rules` adds constrained rules to the ask profile
- [x] write tests that built-in hard-block protections still apply after built-in profile extension
- [x] run `go test ./...` - must pass before next task

### Task 6: Verify acceptance criteria
- [x] verify `Allow similar for session` remains runtime-only
- [x] verify `Add rule to profile` persists to config only when a safe constrained rule can be built
- [x] verify persisted rules survive Guardian reinitialization
- [x] verify snapshots include saved profile rules but runtime profile grants are no longer required for persistence
- [x] run full test suite with `go test ./...`
- [x] run linter with `golangci-lint run` or the repo Makefile if present

### Task 7: Update documentation
- [x] update `README.md` Guardian profile examples if they document profile rules
- [x] update `CLAUDE.md` if new Guardian persistence behavior should be known by agents

## Technical Details
- Saved rule metadata should reuse existing grant constraint keys where possible:
  - `grant_constraints_version`
  - `grant_action_type`
  - `grant_working_dir`
  - `grant_path_prefix`
  - `grant_path_exact`
  - `grant_command_exact`
  - `grant_command_prefix`
  - `grant_command_family`
  - `grant_network_host`
- Profile rules should remain data-only SDK values. Guardian owns normalization and matching.
- Do not let the UI or root settings package decide whether a Guardian rule is safe.

## Post-Completion

**Manual verification**:
- In the TUI, approve a file write with exact-file scope, restart Weave, and verify only the same file is allowed.
- Approve a command-family rule, restart Weave, and verify unrelated commands still ask.

**External system updates**:
- Requires root `weave` SDK/settings changes before implementation.
- Requires `weave-tui-guardian` UI changes to expose rule-scope choices.
