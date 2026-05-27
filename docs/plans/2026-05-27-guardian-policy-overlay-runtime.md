# Guardian Policy Overlay Runtime

## Overview
- Implement runtime Guardian policy overlays that trusted extensions can push/pop without creating user-visible profiles.
- Overlays apply on top of the active Guardian profile and can either tighten or loosen normal profile behavior.
- Overlays may override built-in hard blocks only when `OverrideHardBlocks` is explicitly set.
- Plan mode implementation is out of scope; this repo only implements the Guardian runtime behavior for generic overlays.

## Context (from discovery)
- Files/components involved:
  - `guardian.go` owns extension config, state, bus subscriptions, decisions, profile resolution, snapshots, and policy evaluation.
  - `classifier.go` classifies Guardian requests into action types such as `file.write`, `policy.write`, and `secret.exfiltrate`.
  - `guardian_test.go` contains extensive policy, snapshot, approval, and bus behavior tests.
  - `docs/guardrail-research.md` is existing Guardian documentation/research material.
- Related patterns found:
  - Guardian subscribes to bus events in `Subscribe` and publishes `GuardianRegisteredTopic`.
  - Custom profiles reuse `resolveCustomProfile`, `profileRuleActionTypes`, `normalizeDecision`, and hard-block skipping rules.
  - `policyDecisionForActionTypesWithClassification` currently evaluates hard blocks during profile rule lookup.
  - `Snapshot` clones profiles, grants, and pending approvals under lock.
- Dependencies identified:
  - Requires root SDK changes for `GuardianPolicyOverlay`, push/pop topics, pop payload, and `GuardianSnapshot.Overlays`.
  - `weave-tui-guardian` will display active overlays from snapshots but enforcement lives here.

## Development Approach
- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next.
- Make small, focused changes.
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task.
- **CRITICAL: all tests must pass before starting next task**.
- **CRITICAL: update this plan file when scope changes during implementation**.
- Run tests after each change.
- Maintain backward compatibility.

## Testing Strategy
- **Unit tests**: required for every task.
- Run focused Guardian tests after each task: `go test ./...` from this repo.
- Include decision-order tests for normal overlays, hard-block override overlays, replacement, pop, snapshot, and malformed payloads.

## Progress Tracking
- Mark completed items with `[x]` immediately when done.
- Add newly discovered tasks with ➕ prefix.
- Document issues/blockers with ⚠️ prefix.
- Update plan if implementation deviates from original scope.
- Keep plan in sync with actual work done.

## What Goes Where
- **Implementation Steps** (`[ ]` checkboxes): code changes, tests, documentation updates.
- **Post-Completion**: cross-repo coordination and manual verification.
- **Checkbox placement**: Checkboxes belong only in Task sections.

## Implementation Steps

### Task 1: Add overlay state and bus lifecycle
- [x] add overlay storage to `Guardian` state while preserving existing profile/grant/pending behavior
- [x] subscribe to `sdk.GuardianPolicyOverlayPushTopic` and `sdk.GuardianPolicyOverlayPopTopic` in `Subscribe`
- [x] implement push semantics: validate non-empty ID, normalize rules through existing profile rule conversion, replace existing overlay with same ID
- [x] implement pop semantics: remove overlay by ID and ignore unknown IDs or malformed payloads
- [x] write tests for push, replacement, pop, unknown pop, and malformed event payloads
- [x] run `go test ./...` - must pass before next task

### Task 2: Include overlays in snapshots
- [x] update `Snapshot` to clone active overlays into `sdk.GuardianSnapshot.Overlays`
- [x] ensure snapshot overlays preserve ID, source, description, rules, and `OverrideHardBlocks`
- [x] publish `GuardianSnapshotTopic` after overlay push/pop so UI extensions can refresh
- [x] write tests that pushed overlays appear in snapshots and popped overlays disappear
- [x] write tests that snapshot overlay slices/maps cannot mutate internal Guardian state
- [x] run `go test ./...` - must pass before next task

### Task 3: Apply normal overlays during decisions
- [x] introduce internal compiled overlay representation using existing `policyRule` and action-type resolution helpers
- [x] update decision evaluation so normal overlays are checked before the active profile
- [x] make newest/replaced overlay precedence explicit and deterministic
- [x] ensure normal overlays can allow actions the active profile would ask/block and block actions the active profile would allow
- [x] write tests for permissive overlay over `ask` and restrictive overlay over `auto`
- [x] write tests for overlay precedence when multiple overlays match the same action type
- [x] run `go test ./...` - must pass before next task

### Task 4: Apply explicit hard-block override semantics
- [x] split hard-block evaluation so overlays with `OverrideHardBlocks=true` are evaluated before built-in hard blocks
- [x] preserve current hard-block behavior when no override overlay matches
- [x] ensure normal overlays without `OverrideHardBlocks` cannot override hard blocks
- [x] write tests proving normal overlays cannot allow `policy.write` or secret exfiltration hard blocks
- [x] write tests proving override overlays can allow a hard-blocked action type when explicitly configured
- [x] run `go test ./...` - must pass before next task

### Task 5: Preserve grants, approvals, and decision metadata behavior
- [x] ensure overlay-produced `ask` decisions still create approvals and can be resolved through existing approval flow
- [x] ensure grants continue to match future ask decisions without bypassing active overlays unexpectedly
- [x] ensure published `GuardianDecision` includes the selected profile plus metadata indicating matched overlay ID/source when an overlay decides
- [x] write tests for overlay ask approval flow
- [x] write tests for decision metadata with matched overlay information
- [x] run `go test ./...` - must pass before next task

### Task 6: Verify acceptance criteria
- [ ] verify push/pop event handling is session-only and does not mutate config files
- [ ] verify overlays do not create profiles and do not change current profile selection
- [ ] verify both permissive and restrictive overlays work
- [ ] verify hard-block override requires explicit `OverrideHardBlocks`
- [ ] run `go test ./...`
- [ ] run repository linter if configured

## Technical Details
- Push by ID replaces the previous overlay with the same ID.
- Pop removes by ID and is idempotent.
- Overlays are runtime-only and live in memory.
- Proposed decision order:
  1. classify request into action types
  2. evaluate matching overlays with `OverrideHardBlocks=true`
  3. evaluate built-in hard blocks
  4. evaluate matching normal overlays
  5. evaluate current profile rules
  6. apply existing ask-fallback behavior for unknown actions
- Overlay rules reuse `sdk.GuardianProfileRule` so callers can target coarse actions (`write`, `delete`, `exec`) or detailed action types via metadata `action_type`.
- Decision metadata should include existing `action_type` plus overlay metadata such as `overlay_id` and `overlay_source` when applicable.

## Post-Completion

**Cross-repo order**
- Requires root SDK overlay API plan to be completed first.
- After this plan, update `weave-tui-guardian` to display active overlays from snapshots.

**Manual verification**
- Start Weave with the guardian extension and publish overlay events from a test extension or temporary command harness.
- Confirm write tools are blocked/allowed according to overlay rules without changing the selected Guardian profile.
