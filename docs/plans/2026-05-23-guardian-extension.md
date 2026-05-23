# Guardian Extension

## Overview
Create the new `guardian` core extension. Guardian owns action normalization, deterministic classification, policy resolution, approval lifecycle, session grants, and decision history. It replaces file-policy and approval responsibilities currently embedded in the sandbox extension.

Guardian exposes three built-in profiles: `ask`, `auto`, and `yolo`. Users can define custom profiles that extend built-ins. Guardian communicates exclusively through SDK bus events and typed SDK interfaces.

## Context (from discovery)
- Files/components involved:
  - new repo directory: `/Users/andrey/.weave/extensions/guardian`
  - new module: `github.com/weave-agent/weave-guardian`
  - future SDK contracts from root plan: `sdk.Guardian`, guardian event payloads
- Related patterns found:
  - Core extensions register with `sdk.RegisterExtensionWithScope`.
  - Existing sandbox extension registers under scope `sandbox` and publishes `sandbox.registered`.
  - Independent extension repos use `go test ./...` and depend on `github.com/weave-agent/weave`.
- Dependencies identified:
  - Root SDK guardian types must land before implementation compiles.
  - Tool extension integrations depend on `guardian.registered`.
  - TUI extension depends on guardian approval and snapshot events.

## Development Approach
- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next.
- Make small, focused changes.
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task.
- **CRITICAL: all tests must pass before starting next task**.
- **CRITICAL: update this plan file when scope changes during implementation**.
- Run tests after each change.
- Backward compatibility with old sandbox approval events is not required.

## Testing Strategy
- Unit tests for profile resolution, classifier modules, composition detection, decisions, approval resolution, session grants, and snapshots.
- Table-driven classifier fixtures for allow/ask/block examples.

## Progress Tracking
- Mark completed items with `[x]` immediately when done.
- Add newly discovered tasks with ➕ prefix.
- Document issues/blockers with ⚠️ prefix.
- Update plan if implementation deviates from original scope.
- Keep plan in sync with actual work done.

## What Goes Where
- **Implementation Steps** (`[ ]` checkboxes): tasks achievable within this repo.
- **Post-Completion**: manual or external checks only.
- **Checkbox placement**: Checkboxes belong only in Task sections.

## Implementation Steps

### Task 1: Scaffold guardian extension module
- [x] create `go.mod` for `github.com/weave-agent/weave-guardian`
- [x] create extension entry point registering `guardian` with config scope `guardian`
- [x] publish `guardian.registered` during `Subscribe`
- [x] write tests for registration, config loading, and bus registration event
- [x] run `go test ./...` - must pass before task 2

### Task 2: Implement profile resolution
- [x] define built-in profiles `ask`, `auto`, and `yolo`
- [x] implement custom profile extension and action override resolution
- [x] implement ask fallback behavior with default `block`
- [x] write tests for built-in profile policies and custom profile merging
- [x] run `go test ./...` - must pass before task 3

### Task 3: Implement file action classifier
- [x] classify read/write/delete operations into `file.*`, `secret.*`, and `policy.*` action types
- [x] implement protected path and sensitive path matching with symlink-aware resolution
- [x] implement guardian self-protection for guardian/sandbox settings and extension policy files
- [x] write tests for normal project files, protected files, secrets, policy files, and symlink edge cases
- [x] run `go test ./...` - must pass before task 4

### Task 4: Implement shell parser and command decomposition
- [x] tokenize bash commands with quote-aware parsing
- [x] unwrap shell wrappers such as `bash -c`, `sh -c`, `zsh -c`, `eval`, and `command`
- [x] split compound commands on pipes, logical operators, sequences, and redirects
- [x] write tests for wrapper unwrapping, compound splitting, quoted strings, and obfuscation limits
- [x] run `go test ./...` - must pass before task 5

### Task 5: Implement core command classifiers
- [x] classify git commands into `git.read`, `git.write`, `git.discard`, `git.remote_write`, and `git.history_rewrite`
- [x] classify filesystem shell commands such as `rm`, `mv`, `cp`, `mkdir`, `touch`, `sed`, `find`, `grep`, and `rg`
- [x] classify network commands such as `curl`, `wget`, and HTTP methods into `network.read` and `network.write`
- [x] write table-driven tests for allow/ask/block examples across command families
- [x] run `go test ./...` - must pass before task 6

### Task 6: Implement developer workflow command classifiers
- [x] classify package and build commands for `npm`, `pnpm`, `yarn`, `bun`, `go`, `cargo`, `python`, `uv`, `pip`, `make`, and `just`
- [x] classify global package installs and unknown package/script execution conservatively
- [x] classify process/service commands such as `kill`, `pkill`, and `systemctl`
- [x] write tests for common test/build/lint commands, installs, global installs, and service changes
- [x] run `go test ./...` - must pass before task 7

### Task 7: Implement composition detector and aggregation
- [x] detect `network.read | exec` as `command.exec_remote`
- [x] detect `secret.read | network.write` as `secret.exfiltrate`
- [x] detect decode or obfuscated payload pipelines as `command.obfuscated`
- [x] aggregate stage decisions with `block > ask > allow`
- [x] write tests for composition rules and multi-stage aggregate decisions
- [x] run `go test ./...` - must pass before task 8

### Task 8: Implement approval lifecycle and session grants
- [ ] publish ID-based approval requests for ask decisions
- [ ] handle approval resolutions for once, session, and profile scopes
- [ ] store session grants and apply them to future matching requests
- [ ] implement timeout and headless ask fallback behavior
- [ ] write tests for approval allow, deny, timeout, session grant matching, and headless fallback
- [ ] run `go test ./...` - must pass before task 9

### Task 9: Implement decision history and snapshots
- [ ] record recent decisions with action type, verdict, reason, evidence, rule ID, and timestamp
- [ ] implement `Snapshot` for active profile, recent decisions, and session grants
- [ ] handle snapshot request and grants clear events
- [ ] write tests for decision history limits, snapshot payloads, and clearing grants
- [ ] run `go test ./...` - must pass before task 10

### Task 10: Verify acceptance criteria
- [ ] verify all built-in profiles produce expected decisions for representative fixtures
- [ ] verify hard block examples cannot be bypassed by session grants
- [ ] run full test suite with `go test ./...`
- [ ] run linter if configured
- [ ] update README.md with guardian behavior and configuration

## Technical Details

### Action taxonomy
```text
file.read
file.write
file.delete
file.write_protected
git.read
git.write
git.discard
git.remote_write
git.history_rewrite
command.read
command.write
command.exec_local
command.exec_remote
command.obfuscated
command.dangerous_delete
network.read
network.write
package.test
package.build
package.install
package.global_install
package.script
secret.read
secret.exfiltrate
policy.read
policy.write
system.process_signal
system.service_change
unknown
```

### Decision rules
- Unknown is `ask` in `ask` and `auto` profiles.
- Unknown is `allow` in `yolo` unless a hard block applies.
- Hard blocks include secret exfiltration, catastrophic deletes, protected path writes, remote code execution, and policy tampering.

## Post-Completion

**Manual verification**:
- Use a local Weave build to run representative commands and verify TUI approvals once tool and UI integrations are complete.

**External system updates**:
- Create upstream `github.com/weave-agent/weave-guardian` repository before first-run bootstrap can clone it.
