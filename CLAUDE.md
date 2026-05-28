# Guardian Extension Notes

- Module: `github.com/weave-agent/weave-guardian`.
- Build and test: run `go test ./...`; lint with the repository `.golangci.yml`.
- Registration: package init registers `guardian` with config scope `guardian` through `sdk.RegisterExtensionWithScopeAndWriter[Config]` so profile approvals can persist scoped config changes.
- Core files: `guardian.go` owns profiles, decisions, approvals, grants, snapshots, and history; `classifier.go` owns path and request classification; `shell.go` owns shell parsing and command taxonomy.
- Classification convention: requests normalize to action type strings stored in decision metadata under `action_type`; exec requests can produce multiple stage action types and policy selection chooses by decision severity, then action rank.
- Policy convention: hard blocks apply to `ask`, `auto`, and custom profiles, and must not be bypassed by grants. `yolo` allows all actions.
- Overlay convention: runtime policy overlays live only in memory, are pushed/popped via SDK bus topics, and are not config profiles. Push requires a non-empty ID; pushing the same ID replaces it and gives it newest precedence.
- Policy evaluation order: override overlays (`OverrideHardBlocks=true`) run before built-in hard blocks; built-in hard blocks run before normal overlays; normal overlays run before active profile rules.
- Overlay metadata: overlay-selected decisions include `metadata.overlay_id` and `metadata.overlay_source`; snapshots clone active overlays.
- Approval convention: session approvals remain runtime-only grants. Profile approvals are persisted as constrained `sdk.GuardianProfileRule` entries in the active profile, then policy is reloaded and a fresh snapshot is published. Persisted allow rules must not bypass hard blocks.
- Profile rule constraints: saved approval rules use `grant_action_type` plus constraint metadata such as `grant_path_exact`, `grant_path_prefix`, `grant_command_exact`, `grant_command_prefix`, `grant_command_family`, `grant_working_dir`, or `grant_network_host`. Legacy `metadata.action_type` rules remain broad action-type rules.
