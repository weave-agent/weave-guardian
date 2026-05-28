# Guardian Extension

Guardian is the core Weave policy extension for normalizing actions, classifying risk, resolving policy profiles, managing approvals, storing session grants, saving profile rules, and publishing decision snapshots.

The extension registers under the `guardian` config scope with scoped config writer access and publishes `guardian.registered` when subscribed to the SDK bus. Other extensions should communicate with Guardian through the typed SDK Guardian interface and SDK bus events.

## Profiles

Guardian ships with three built-in profiles:

- `ask`: allows routine read, test, and build actions; asks before mutating or risky actions; blocks non-approvable hard-deny actions.
- `auto`: allows common development actions such as project writes, local command execution, network reads, package installs, and package scripts; asks for higher-risk actions such as remote writes, history rewrites, secret reads, global installs, process signals, service changes, remote execution, obfuscated commands, dangerous deletes, and unknown actions; blocks non-approvable hard-deny actions.
- `yolo`: allows all known and unknown actions.

Non-approvable hard-deny actions are always blocked before approval grants are considered in `ask`, `auto`, and custom profiles. They include protected path writes, policy tampering, and secret exfiltration. Remote code execution, obfuscated command payloads, and dangerous recursive deletes require approval in `ask` and `auto`. `yolo` allows all actions.

## Configuration

Example configuration:

```json
{
  "profile": "team",
  "approval_timeout": "2m",
  "profiles": {
    "team": {
      "metadata": {
        "extends": "auto"
      },
      "rules": [
        {
          "decision": "allow",
          "reason": "approved host for this profile",
          "metadata": {
            "grant_action_type": "network.read",
            "grant_constraints_version": "1",
            "grant_network_host": "registry.npmjs.org",
            "grant_profile": "team"
          }
        },
        {
          "decision": "block",
          "reason": "global installs are disabled",
          "metadata": {
            "action_type": "package.global_install"
          }
        }
      ]
    }
  }
}
```

Fields:

- `profile`: active profile name. Defaults to `ask`; unknown profile names fall back to `ask`.
- `approval_timeout`: duration to wait for an approval resolution before denying an ask decision. Defaults to `2m`.
- `profiles`: profile additions keyed by profile name using the shared SDK profile shape. Each profile extends `ask` by default, or the profile named by `metadata.extends`. Entries named `ask`, `auto`, or `yolo` extend the matching built-in profile unless a different base is explicitly configured.

Profile rules can target detailed action types through `metadata.action_type`, which is treated as a broad rule for that action type. Rules saved from profile approvals are narrower by default and use `metadata.grant_action_type` plus constraint metadata such as `grant_path_exact`, `grant_path_prefix`, `grant_command_exact`, `grant_command_prefix`, `grant_command_family`, `grant_working_dir`, or `grant_network_host`.

## Policy Overlays

Trusted extensions can push session-only policy overlays through `guardian.policy.overlay.push` with an `sdk.GuardianPolicyOverlay` payload. A non-empty `id` is required; pushing the same ID replaces the existing overlay and makes it newest for precedence. `guardian.policy.overlay.pop` removes an overlay by ID.

Overlay rules reuse `sdk.GuardianProfileRule`. They can target coarse actions through `actions`, or detailed action types through `metadata.action_type`. Normal overlays are evaluated before the active profile and may allow, ask, or block actions without changing the selected profile or persisted config.

Built-in hard blocks still win unless an overlay sets `override_hard_blocks: true`; those override overlays are evaluated before hard blocks. Decisions produced by overlays include `metadata.overlay_id` and `metadata.overlay_source` when available. Snapshots include active overlays in `overlays`, and Guardian publishes a fresh `guardian.snapshot` after successful push/pop.

## SDK Integration

Guardian implements `sdk.Guardian` with `Decide`, `Resolve`, and `Snapshot`. The extension publishes and listens on the SDK Guardian bus topics:

- `guardian.registered`: publishes the `sdk.Guardian` implementation.
- `guardian.decision`: publishes each completed `sdk.GuardianDecision`.
- `guardian.approval.request`: publishes `sdk.GuardianApprovalRequest` for ask decisions.
- `guardian.approval.resolution`: accepts and publishes `sdk.GuardianApprovalResolution`.
- `guardian.snapshot.request`: requests a current snapshot.
- `guardian.snapshot`: publishes `sdk.GuardianSnapshot`.
- `guardian.grants.clear`: accepts `sdk.GuardianClearGrantsRequest`, or `nil` to clear all grants.
- `guardian.policy.overlay.push`: accepts `sdk.GuardianPolicyOverlay` to add or replace a runtime overlay.
- `guardian.policy.overlay.pop`: accepts `sdk.GuardianPolicyOverlayPop` to remove a runtime overlay.

## Action Classification

Guardian classifies SDK requests into action types such as:

- Files: `file.read`, `file.write`, `file.delete`, `file.write_protected`
- Git: `git.read`, `git.write`, `git.discard`, `git.remote_write`, `git.history_rewrite`
- Commands: `command.read`, `command.write`, `command.exec_local`, `command.exec_remote`, `command.obfuscated`, `command.dangerous_delete`
- Network: `network.read`, `network.write`
- Packages: `package.test`, `package.build`, `package.install`, `package.global_install`, `package.script`
- Secrets and policy: `secret.read`, `secret.exfiltrate`, `policy.read`, `policy.write`
- System and fallback: `system.process_signal`, `system.service_change`, `unknown`

Shell commands are validated with an AST-backed shell parser, tokenized with quote-aware parsing, shell wrappers such as `bash -c` are unwrapped, and compound commands are decomposed so Guardian can aggregate the riskiest stage. The aggregate order is `block > ask > allow`.

Exec decisions include `metadata.action_type` for the selected policy action. They may also include `metadata.stage_action_types` and `metadata.composition_action_type` to explain multi-stage command escalation such as `network.read | shell` becoming `command.exec_remote`.

## Approvals and Grants

Ask decisions publish ID-based approval requests. Resolutions can allow or deny once, for the current session, or for the active profile. Session grants stay in memory and match future requests by normalized action type plus reusable constraints derived from the original request.

Profile approvals are saved as profile rules in Guardian config instead of as runtime grants. Guardian builds a constrained rule for the selected rule scope, saves it to the active profile, reloads profile policy, and publishes an updated snapshot. Missing or unsupported rule scopes fall back to conservative defaults: exact file for file requests, exact command for exec requests, host for network requests, and action type for other requests. Guardian refuses persisted allow rules for hard-blocked action types.

In headless mode, ask decisions are blocked immediately without publishing an approval request. Outside headless mode, ask decisions wait up to `approval_timeout`; timeout or context cancellation blocks the action.

Guardian records recent decisions with action type, verdict, reason, evidence, rule ID, and timestamp. `RecentDecisions()` returns the last 100 records; this audit history is separate from SDK snapshots. Snapshots include the active profile, resolved profiles, active runtime overlays, pending approvals, current session grants, and saved profile rules. Clear-grants events can remove all grants or selected grant scopes and IDs.
