# Guardian Extension

Guardian is the core Weave policy extension for normalizing actions, classifying risk, resolving policy profiles, managing approvals, storing session grants, and publishing decision snapshots.

The extension registers under the `guardian` config scope and publishes `guardian.registered` when subscribed to the SDK bus. Other extensions should communicate with Guardian through the typed SDK Guardian interface and SDK bus events.

## Profiles

Guardian ships with three built-in profiles:

- `ask`: allows routine read, test, and build actions; asks before mutating or risky actions; blocks hard-deny actions.
- `auto`: allows common development actions such as project writes, local command execution, network reads, package installs, and package scripts; asks for higher-risk actions such as remote writes, history rewrites, secret reads, global installs, process signals, service changes, and unknown actions; blocks hard-deny actions.
- `yolo`: allows all known and unknown actions except hard-deny actions.

Hard-deny actions are always blocked before approval grants are considered. They include remote code execution, obfuscated command payloads, dangerous recursive deletes, protected path writes, policy tampering, and secret exfiltration.

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
          "decision": "ask",
          "reason": "network reads require team approval",
          "metadata": {
            "action_type": "network.read"
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
- `profiles`: custom profiles keyed by profile name using the shared SDK profile shape. Each custom profile extends `ask` by default, or the profile named by `metadata.extends`, and can override detailed action types through rules whose metadata includes `action_type`.

## SDK Integration

Guardian implements `sdk.Guardian` with `Decide`, `Resolve`, and `Snapshot`. The extension publishes and listens on the SDK Guardian bus topics:

- `guardian.registered`: publishes the `sdk.Guardian` implementation.
- `guardian.decision`: publishes each completed `sdk.GuardianDecision`.
- `guardian.approval.request`: publishes `sdk.GuardianApprovalRequest` for ask decisions.
- `guardian.approval.resolution`: accepts and publishes `sdk.GuardianApprovalResolution`.
- `guardian.snapshot.request`: requests a current snapshot.
- `guardian.snapshot`: publishes `sdk.GuardianSnapshot`.
- `guardian.grants.clear`: accepts `sdk.GuardianClearGrantsRequest`, or `nil` to clear all grants.

## Action Classification

Guardian classifies SDK requests into action types such as:

- Files: `file.read`, `file.write`, `file.delete`, `file.write_protected`
- Git: `git.read`, `git.write`, `git.discard`, `git.remote_write`, `git.history_rewrite`
- Commands: `command.read`, `command.write`, `command.exec_local`, `command.exec_remote`, `command.obfuscated`, `command.dangerous_delete`
- Network: `network.read`, `network.write`
- Packages: `package.test`, `package.build`, `package.install`, `package.global_install`, `package.script`
- Secrets and policy: `secret.read`, `secret.exfiltrate`, `policy.read`, `policy.write`
- System and fallback: `system.process_signal`, `system.service_change`, `unknown`

Shell commands are tokenized with quote-aware parsing, shell wrappers such as `bash -c` are unwrapped, and compound commands are decomposed so Guardian can aggregate the riskiest stage. The aggregate order is `block > ask > allow`.

## Approvals and Grants

Ask decisions publish ID-based approval requests. Resolutions can allow or deny once, for the current session, or for the active profile. Session and profile grants match future requests by normalized action type.

In headless mode, ask decisions are blocked immediately without publishing an approval request. Outside headless mode, ask decisions wait up to `approval_timeout`; timeout or context cancellation blocks the action.

Guardian records recent decisions with action type, verdict, reason, evidence, rule ID, and timestamp. `RecentDecisions()` returns the last 100 records; this audit history is separate from SDK snapshots. Snapshots include the active profile, resolved profiles, pending approvals, and current grants. Clear-grants events can remove all grants or selected grant scopes and IDs.
