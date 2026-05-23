package guardian

import (
	"context"
	"fmt"

	"github.com/weave-agent/weave/sdk"
)

const (
	extensionName = "guardian"

	defaultProfile = "ask"

	actionTypeMetadataKey = "action_type"
)

// Config holds guardian extension settings.
type Config struct {
	Profile  string                   `json:"profile" default:"ask" env:"PROFILE" description:"Active guardian policy profile"`
	Profiles map[string]ProfileConfig `json:"profiles,omitempty" description:"Custom guardian policy profiles"`
}

// ProfileConfig defines a user profile by extending a built-in or custom
// profile and replacing selected action decisions.
type ProfileConfig struct {
	Extends string            `json:"extends,omitempty"`
	Actions map[string]string `json:"actions,omitempty"`
}

type policyProfile struct {
	name        string
	description string
	rules       map[string]policyRule
}

type policyRule struct {
	decision sdk.GuardianDecisionAction
	reason   string
}

// Guardian owns action classification, policy decisions, approvals, grants, and
// snapshots.
type Guardian struct {
	cfg      Config
	bus      sdk.Bus
	profiles map[string]policyProfile
}

func init() {
	sdk.RegisterExtensionWithScope[Config](extensionName, extensionName, func(_ sdk.Config, _ sdk.PreferenceReader, cfg Config) (sdk.Extension, error) {
		return New(cfg), nil
	})
}

// New creates a Guardian extension with normalized config defaults.
func New(cfg Config) *Guardian {
	if cfg.Profile == "" {
		cfg.Profile = defaultProfile
	}

	profiles := resolveProfiles(cfg.Profiles)
	if _, ok := profiles[cfg.Profile]; !ok {
		cfg.Profile = defaultProfile
	}

	return &Guardian{cfg: cfg, profiles: profiles}
}

func (g *Guardian) Name() string { return extensionName }

func (g *Guardian) Subscribe(bus sdk.Bus) error {
	g.bus = bus
	bus.Publish(sdk.NewEvent(sdk.GuardianRegisteredTopic, g))

	return nil
}

func (g *Guardian) Close() error { return nil }

func (g *Guardian) Decide(_ context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
	actionType := requestActionType(req)
	profile := g.profiles[g.cfg.Profile]
	rule, ok := profile.rules[actionType]
	if !ok {
		rule = policyRule{
			decision: sdk.GuardianDecisionBlock,
			reason:   fmt.Sprintf("%s has no policy rule in profile %s", actionType, profile.name),
		}
	}

	return sdk.GuardianDecision{
		ID:        req.ID,
		RequestID: req.ID,
		Action:    rule.decision,
		Reason:    rule.reason,
		Profile:   profile.name,
		Metadata: map[string]any{
			actionTypeMetadataKey: actionType,
		},
	}, nil
}

func (g *Guardian) Resolve(context.Context, string, sdk.GuardianResolution) error {
	return nil
}

func (g *Guardian) Snapshot(context.Context) (sdk.GuardianSnapshot, error) {
	return sdk.GuardianSnapshot{
		CurrentProfile: g.cfg.Profile,
		Profiles:       sdkProfiles(g.profiles),
	}, nil
}

func resolveProfiles(custom map[string]ProfileConfig) map[string]policyProfile {
	profiles := builtInProfiles()

	for name := range custom {
		resolveCustomProfile(name, custom, profiles, make(map[string]bool))
	}

	return profiles
}

func resolveCustomProfile(name string, custom map[string]ProfileConfig, profiles map[string]policyProfile, resolving map[string]bool) policyProfile {
	if profile, ok := profiles[name]; ok {
		return profile
	}
	if resolving[name] {
		return profiles[defaultProfile]
	}

	resolving[name] = true
	cfg := custom[name]
	baseName := cfg.Extends
	if baseName == "" {
		baseName = defaultProfile
	}

	base, ok := profiles[baseName]
	if !ok {
		if _, customBase := custom[baseName]; customBase {
			base = resolveCustomProfile(baseName, custom, profiles, resolving)
		} else {
			base = profiles[defaultProfile]
		}
	}

	rules := copyRules(base.rules)
	for actionType, decision := range cfg.Actions {
		rules[actionType] = policyRule{
			decision: normalizeDecision(decision),
			reason:   fmt.Sprintf("custom profile %s overrides %s", name, actionType),
		}
	}

	profile := policyProfile{
		name:        name,
		description: fmt.Sprintf("Custom profile extending %s", base.name),
		rules:       rules,
	}
	profiles[name] = profile
	resolving[name] = false

	return profile
}

func builtInProfiles() map[string]policyProfile {
	hardBlocks := map[string]string{
		"command.exec_remote":      "remote code execution is blocked",
		"command.obfuscated":       "obfuscated command payloads are blocked",
		"command.dangerous_delete": "dangerous delete operations are blocked",
		"file.write_protected":     "protected path writes are blocked",
		"policy.write":             "policy tampering is blocked",
		"secret.exfiltrate":        "secret exfiltration is blocked",
	}

	askRules := map[string]policyRule{
		"file.read":              allowRule("project file reads are allowed"),
		"git.read":               allowRule("git read operations are allowed"),
		"command.read":           allowRule("read-only commands are allowed"),
		"package.test":           allowRule("test commands are allowed"),
		"package.build":          allowRule("build commands are allowed"),
		"policy.read":            allowRule("policy reads are allowed"),
		"file.write":             askRule("file writes require approval"),
		"file.delete":            askRule("file deletes require approval"),
		"git.write":              askRule("git write operations require approval"),
		"git.discard":            askRule("git discard operations require approval"),
		"git.remote_write":       askRule("git remote writes require approval"),
		"git.history_rewrite":    askRule("git history rewrites require approval"),
		"command.write":          askRule("write commands require approval"),
		"command.exec_local":     askRule("local command execution requires approval"),
		"network.read":           askRule("network reads require approval"),
		"network.write":          askRule("network writes require approval"),
		"package.install":        askRule("package installs require approval"),
		"package.global_install": askRule("global package installs require approval"),
		"package.script":         askRule("package scripts require approval"),
		"secret.read":            askRule("secret reads require approval"),
		"system.process_signal":  askRule("process signal operations require approval"),
		"system.service_change":  askRule("service changes require approval"),
		"unknown":                askRule("unknown actions require approval"),
	}
	for actionType, reason := range hardBlocks {
		askRules[actionType] = blockRule(reason)
	}

	autoRules := copyRules(askRules)
	for _, actionType := range []string{
		"file.write",
		"git.write",
		"command.write",
		"command.exec_local",
		"network.read",
		"package.install",
		"package.script",
	} {
		autoRules[actionType] = allowRule(fmt.Sprintf("%s is allowed by auto profile", actionType))
	}

	yoloRules := make(map[string]policyRule, len(askRules))
	for actionType := range askRules {
		yoloRules[actionType] = allowRule(fmt.Sprintf("%s is allowed by yolo profile", actionType))
	}
	yoloRules["unknown"] = allowRule("unknown actions are allowed by yolo profile")
	for actionType, reason := range hardBlocks {
		yoloRules[actionType] = blockRule(reason)
	}

	return map[string]policyProfile{
		"ask": {
			name:        "ask",
			description: "Conservative profile that asks before mutating or risky actions",
			rules:       askRules,
		},
		"auto": {
			name:        "auto",
			description: "Productive profile that allows routine development actions and asks for risky actions",
			rules:       autoRules,
		},
		"yolo": {
			name:        "yolo",
			description: "Permissive profile that still enforces hard blocks",
			rules:       yoloRules,
		},
	}
}

func requestActionType(req sdk.GuardianRequest) string {
	if req.Metadata != nil {
		if raw, ok := req.Metadata[actionTypeMetadataKey]; ok {
			if actionType, ok := raw.(string); ok && actionType != "" {
				return actionType
			}
		}
	}

	switch req.Action {
	case sdk.GuardianActionRead:
		return "file.read"
	case sdk.GuardianActionWrite:
		return "file.write"
	case sdk.GuardianActionDelete:
		return "file.delete"
	case sdk.GuardianActionExec:
		return "command.exec_local"
	case sdk.GuardianActionNetwork:
		return "network.read"
	default:
		return "unknown"
	}
}

func normalizeDecision(decision string) sdk.GuardianDecisionAction {
	switch sdk.GuardianDecisionAction(decision) {
	case sdk.GuardianDecisionAllow, sdk.GuardianDecisionAsk, sdk.GuardianDecisionBlock:
		return sdk.GuardianDecisionAction(decision)
	default:
		return sdk.GuardianDecisionBlock
	}
}

func allowRule(reason string) policyRule {
	return policyRule{decision: sdk.GuardianDecisionAllow, reason: reason}
}

func askRule(reason string) policyRule {
	return policyRule{decision: sdk.GuardianDecisionAsk, reason: reason}
}

func blockRule(reason string) policyRule {
	return policyRule{decision: sdk.GuardianDecisionBlock, reason: reason}
}

func copyRules(in map[string]policyRule) map[string]policyRule {
	out := make(map[string]policyRule, len(in))
	for actionType, rule := range in {
		out[actionType] = rule
	}
	return out
}

func sdkProfiles(profiles map[string]policyProfile) map[string]sdk.GuardianProfile {
	out := make(map[string]sdk.GuardianProfile, len(profiles))
	for name, profile := range profiles {
		rules := make([]sdk.GuardianProfileRule, 0, len(profile.rules))
		for actionType, rule := range profile.rules {
			rules = append(rules, sdk.GuardianProfileRule{
				Decision: rule.decision,
				Reason:   rule.reason,
				Metadata: map[string]any{
					actionTypeMetadataKey: actionType,
				},
			})
		}
		out[name] = sdk.GuardianProfile{
			Name:        profile.name,
			Description: profile.description,
			Rules:       rules,
		}
	}
	return out
}
