package guardian

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/weave-agent/weave/sdk"
)

const (
	extensionName = "guardian"

	defaultProfile         = "ask"
	defaultApprovalTimeout = 2 * time.Minute

	actionTypeMetadataKey = "action_type"
	profileMetadataKey    = "profile"
)

// Config holds guardian extension settings.
type Config struct {
	Profile         string                   `json:"profile" default:"ask" env:"PROFILE" description:"Active guardian policy profile"`
	ApprovalTimeout string                   `json:"approval_timeout,omitempty" default:"2m" description:"How long to wait for ask-mode approval before denying"`
	Profiles        map[string]ProfileConfig `json:"profiles,omitempty" description:"Custom guardian policy profiles"`
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
	cfg             Config
	bus             sdk.Bus
	profiles        map[string]policyProfile
	headless        bool
	approvalTimeout time.Duration

	mu      sync.Mutex
	pending map[string]*pendingApproval
	grants  []sdk.GuardianGrant
	nextID  uint64
}

func init() {
	sdk.RegisterExtensionWithScope[Config](extensionName, extensionName, func(sdkCfg sdk.Config, _ sdk.PreferenceReader, cfg Config) (sdk.Extension, error) {
		return newGuardian(cfg, sdkCfg.IsHeadless()), nil
	})
}

// New creates a Guardian extension with normalized config defaults.
func New(cfg Config) *Guardian {
	return newGuardian(cfg, false)
}

func newGuardian(cfg Config, headless bool) *Guardian {
	if cfg.Profile == "" {
		cfg.Profile = defaultProfile
	}

	profiles := resolveProfiles(cfg.Profiles)
	if _, ok := profiles[cfg.Profile]; !ok {
		cfg.Profile = defaultProfile
	}

	return &Guardian{
		cfg:             cfg,
		profiles:        profiles,
		headless:        headless,
		approvalTimeout: approvalTimeout(cfg.ApprovalTimeout),
		pending:         make(map[string]*pendingApproval),
	}
}

func (g *Guardian) Name() string { return extensionName }

func (g *Guardian) Subscribe(bus sdk.Bus) error {
	g.bus = bus
	bus.On(sdk.GuardianApprovalResolutionTopic, func(ev sdk.Event) error {
		payload, ok := ev.Payload.(sdk.GuardianApprovalResolution)
		if !ok {
			return nil
		}
		g.resolve(payload.DecisionID, payload.Resolution, false)
		return nil
	})
	bus.Publish(sdk.NewEvent(sdk.GuardianRegisteredTopic, g))

	return nil
}

func (g *Guardian) Close() error { return nil }

func (g *Guardian) Decide(ctx context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
	decision := g.policyDecision(req)
	if decision.Action != sdk.GuardianDecisionAsk {
		g.publishDecision(decision)
		return decision, nil
	}

	if grant, ok := g.matchingGrant(req, decision); ok {
		decision.Action = sdk.GuardianDecisionAllow
		decision.Reason = fmt.Sprintf("allowed by %s grant", grant.Scope)
		decision.MatchedGrantID = grant.ID
		decision.Approval = nil
		g.publishDecision(decision)
		return decision, nil
	}

	if g.headless {
		decision.Action = sdk.GuardianDecisionBlock
		decision.Reason = "action requires approval in headless mode"
		g.publishDecision(decision)
		return decision, nil
	}

	if decision.ID == "" {
		decision.ID = g.nextIdentifier("decision")
		decision.RequestID = decision.ID
	}
	approval := g.newApproval(req, decision)
	decision.Approval = &approval
	if g.bus == nil {
		return decision, nil
	}

	pending := &pendingApproval{approval: approval, result: make(chan sdk.GuardianResolution, 1)}
	g.mu.Lock()
	g.pending[decision.ID] = pending
	g.mu.Unlock()
	g.bus.Publish(sdk.NewEvent(sdk.GuardianApprovalRequestTopic, sdk.GuardianApprovalRequest{Approval: approval}))

	resolution, ok := g.waitForResolution(ctx, pending)
	g.mu.Lock()
	delete(g.pending, decision.ID)
	g.mu.Unlock()
	if !ok {
		decision.Action = sdk.GuardianDecisionBlock
		decision.Reason = "approval timed out"
		decision.Approval = nil
		g.publishDecision(decision)
		return decision, nil
	}

	if resolution.Action == sdk.GuardianResolutionAllow {
		decision.Action = sdk.GuardianDecisionAllow
		decision.Reason = resolutionReason(resolution, "approved")
		g.applyGrant(approval, resolution)
	} else {
		decision.Action = sdk.GuardianDecisionBlock
		decision.Reason = resolutionReason(resolution, "denied")
	}
	decision.Approval = nil
	g.publishDecision(decision)
	return decision, nil
}

func (g *Guardian) Resolve(_ context.Context, decisionID string, resolution sdk.GuardianResolution) error {
	g.resolve(decisionID, resolution, true)
	return nil
}

func (g *Guardian) resolve(decisionID string, resolution sdk.GuardianResolution, publish bool) {
	g.mu.Lock()
	pending := g.pending[decisionID]
	g.mu.Unlock()
	if pending == nil {
		return
	}

	select {
	case pending.result <- resolution:
	default:
	}
	if publish && g.bus != nil {
		g.bus.Publish(sdk.NewEvent(sdk.GuardianApprovalResolutionTopic, sdk.GuardianApprovalResolution{
			ApprovalID: pending.approval.ID,
			DecisionID: decisionID,
			Resolution: resolution,
		}))
	}
}

func (g *Guardian) Snapshot(context.Context) (sdk.GuardianSnapshot, error) {
	g.mu.Lock()
	grants := append([]sdk.GuardianGrant(nil), g.grants...)
	pending := make([]sdk.GuardianApproval, 0, len(g.pending))
	for _, approval := range g.pending {
		pending = append(pending, approval.approval)
	}
	g.mu.Unlock()

	return sdk.GuardianSnapshot{
		CurrentProfile: g.cfg.Profile,
		Profiles:       sdkProfiles(g.profiles),
		Grants:         grants,
		Pending:        pending,
	}, nil
}

type pendingApproval struct {
	approval sdk.GuardianApproval
	result   chan sdk.GuardianResolution
}

func (g *Guardian) policyDecision(req sdk.GuardianRequest) sdk.GuardianDecision {
	actionTypes := requestActionTypes(req)
	profileName := g.cfg.Profile
	profile := g.profiles[profileName]

	actionType := ""
	rule := policyRule{
		decision: sdk.GuardianDecisionAllow,
		reason:   "all stages allowed",
	}
	for _, candidateType := range actionTypes {
		candidateRule, ok := profile.rules[candidateType]
		if !ok {
			candidateRule = policyRule{
				decision: sdk.GuardianDecisionBlock,
				reason:   fmt.Sprintf("%s has no policy rule in profile %s", candidateType, profile.name),
			}
		}
		if shouldUseDecision(candidateType, candidateRule, actionType, rule) {
			actionType = candidateType
			rule = candidateRule
		}
	}

	return sdk.GuardianDecision{
		ID:        req.ID,
		RequestID: req.ID,
		Action:    rule.decision,
		Reason:    rule.reason,
		Profile:   profileName,
		Metadata: map[string]any{
			actionTypeMetadataKey: actionType,
		},
	}
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
	actionTypes := requestActionTypes(req)
	if len(actionTypes) == 0 {
		return actionUnknown
	}
	return actionTypes[0]
}

func approvalTimeout(raw string) time.Duration {
	if raw == "" {
		return defaultApprovalTimeout
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout < 0 {
		return defaultApprovalTimeout
	}
	return timeout
}

func (g *Guardian) publishDecision(decision sdk.GuardianDecision) {
	if g.bus != nil {
		g.bus.Publish(sdk.NewEvent(sdk.GuardianDecisionTopic, decision))
	}
}

func (g *Guardian) newApproval(req sdk.GuardianRequest, decision sdk.GuardianDecision) sdk.GuardianApproval {
	decisionID := decision.ID
	if decisionID == "" {
		decisionID = g.nextIdentifier("decision")
	}
	approvalID := "approval-" + decisionID

	return sdk.GuardianApproval{
		ID:            approvalID,
		DecisionID:    decisionID,
		Request:       req,
		AllowedScopes: []sdk.GuardianGrantScope{sdk.GuardianGrantScopeOnce, sdk.GuardianGrantScopeSession, sdk.GuardianGrantScopeProfile},
		Reason:        decision.Reason,
	}
}

func (g *Guardian) nextIdentifier(prefix string) string {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.nextID++
	return fmt.Sprintf("%s-%d", prefix, g.nextID)
}

func (g *Guardian) waitForResolution(ctx context.Context, pending *pendingApproval) (sdk.GuardianResolution, bool) {
	var timeout <-chan time.Time
	if g.approvalTimeout > 0 {
		timer := time.NewTimer(g.approvalTimeout)
		defer timer.Stop()
		timeout = timer.C
	}

	select {
	case resolution := <-pending.result:
		return resolution, true
	case <-ctx.Done():
		return sdk.GuardianResolution{}, false
	case <-timeout:
		return sdk.GuardianResolution{}, false
	}
}

func (g *Guardian) matchingGrant(req sdk.GuardianRequest, decision sdk.GuardianDecision) (sdk.GuardianGrant, bool) {
	actionType, _ := decision.Metadata[actionTypeMetadataKey].(string)
	if actionType == "" {
		return sdk.GuardianGrant{}, false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for _, grant := range g.grants {
		if grant.Resolution.Action != sdk.GuardianResolutionAllow {
			continue
		}
		if grant.Scope != sdk.GuardianGrantScopeSession && grant.Scope != sdk.GuardianGrantScopeProfile {
			continue
		}
		if grant.Scope == sdk.GuardianGrantScopeProfile {
			if grantProfile, _ := grant.Request.Metadata[profileMetadataKey].(string); grantProfile != decision.Profile {
				continue
			}
		}
		if requestActionType(grant.Request) == actionType {
			return grant, true
		}
	}
	return sdk.GuardianGrant{}, false
}

func (g *Guardian) applyGrant(approval sdk.GuardianApproval, resolution sdk.GuardianResolution) {
	scope := resolution.Scope
	if scope == "" {
		scope = sdk.GuardianGrantScopeOnce
	}
	if scope == sdk.GuardianGrantScopeOnce {
		return
	}

	request := approval.Request
	if request.Metadata == nil {
		request.Metadata = make(map[string]any)
	}
	request.Metadata[actionTypeMetadataKey] = requestActionType(approval.Request)
	request.Metadata[profileMetadataKey] = g.cfg.Profile

	grant := sdk.GuardianGrant{
		ID:         g.nextIdentifier("grant"),
		Scope:      scope,
		Request:    request,
		Resolution: resolution,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}

	g.mu.Lock()
	g.grants = append(g.grants, grant)
	g.mu.Unlock()
}

func resolutionReason(resolution sdk.GuardianResolution, fallback string) string {
	if resolution.Reason != "" {
		return resolution.Reason
	}
	return fallback
}

func requestActionTypes(req sdk.GuardianRequest) []string {
	if req.Metadata != nil {
		if raw, ok := req.Metadata[actionTypeMetadataKey]; ok {
			if actionType, ok := raw.(string); ok && actionType != "" {
				return []string{actionType}
			}
		}
	}

	if req.Action == sdk.GuardianActionExec {
		return classifyExecCommandActions(req.Command)
	}

	return []string{classifyRequest(req)}
}

func shouldUseDecision(candidateType string, candidateRule policyRule, currentType string, currentRule policyRule) bool {
	if currentType == "" {
		return true
	}
	candidateRank := decisionRank(candidateRule.decision)
	currentRank := decisionRank(currentRule.decision)
	if candidateRank != currentRank {
		return candidateRank > currentRank
	}
	return commandActionRank(candidateType) > commandActionRank(currentType)
}

func decisionRank(decision sdk.GuardianDecisionAction) int {
	switch decision {
	case sdk.GuardianDecisionBlock:
		return 3
	case sdk.GuardianDecisionAsk:
		return 2
	case sdk.GuardianDecisionAllow:
		return 1
	default:
		return 0
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
