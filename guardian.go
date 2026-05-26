package guardian

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/weave-agent/weave/sdk"
)

const (
	extensionName = "guardian"

	defaultProfile         = "ask"
	autoProfile            = "auto"
	yoloProfile            = "yolo"
	defaultApprovalTimeout = 2 * time.Minute
	defaultDecisionLimit   = 100

	actionTypeMetadataKey = "action_type"
	profileMetadataKey    = "profile"
	stageActionTypesKey   = "stage_action_types"
	compositionActionKey  = "composition_action_type"

	grantConstraintsVersionKey = "grant_constraints_version"
	grantConstraintsVersion    = "v1"
	grantActionTypeKey         = "grant_action_type"
	grantProfileKey            = "grant_profile"
	grantWorkingDirKey         = "grant_working_dir"
	grantPathPrefixKey         = "grant_path_prefix"
	grantPathExactKey          = "grant_path_exact"
	grantCommandFamilyKey      = "grant_command_family"
	grantNetworkHostKey        = "grant_network_host"
)

// Config holds guardian extension settings.
type Config struct {
	Profile         string                         `json:"profile" default:"ask" env:"PROFILE" description:"Active guardian policy profile"`
	AskFallback     bool                           `json:"ask_fallback,omitempty" env:"ASK_FALLBACK" description:"Ask instead of blocking when no guardian policy matches"`
	ApprovalTimeout string                         `json:"approval_timeout,omitempty" default:"2m" description:"How long to wait for ask-mode approval before denying"`
	Profiles        map[string]sdk.GuardianProfile `json:"profiles,omitempty" description:"Custom guardian policy profiles"`
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
	history []DecisionRecord
	nextID  uint64
}

// DecisionRecord is the bounded audit trail Guardian keeps for recent
// decisions.
type DecisionRecord struct {
	DecisionID string
	RequestID  string
	ActionType string
	Verdict    sdk.GuardianDecisionAction
	Reason     string
	Evidence   map[string]any
	RuleID     string
	Timestamp  string
}

func init() { //nolint:gochecknoinits // SDK extensions register themselves during package initialization.
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
	bus.On(sdk.GuardianProfileChangeTopic, func(ev sdk.Event) error {
		payload, ok := ev.Payload.(sdk.GuardianProfileChange)
		if !ok {
			return nil
		}
		g.changeProfile(payload.CurrentProfile)
		return nil
	})
	bus.On(sdk.GuardianSnapshotRequestTopic, func(sdk.Event) error {
		snapshot, err := g.Snapshot(context.Background())
		if err != nil {
			return err
		}
		bus.Publish(sdk.NewEvent(sdk.GuardianSnapshotTopic, snapshot))
		return nil
	})
	bus.On(sdk.GuardianClearGrantsTopic, func(ev sdk.Event) error {
		g.clearGrants(ev.Payload)
		return nil
	})
	bus.Publish(sdk.NewEvent(sdk.GuardianRegisteredTopic, g))

	return nil
}

func (g *Guardian) Close() error { return nil }

func (g *Guardian) Decide(ctx context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
	decision := g.policyDecision(req)
	if decision.Action != sdk.GuardianDecisionAsk {
		g.recordAndPublishDecision(req, decision)
		return decision, nil
	}

	if grant, ok := g.matchingGrant(req, decision); ok {
		decision.Action = sdk.GuardianDecisionAllow
		decision.Reason = fmt.Sprintf("allowed by %s grant", grant.Scope)
		decision.MatchedGrantID = grant.ID
		decision.Approval = nil
		g.recordAndPublishDecision(req, decision)
		return decision, nil
	}

	if g.headless || g.bus == nil {
		decision.Action = sdk.GuardianDecisionBlock
		if g.headless {
			decision.Reason = "action requires approval in headless mode"
		} else {
			decision.Reason = "approval unavailable"
		}
		g.recordAndPublishDecision(req, decision)
		return decision, nil
	}

	if decision.ID == "" {
		decision.ID = g.nextIdentifier("decision")
		decision.RequestID = decision.ID
	}
	approval := g.newApproval(req, decision)
	decision.Approval = &approval

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
		g.recordAndPublishDecision(req, decision)
		return decision, nil
	}

	if resolution.Action == sdk.GuardianResolutionAllow {
		decision.Action = sdk.GuardianDecisionAllow
		decision.Reason = resolutionReason(resolution, "approved")
		g.applyGrant(approval, decision, resolution)
	} else {
		decision.Action = sdk.GuardianDecisionBlock
		decision.Reason = resolutionReason(resolution, "denied")
	}
	decision.Approval = nil
	g.recordAndPublishDecision(req, decision)
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
	currentProfile := g.cfg.Profile
	grants := make([]sdk.GuardianGrant, 0, len(g.grants))
	for _, grant := range g.grants {
		grants = append(grants, cloneGuardianGrant(grant))
	}
	pending := make([]sdk.GuardianApproval, 0, len(g.pending))
	for _, approval := range g.pending {
		pending = append(pending, cloneGuardianApproval(approval.approval))
	}
	profiles := cloneSDKProfiles(sdkProfiles(g.profiles))
	g.mu.Unlock()

	return sdk.GuardianSnapshot{
		CurrentProfile: currentProfile,
		Profiles:       profiles,
		Grants:         grants,
		Pending:        pending,
	}, nil
}

func (g *Guardian) changeProfile(profile string) {
	if profile == "" {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.profiles[profile]; !ok {
		return
	}

	g.cfg.Profile = profile
}

func (g *Guardian) RecentDecisions() []DecisionRecord {
	g.mu.Lock()
	defer g.mu.Unlock()

	return append([]DecisionRecord(nil), g.history...)
}

type pendingApproval struct {
	approval sdk.GuardianApproval
	result   chan sdk.GuardianResolution
}

func (g *Guardian) policyDecision(req sdk.GuardianRequest) sdk.GuardianDecision {
	classification := requestActionClassification(req)
	return g.policyDecisionForActionTypesWithClassification(req, classification.ActionTypes, classification)
}

func (g *Guardian) policyDecisionForActionTypes(req sdk.GuardianRequest, actionTypes []string) sdk.GuardianDecision {
	return g.policyDecisionForActionTypesWithClassification(req, actionTypes, execClassification{})
}

func (g *Guardian) policyDecisionForActionTypesWithClassification(req sdk.GuardianRequest, actionTypes []string, classification execClassification) sdk.GuardianDecision {
	g.mu.Lock()
	profileName := g.cfg.Profile
	profile := g.profiles[profileName]
	g.mu.Unlock()

	actionType := ""
	rule := policyRule{
		decision: sdk.GuardianDecisionAllow,
		reason:   "all stages allowed",
	}
	for _, candidateType := range actionTypes {
		candidateRule, ok := profile.rules[candidateType]
		if hardRule, hard := profileHardBlockRule(profileName, candidateType); hard {
			candidateRule = hardRule
			ok = true
		}
		if !ok {
			decision := sdk.GuardianDecisionBlock
			if g.cfg.AskFallback {
				decision = sdk.GuardianDecisionAsk
			}
			candidateRule = policyRule{
				decision: decision,
				reason:   fmt.Sprintf("%s has no policy rule in profile %s", candidateType, profile.name),
			}
		}
		if shouldUseDecision(candidateType, candidateRule, actionType, rule) {
			actionType = candidateType
			rule = candidateRule
		}
	}

	metadata := map[string]any{
		actionTypeMetadataKey: actionType,
	}
	if req.Action == sdk.GuardianActionExec {
		if len(classification.StageActionTypes) > 0 {
			metadata[stageActionTypesKey] = append([]string(nil), classification.StageActionTypes...)
		}
		if classification.CompositionActionType != "" {
			metadata[compositionActionKey] = classification.CompositionActionType
		}
	}

	return sdk.GuardianDecision{
		ID:        req.ID,
		RequestID: req.ID,
		Action:    rule.decision,
		Reason:    rule.reason,
		Profile:   profileName,
		Metadata:  metadata,
	}
}

func resolveProfiles(custom map[string]sdk.GuardianProfile) map[string]policyProfile {
	profiles := builtInProfiles()

	for name := range custom {
		resolveCustomProfile(name, custom, profiles, make(map[string]bool))
	}

	return profiles
}

func resolveCustomProfile(name string, custom map[string]sdk.GuardianProfile, profiles map[string]policyProfile, resolving map[string]bool) policyProfile {
	if profile, ok := profiles[name]; ok {
		return profile
	}
	if resolving[name] {
		return profiles[defaultProfile]
	}

	resolving[name] = true
	cfg := custom[name]
	baseName := profileExtends(cfg)
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
	for _, override := range cfg.Rules {
		actionTypes := profileRuleActionTypes(override)
		if len(actionTypes) == 0 {
			continue
		}
		decision := override.Decision
		reason := override.Reason
		if reason == "" {
			reason = fmt.Sprintf("custom profile %s overrides action", name)
		}
		for _, actionType := range actionTypes {
			if _, hard := hardBlockRule(actionType); hard {
				continue
			}
			rules[actionType] = policyRule{
				decision: normalizeDecision(decision),
				reason:   reason,
			}
		}
	}

	for actionType, decision := range legacyProfileActions(cfg) {
		if _, hard := hardBlockRule(actionType); hard {
			continue
		}
		rules[actionType] = policyRule{
			decision: normalizeDecision(sdk.GuardianDecisionAction(decision)),
			reason:   fmt.Sprintf("custom profile %s overrides %s", name, actionType),
		}
	}

	profile := policyProfile{
		name:        name,
		description: "Custom profile extending " + base.name,
		rules:       rules,
	}
	profiles[name] = profile
	resolving[name] = false

	return profile
}

func profileExtends(profile sdk.GuardianProfile) string {
	if profile.Metadata == nil {
		return ""
	}
	extends, _ := profile.Metadata["extends"].(string)
	return extends
}

func profileRuleActionTypes(rule sdk.GuardianProfileRule) []string {
	types := make([]string, 0, len(rule.Actions)+1)
	if rule.Metadata != nil {
		if actionType, ok := metadataActionType(rule.Metadata); ok {
			types = append(types, actionType)
		}
	}
	for _, action := range rule.Actions {
		switch action {
		case sdk.GuardianActionRead:
			types = append(types, actionFileRead, actionPolicyRead, actionSecretRead, actionGitRead, actionCommandRead)
		case sdk.GuardianActionWrite:
			types = append(types, actionFileWrite, actionFileProtected, actionPolicyWrite, actionGitWrite, actionGitDiscard,
				actionGitRemoteWrite, actionGitHistoryRewrite, actionCommandWrite, actionPackageInstall, actionPackageGlobal,
				actionPackageScript, actionSystemSignal, actionSystemService)
		case sdk.GuardianActionDelete:
			types = append(types, actionFileDelete, actionGitDiscard, actionCommandDangerousDelete)
		case sdk.GuardianActionExec:
			types = append(types, actionCommandRead, actionCommandWrite, actionCommandExecLocal, actionCommandExecRemote,
				actionCommandObfuscated, actionCommandDangerousDelete, actionGitRead, actionGitWrite, actionGitDiscard,
				actionGitRemoteWrite, actionGitHistoryRewrite, actionNetworkRead, actionNetworkWrite, actionPackageTest,
				actionPackageBuild, actionPackageInstall, actionPackageGlobal, actionPackageScript, actionSystemSignal,
				actionSystemService, actionSecretRead, actionSecretExfiltrate, actionPolicyWrite, actionFileProtected)
		case sdk.GuardianActionNetwork:
			types = append(types, actionNetworkRead, actionNetworkWrite)
		case sdk.GuardianActionUnknown:
			types = append(types, actionUnknown)
		}
	}
	return types
}

func legacyProfileActions(profile sdk.GuardianProfile) map[string]string {
	if profile.Metadata == nil {
		return nil
	}
	raw, ok := profile.Metadata["actions"]
	if !ok {
		return nil
	}
	actions, _ := raw.(map[string]string)
	return actions
}

func builtInProfiles() map[string]policyProfile {
	hardBlocks := hardBlockReasons()

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
		if canApproveHardCommand(actionType) {
			askRules[actionType] = askRule(hardCommandApprovalReason(actionType, reason))
			continue
		}
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
		autoRules[actionType] = allowRule(actionType + " is allowed by auto profile")
	}

	yoloRules := make(map[string]policyRule, len(askRules))
	for actionType := range askRules {
		yoloRules[actionType] = allowRule(actionType + " is allowed by yolo profile")
	}
	yoloRules["unknown"] = allowRule("unknown actions are allowed by yolo profile")
	for actionType, reason := range hardBlocks {
		yoloRules[actionType] = allowRule(reason)
	}

	return map[string]policyProfile{
		defaultProfile: {
			name:        defaultProfile,
			description: "Conservative profile that asks before mutating or risky actions",
			rules:       askRules,
		},
		autoProfile: {
			name:        autoProfile,
			description: "Productive profile that allows routine development actions and asks for risky actions",
			rules:       autoRules,
		},
		yoloProfile: {
			name:        yoloProfile,
			description: "Permissive profile that allows all actions",
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

func (g *Guardian) recordAndPublishDecision(req sdk.GuardianRequest, decision sdk.GuardianDecision) {
	g.recordDecision(req, decision)
	if g.bus != nil {
		g.bus.Publish(sdk.NewEvent(sdk.GuardianDecisionTopic, decision))
	}
}

func (g *Guardian) recordDecision(req sdk.GuardianRequest, decision sdk.GuardianDecision) {
	actionType, _ := decision.Metadata[actionTypeMetadataKey].(string)
	record := DecisionRecord{
		DecisionID: decision.ID,
		RequestID:  decision.RequestID,
		ActionType: actionType,
		Verdict:    decision.Action,
		Reason:     decision.Reason,
		Evidence:   decisionEvidence(req),
		RuleID:     decisionRuleID(decision.Profile, actionType),
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.history = append(g.history, record)
	if len(g.history) > defaultDecisionLimit {
		g.history = append([]DecisionRecord(nil), g.history[len(g.history)-defaultDecisionLimit:]...)
	}
}

func decisionEvidence(req sdk.GuardianRequest) map[string]any {
	evidence := map[string]any{}
	if req.ToolCallID != "" {
		evidence["tool_call_id"] = req.ToolCallID
	}
	if req.ToolName != "" {
		evidence["tool_name"] = req.ToolName
	}
	if req.Action != "" {
		evidence["action"] = req.Action
	}
	if req.Command != "" {
		evidence["command"] = req.Command
	}
	if req.Path != "" {
		evidence["path"] = req.Path
	}
	if req.WorkingDir != "" {
		evidence["working_dir"] = req.WorkingDir
	}
	if req.Description != "" {
		evidence["description"] = req.Description
	}
	return evidence
}

func decisionRuleID(profile, actionType string) string {
	if profile == "" || actionType == "" {
		return ""
	}
	return profile + ":" + actionType
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
	requestConstraints := grantConstraintsForRequest(req, decision, false)

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
			if grantProfile(grant.Request) != decision.Profile {
				continue
			}
		}
		if grantMatchesRequest(grant.Request, actionType, requestConstraints) {
			return grant, true
		}
	}
	return sdk.GuardianGrant{}, false
}

func (g *Guardian) applyGrant(approval sdk.GuardianApproval, decision sdk.GuardianDecision, resolution sdk.GuardianResolution) {
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
	request.Metadata[actionTypeMetadataKey] = decision.Metadata[actionTypeMetadataKey]
	g.mu.Lock()
	request.Metadata[profileMetadataKey] = g.cfg.Profile
	g.mu.Unlock()
	for key, value := range grantConstraintsForRequest(request, decision, true) {
		request.Metadata[key] = value
	}

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

func grantConstraintsForRequest(req sdk.GuardianRequest, decision sdk.GuardianDecision, persist bool) map[string]any {
	actionType, _ := decision.Metadata[actionTypeMetadataKey].(string)
	constraints := make(map[string]any)
	if persist {
		constraints[grantConstraintsVersionKey] = grantConstraintsVersion
		constraints[grantActionTypeKey] = actionType
		constraints[grantProfileKey] = decision.Profile
	}

	if req.WorkingDir != "" {
		constraints[grantWorkingDirKey] = normalizeGrantWorkingDir(req.WorkingDir)
	}

	switch req.Action {
	case sdk.GuardianActionRead, sdk.GuardianActionWrite, sdk.GuardianActionDelete:
		addFileGrantPathConstraint(constraints, actionType, req.Path, req.WorkingDir)
	case sdk.GuardianActionExec:
		addExecGrantConstraints(constraints, req, actionType)
	case sdk.GuardianActionNetwork:
		if host := requestNetworkHost(req); host != "" {
			constraints[grantNetworkHostKey] = host
		}
	}

	return constraints
}

func grantMatchesRequest(grantReq sdk.GuardianRequest, actionType string, requestConstraints map[string]any) bool {
	grantMetadata := grantReq.Metadata
	if grantActionType(grantReq) != actionType {
		return false
	}
	if metadataString(grantMetadata, grantConstraintsVersionKey) == "" {
		return true
	}
	if metadataString(grantMetadata, grantConstraintsVersionKey) != grantConstraintsVersion {
		return false
	}

	if !constraintStringMatches(grantMetadata, requestConstraints, grantWorkingDirKey) {
		return false
	}
	if !constraintStringMatches(grantMetadata, requestConstraints, grantCommandFamilyKey) {
		return false
	}
	if !constraintStringMatches(grantMetadata, requestConstraints, grantNetworkHostKey) {
		return false
	}
	if exact := metadataString(grantMetadata, grantPathExactKey); exact != "" && metadataString(requestConstraints, grantPathExactKey) != exact {
		return false
	}
	if prefix := metadataString(grantMetadata, grantPathPrefixKey); prefix != "" {
		requestPath := metadataString(requestConstraints, grantPathExactKey, grantPathPrefixKey)
		if !pathHasGrantPrefix(requestPath, prefix) {
			return false
		}
	}
	return true
}

func constraintStringMatches(grantMetadata, requestConstraints map[string]any, key string) bool {
	grantValue := metadataString(grantMetadata, key)
	if grantValue == "" {
		return true
	}
	return metadataString(requestConstraints, key) == grantValue
}

func addFileGrantPathConstraint(constraints map[string]any, actionType, rawPath, workingDir string) {
	if rawPath == "" {
		return
	}
	normalized := normalizeRequestPath(rawPath, workingDir).resolved
	if normalized == "" {
		return
	}
	switch actionType {
	case actionFileRead, actionFileWrite:
		constraints[grantPathPrefixKey] = filepath.Dir(normalized)
	case actionFileDelete, actionSecretRead:
		constraints[grantPathExactKey] = normalized
	}
}

func addExecGrantConstraints(constraints map[string]any, req sdk.GuardianRequest, actionType string) {
	stage, ok := selectedShellStage(req.Command, req.WorkingDir, actionType)
	if !ok {
		return
	}
	if len(stage.Tokens) > 0 {
		constraints[grantCommandFamilyKey] = normalizedCommandName(stage.Tokens[0])
	}
	if actionType == actionNetworkRead || actionType == actionNetworkWrite {
		if host := shellStageNetworkHost(stage); host != "" {
			constraints[grantNetworkHostKey] = host
		}
	}
	if path := shellStageConstraintPath(stage, req.WorkingDir, actionType); path != "" {
		switch actionType {
		case actionSecretRead, actionFileDelete:
			constraints[grantPathExactKey] = path
		default:
			constraints[grantPathPrefixKey] = filepath.Dir(path)
		}
	}
}

func selectedShellStage(command, workingDir, actionType string) (shellStage, bool) {
	parsed := decomposeShellCommand(command)
	if len(parsed.Issues) > 0 || len(parsed.Stages) == 0 {
		return shellStage{}, false
	}
	for _, stage := range parsed.Stages {
		if classifyShellStage(stage, workingDir) == actionType {
			return stage, true
		}
	}
	return shellStage{}, false
}

func shellStageConstraintPath(stage shellStage, workingDir, actionType string) string {
	for _, redirect := range stage.Redirects {
		if redirect.Target == "" {
			continue
		}
		if strings.Contains(redirect.Operator, "<") && (actionType == actionSecretRead || actionType == actionCommandRead) {
			return normalizeRequestPath(redirect.Target, workingDir).resolved
		}
		if strings.Contains(redirect.Operator, ">") {
			return normalizeRequestPath(redirect.Target, workingDir).resolved
		}
	}
	if len(stage.Tokens) == 0 {
		return ""
	}
	name := normalizedCommandName(stage.Tokens[0])
	args := stage.Tokens[1:]
	var paths []string
	switch name {
	case "rm", "rmdir", "unlink", "sed", "grep", "rg", "cat", "ls", "wc", "head", "tail", "stat", "source", ".":
		paths = shellPathArgs(args)
	case "mv", "cp", "mkdir", "touch", "tee", "dd", "truncate", "shred", "rsync":
		paths = shellWritePathArgs(name, args)
	case commandCurl, commandWget:
		for i := range args {
			output, ok := networkOutputTarget(name, strings.ToLower(args[i]), args, i)
			if ok && output != "" && !isStdoutTarget(output) {
				paths = []string{output}
				break
			}
		}
	}
	for _, path := range paths {
		if isShellFileArg(path) {
			return normalizeRequestPath(path, workingDir).resolved
		}
	}
	return ""
}

func shellStageNetworkHost(stage shellStage) string {
	for _, token := range stage.Tokens {
		if host := urlHost(token); host != "" {
			return host
		}
	}
	return ""
}

func requestNetworkHost(req sdk.GuardianRequest) string {
	for _, key := range []string{"host", "url", "uri", "endpoint", "target", "http.host"} {
		if host := urlHost(metadataString(req.Metadata, key)); host != "" {
			return host
		}
	}
	return ""
}

func urlHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err == nil && parsed.Hostname() != "" {
			return strings.ToLower(parsed.Hostname())
		}
		return ""
	}
	if strings.Contains(raw, ".") && strings.ContainsFunc(raw, func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	}) && !strings.ContainsAny(raw, "/\\") && !strings.HasPrefix(raw, ".") {
		host, _, ok := strings.Cut(raw, ":")
		if ok {
			raw = host
		}
		return strings.ToLower(raw)
	}
	return ""
}

func normalizeGrantWorkingDir(workingDir string) string {
	if workingDir == "" {
		return ""
	}
	return normalizeRequestPath(".", workingDir).resolved
}

func pathHasGrantPrefix(path, prefix string) bool {
	if path == "" || prefix == "" {
		return false
	}
	cleanPath := filepath.Clean(path)
	cleanPrefix := filepath.Clean(prefix)
	if cleanPath == cleanPrefix {
		return true
	}
	return strings.HasPrefix(cleanPath, strings.TrimRight(cleanPrefix, string(filepath.Separator))+string(filepath.Separator))
}

func (g *Guardian) clearGrants(payload any) {
	req, ok := payload.(sdk.GuardianClearGrantsRequest)
	if !ok {
		g.mu.Lock()
		g.grants = nil
		g.mu.Unlock()
		return
	}

	ids := make(map[string]bool, len(req.GrantIDs))
	for _, id := range req.GrantIDs {
		if id != "" {
			ids[id] = true
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if len(ids) == 0 && req.Scope == "" {
		g.grants = nil
		return
	}

	kept := g.grants[:0]
	for _, grant := range g.grants {
		if len(ids) > 0 && ids[grant.ID] {
			continue
		}
		if req.Scope != "" && string(grant.Scope) == req.Scope {
			continue
		}
		kept = append(kept, grant)
	}
	g.grants = kept
}

func resolutionReason(resolution sdk.GuardianResolution, fallback string) string {
	if resolution.Reason != "" {
		return resolution.Reason
	}
	return fallback
}

func requestActionTypes(req sdk.GuardianRequest) []string {
	return requestActionClassification(req).ActionTypes
}

func requestActionClassification(req sdk.GuardianRequest) execClassification {
	if req.Action == sdk.GuardianActionExec {
		return classifyExecCommandClassificationInWorkingDir(req.Command, req.WorkingDir)
	}

	actionType := classifyRequest(req)
	return execClassification{
		ActionTypes:      []string{actionType},
		StageActionTypes: []string{actionType},
	}
}

func metadataActionType(metadata map[string]any) (string, bool) {
	actionType := metadataString(metadata, actionTypeMetadataKey)
	return actionType, actionType != ""
}

func metadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		raw, ok := metadata[key]
		if !ok {
			continue
		}
		if value, ok := raw.(string); ok {
			return value
		}
	}
	return ""
}

func cloneGuardianGrant(grant sdk.GuardianGrant) sdk.GuardianGrant {
	grant.Request = cloneGuardianRequest(grant.Request)
	return grant
}

func cloneGuardianApproval(approval sdk.GuardianApproval) sdk.GuardianApproval {
	approval.Request = cloneGuardianRequest(approval.Request)
	approval.AllowedScopes = append([]sdk.GuardianGrantScope(nil), approval.AllowedScopes...)
	return approval
}

func cloneGuardianRequest(req sdk.GuardianRequest) sdk.GuardianRequest {
	req.Metadata = maps.Clone(req.Metadata)
	return req
}

func cloneSDKProfiles(profiles map[string]sdk.GuardianProfile) map[string]sdk.GuardianProfile {
	out := make(map[string]sdk.GuardianProfile, len(profiles))
	for name, profile := range profiles {
		profile.Metadata = maps.Clone(profile.Metadata)
		profile.Rules = append([]sdk.GuardianProfileRule(nil), profile.Rules...)
		for i := range profile.Rules {
			profile.Rules[i].Actions = append([]sdk.GuardianAction(nil), profile.Rules[i].Actions...)
			profile.Rules[i].Metadata = maps.Clone(profile.Rules[i].Metadata)
		}
		out[name] = profile
	}
	return out
}

func grantActionType(req sdk.GuardianRequest) string {
	if req.Metadata != nil {
		if raw, ok := req.Metadata[grantActionTypeKey]; ok {
			if actionType, ok := raw.(string); ok && actionType != "" {
				return actionType
			}
		}
		if raw, ok := req.Metadata[actionTypeMetadataKey]; ok {
			if actionType, ok := raw.(string); ok && actionType != "" {
				return actionType
			}
		}
	}

	return requestActionType(req)
}

func grantProfile(req sdk.GuardianRequest) string {
	if req.Metadata == nil {
		return ""
	}
	if profile := metadataString(req.Metadata, grantProfileKey); profile != "" {
		return profile
	}
	return metadataString(req.Metadata, profileMetadataKey)
}

func hardBlockReasons() map[string]string {
	return map[string]string{ //nolint:gosec // Action names mention secrets but are policy taxonomy, not credentials.
		"command.exec_remote":      "remote code execution is blocked",
		"command.obfuscated":       "obfuscated command payloads are blocked",
		"command.dangerous_delete": "dangerous delete operations are blocked",
		"file.write_protected":     "protected path writes are blocked",
		"policy.write":             "policy tampering is blocked",
		"secret.exfiltrate":        "secret exfiltration is blocked",
	}
}

func hardBlockRule(actionType string) (policyRule, bool) {
	reason, ok := hardBlockReasons()[actionType]
	if !ok {
		return policyRule{}, false
	}

	return blockRule(reason), true
}

func profileHardBlockRule(profileName, actionType string) (policyRule, bool) {
	rule, ok := hardBlockRule(actionType)
	if !ok {
		return policyRule{}, false
	}
	if profileName == yoloProfile {
		return allowRule(rule.reason), true
	}
	if profileCanApproveHardCommand(profileName, actionType) {
		return askRule(hardCommandApprovalReason(actionType, rule.reason)), true
	}
	return rule, true
}

func profileCanApproveHardCommand(profileName, actionType string) bool {
	if profileName != defaultProfile && profileName != autoProfile {
		return false
	}
	return canApproveHardCommand(actionType)
}

func canApproveHardCommand(actionType string) bool {
	switch actionType {
	case actionCommandExecRemote, actionCommandObfuscated, actionCommandDangerousDelete:
		return true
	default:
		return false
	}
}

func hardCommandApprovalReason(actionType, fallback string) string {
	switch actionType {
	case actionCommandExecRemote:
		return "remote code execution requires approval"
	case actionCommandObfuscated:
		return "obfuscated command payloads require approval"
	case actionCommandDangerousDelete:
		return "dangerous delete operations require approval"
	default:
		return fallback
	}
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

func normalizeDecision(decision sdk.GuardianDecisionAction) sdk.GuardianDecisionAction {
	switch decision {
	case sdk.GuardianDecisionAllow, sdk.GuardianDecisionAsk, sdk.GuardianDecisionBlock:
		return decision
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
	maps.Copy(out, in)

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
