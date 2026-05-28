package guardian

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"slices"
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
	overlayIDMetadataKey  = "overlay_id"
	overlaySrcMetadataKey = "overlay_source"
	stageActionTypesKey   = "stage_action_types"
	compositionActionKey  = "composition_action_type"

	grantConstraintsVersionKey = "grant_constraints_version"
	grantConstraintsVersion    = "v1"
	grantActionTypeKey         = "grant_action_type"
	grantProfileKey            = "grant_profile"
	grantWorkingDirKey         = "grant_working_dir"
	grantPathPrefixKey         = "grant_path_prefix"
	grantPathExactKey          = "grant_path_exact"
	grantCommandExactKey       = "grant_command_exact"
	grantCommandPrefixKey      = "grant_command_prefix"
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
	rules       map[string][]policyRule
}

type policyRule struct {
	decision sdk.GuardianDecisionAction
	reason   string
	metadata map[string]any
}

type selectedPolicyRule struct {
	actionType string
	rule       policyRule
	overlayID  string
	source     string
}

type policyOverlay struct {
	overlay sdk.GuardianPolicyOverlay
	rules   map[string][]policyRule
}

// Guardian owns action classification, policy decisions, approvals, grants, and
// snapshots.
type Guardian struct {
	cfg             Config
	bus             sdk.Bus
	configWriter    sdk.ExtensionConfigWriter
	profiles        map[string]policyProfile
	headless        bool
	approvalTimeout time.Duration

	persistMu sync.Mutex

	mu       sync.Mutex
	pending  map[string]*pendingApproval
	grants   []sdk.GuardianGrant
	history  []DecisionRecord
	overlays []policyOverlay
	nextID   uint64
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
	sdk.RegisterExtensionWithScopeAndWriter[Config](extensionName, extensionName, func(sdkCfg sdk.Config, writer sdk.PreferenceWriter, cfg Config) (sdk.Extension, error) {
		configWriter, ok := writer.(sdk.ExtensionConfigWriter)
		if !ok {
			configWriter = noopConfigWriter{}
		}

		return newGuardianWithWriter(cfg, sdkCfg.IsHeadless(), configWriter), nil
	})
}

// New creates a Guardian extension with normalized config defaults.
func New(cfg Config) *Guardian {
	return newGuardianWithWriter(cfg, false, noopConfigWriter{})
}

func newGuardian(cfg Config, headless bool) *Guardian {
	return newGuardianWithWriter(cfg, headless, noopConfigWriter{})
}

func newGuardianWithWriter(cfg Config, headless bool, writer sdk.ExtensionConfigWriter) *Guardian {
	if cfg.Profile == "" {
		cfg.Profile = defaultProfile
	}
	if writer == nil {
		writer = noopConfigWriter{}
	}

	profiles := resolveProfiles(cfg.Profiles)
	if _, ok := profiles[cfg.Profile]; !ok {
		cfg.Profile = defaultProfile
	}

	return &Guardian{
		cfg:             cfg,
		configWriter:    writer,
		profiles:        profiles,
		headless:        headless,
		approvalTimeout: approvalTimeout(cfg.ApprovalTimeout),
		pending:         make(map[string]*pendingApproval),
	}
}

type noopConfigWriter struct{}

func (noopConfigWriter) SaveExtensionConfig(_, _ string, _ any) error {
	return sdk.ErrExtensionConfigWriterUnavailable
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
	bus.On(sdk.GuardianPolicyOverlayPushTopic, func(ev sdk.Event) error {
		payload, ok := ev.Payload.(sdk.GuardianPolicyOverlay)
		if !ok {
			return nil
		}
		if g.pushPolicyOverlay(payload) {
			g.publishSnapshot()
		}
		return nil
	})
	bus.On(sdk.GuardianPolicyOverlayPopTopic, func(ev sdk.Event) error {
		payload, ok := ev.Payload.(sdk.GuardianPolicyOverlayPop)
		if !ok {
			return nil
		}
		if g.popPolicyOverlay(payload.ID) {
			g.publishSnapshot()
		}
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
		if resolution.Scope == sdk.GuardianGrantScopeProfile {
			g.persistProfileRule(approval, decision, resolution)
		}
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
	overlays := cloneGuardianPolicyOverlays(g.overlays)
	profiles := cloneSDKProfiles(sdkProfiles(g.profiles))
	g.mu.Unlock()

	return sdk.GuardianSnapshot{
		CurrentProfile: currentProfile,
		Profiles:       profiles,
		Overlays:       overlays,
		Grants:         grants,
		Pending:        pending,
	}, nil
}

func (g *Guardian) publishSnapshot() {
	if g.bus == nil {
		return
	}

	snapshot, err := g.Snapshot(context.Background())
	if err != nil {
		return
	}
	g.bus.Publish(sdk.NewEvent(sdk.GuardianSnapshotTopic, snapshot))
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

func (g *Guardian) pushPolicyOverlay(overlay sdk.GuardianPolicyOverlay) bool {
	if overlay.ID == "" {
		return false
	}

	compiled := policyOverlay{
		overlay: cloneGuardianPolicyOverlay(overlay),
		rules:   compileOverlayRules(overlay),
	}

	g.mu.Lock()
	g.removePolicyOverlayLocked(overlay.ID)
	g.overlays = append(g.overlays, compiled)
	g.mu.Unlock()
	return true
}

func (g *Guardian) popPolicyOverlay(id string) bool {
	if id == "" {
		return false
	}

	g.mu.Lock()
	before := len(g.overlays)
	g.removePolicyOverlayLocked(id)
	ok := len(g.overlays) != before
	g.mu.Unlock()
	return ok
}

func (g *Guardian) removePolicyOverlayLocked(id string) {
	for i, overlay := range g.overlays {
		if overlay.overlay.ID == id {
			g.overlays = append(g.overlays[:i], g.overlays[i+1:]...)
			return
		}
	}
}

func compileOverlayRules(overlay sdk.GuardianPolicyOverlay) map[string][]policyRule {
	rules := make(map[string][]policyRule)
	for _, rule := range overlay.Rules {
		actionTypes := overlayRuleActionTypes(rule)
		if len(actionTypes) == 0 {
			continue
		}
		reason := rule.Reason
		if reason == "" {
			reason = fmt.Sprintf("policy overlay %s overrides action", overlay.ID)
		}
		for _, actionType := range actionTypes {
			rules[actionType] = append(rules[actionType], policyRule{
				decision: normalizeDecision(rule.Decision),
				reason:   reason,
				metadata: maps.Clone(rule.Metadata),
			})
		}
	}
	return rules
}

func overlayRuleActionTypes(rule sdk.GuardianProfileRule) []string {
	if rule.Metadata != nil {
		if actionType, ok := metadataActionType(rule.Metadata); ok {
			return []string{actionType}
		}
	}
	return profileRuleActionTypes(rule)
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
	overlays := append([]policyOverlay(nil), g.overlays...)
	g.mu.Unlock()

	selected := selectedPolicyRule{
		rule: policyRule{
			decision: sdk.GuardianDecisionAllow,
			reason:   "all stages allowed",
		},
	}
	if classification.CompositionActionType != "" {
		if rule, overlay, ok := policyOverlayRule(req, overlays, classification.CompositionActionType, true); ok {
			selected = selectedPolicyRule{
				actionType: classification.CompositionActionType,
				rule:       rule,
				overlayID:  overlay.overlay.ID,
				source:     overlay.overlay.Source,
			}
		}
	}
	for _, actionType := range actionTypes {
		candidate := selectPolicyRuleForActionType(req, overlays, profileName, profile, actionType, g.cfg.AskFallback)
		if compositionOverrideCoversCandidate(classification.CompositionActionType, selected, candidate) {
			continue
		}
		if shouldUseDecision(candidate.actionType, candidate.rule, selected.actionType, selected.rule) {
			selected = candidate
		}
	}

	return guardianDecisionFromSelectedRule(req, profileName, selected, classification)
}

func compositionOverrideCoversCandidate(compositionActionType string, selected, candidate selectedPolicyRule) bool {
	if compositionActionType == "" || selected.actionType != compositionActionType || selected.overlayID == "" {
		return false
	}
	if selected.rule.decision != sdk.GuardianDecisionAllow || candidate.actionType == compositionActionType {
		return false
	}
	if candidate.overlayID != "" {
		return false
	}
	return !isHardBlockActionType(candidate.actionType)
}

func guardianDecisionFromSelectedRule(
	req sdk.GuardianRequest,
	profileName string,
	selected selectedPolicyRule,
	classification execClassification,
) sdk.GuardianDecision {
	metadata := map[string]any{
		actionTypeMetadataKey: selected.actionType,
	}
	if selected.overlayID != "" {
		metadata[overlayIDMetadataKey] = selected.overlayID
		metadata[overlaySrcMetadataKey] = selected.source
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
		Action:    selected.rule.decision,
		Reason:    selected.rule.reason,
		Profile:   profileName,
		Metadata:  metadata,
	}
}

func selectPolicyRuleForActionType(
	req sdk.GuardianRequest,
	overlays []policyOverlay,
	profileName string,
	profile policyProfile,
	actionType string,
	askFallback bool,
) selectedPolicyRule {
	if rule, overlay, ok := policyOverlayRule(req, overlays, actionType, true); ok {
		return selectedPolicyRule{
			actionType: actionType,
			rule:       rule,
			overlayID:  overlay.overlay.ID,
			source:     overlay.overlay.Source,
		}
	}
	if rule, ok := profileHardBlockRule(profileName, actionType); ok {
		if rule.decision == sdk.GuardianDecisionAsk {
			profileCandidate := profilePolicyRule(req, profile, actionType, askFallback)
			if profileCandidate.rule.decision == sdk.GuardianDecisionBlock {
				return profileCandidate
			}
		}
		return selectedPolicyRule{
			actionType: actionType,
			rule:       rule,
		}
	}
	if rule, overlay, ok := policyOverlayRule(req, overlays, actionType, false); ok {
		return selectedPolicyRule{
			actionType: actionType,
			rule:       rule,
			overlayID:  overlay.overlay.ID,
			source:     overlay.overlay.Source,
		}
	}
	return profilePolicyRule(req, profile, actionType, askFallback)
}

func policyOverlayRule(req sdk.GuardianRequest, overlays []policyOverlay, actionType string, overrideHardBlocks bool) (policyRule, policyOverlay, bool) {
	for _, overlay := range slices.Backward(overlays) {
		if overlay.overlay.OverrideHardBlocks != overrideHardBlocks {
			continue
		}
		if rule, ok := lastMatchingPolicyRule(overlay.rules[actionType], req, actionType); ok {
			return rule, overlay, true
		}
	}
	return policyRule{}, policyOverlay{}, false
}

func profilePolicyRule(req sdk.GuardianRequest, profile policyProfile, actionType string, askFallback bool) selectedPolicyRule {
	rule, ok := lastMatchingPolicyRule(profile.rules[actionType], req, actionType)
	if !ok {
		decision := sdk.GuardianDecisionBlock
		if askFallback {
			decision = sdk.GuardianDecisionAsk
		}
		rule = policyRule{
			decision: decision,
			reason:   fmt.Sprintf("%s has no policy rule in profile %s", actionType, profile.name),
		}
	}
	return selectedPolicyRule{
		actionType: actionType,
		rule:       rule,
	}
}

func lastMatchingPolicyRule(rules []policyRule, req sdk.GuardianRequest, actionType string) (policyRule, bool) {
	for _, rule := range slices.Backward(rules) {
		if policyRuleMatchesRequest(rule, req, actionType) {
			return rule, true
		}
	}
	return policyRule{}, false
}

func policyRuleMatchesRequest(rule policyRule, req sdk.GuardianRequest, actionType string) bool {
	metadata := rule.metadata
	if metadataString(metadata, grantConstraintsVersionKey) == "" {
		return true
	}
	if metadataString(metadata, grantConstraintsVersionKey) != grantConstraintsVersion {
		return false
	}
	if grantActionType := metadataString(metadata, grantActionTypeKey); grantActionType != "" && grantActionType != actionType {
		return false
	}
	requestConstraints := requestConstraintsForActionType(req, actionType)
	return grantConstraintMetadataMatchesRequest(metadata, requestConstraints)
}

func resolveProfiles(custom map[string]sdk.GuardianProfile) map[string]policyProfile {
	profiles := builtInProfiles()
	applied := make(map[string]bool, len(custom))

	for name := range custom {
		resolveCustomProfile(name, custom, profiles, applied, make(map[string]bool))
	}

	return profiles
}

func resolveCustomProfile(name string, custom map[string]sdk.GuardianProfile, profiles map[string]policyProfile, applied, resolving map[string]bool) policyProfile {
	if applied[name] {
		if profile, ok := profiles[name]; ok {
			return profile
		}
	}
	cfg, hasCustom := custom[name]
	if !hasCustom {
		if profile, ok := profiles[name]; ok {
			return profile
		}
		return profiles[defaultProfile]
	}
	if resolving[name] {
		if profile, ok := profiles[name]; ok && isBuiltInProfileName(name) {
			return profile
		}
		return profiles[defaultProfile]
	}

	resolving[name] = true
	baseName := profileExtends(cfg)
	if baseName == "" {
		baseName = defaultBaseProfileName(name)
	}
	base := resolveBaseProfile(name, baseName, custom, profiles, applied, resolving)

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
		normalizedDecision := normalizeDecision(decision)
		for _, actionType := range actionTypes {
			if _, hard := hardBlockRule(actionType); hard && normalizedDecision == sdk.GuardianDecisionAllow {
				continue
			}
			rules[actionType] = append(rules[actionType], policyRule{
				decision: normalizedDecision,
				reason:   reason,
				metadata: maps.Clone(override.Metadata),
			})
		}
	}

	for actionType, decision := range legacyProfileActions(cfg) {
		normalizedDecision := normalizeDecision(sdk.GuardianDecisionAction(decision))
		if _, hard := hardBlockRule(actionType); hard && normalizedDecision == sdk.GuardianDecisionAllow {
			continue
		}
		rules[actionType] = append(rules[actionType], policyRule{
			decision: normalizedDecision,
			reason:   fmt.Sprintf("custom profile %s overrides %s", name, actionType),
		})
	}

	profile := policyProfile{
		name:        name,
		description: "Custom profile extending " + base.name,
		rules:       rules,
	}
	profiles[name] = profile
	applied[name] = true
	resolving[name] = false

	return profile
}

func defaultBaseProfileName(name string) string {
	if isBuiltInProfileName(name) {
		return name
	}
	return defaultProfile
}

func resolveBaseProfile(name, baseName string, custom map[string]sdk.GuardianProfile, profiles map[string]policyProfile, applied, resolving map[string]bool) policyProfile {
	if isBuiltInProfileName(name) && baseName == name {
		return profiles[name]
	}
	if _, customBase := custom[baseName]; customBase {
		return resolveCustomProfile(baseName, custom, profiles, applied, resolving)
	}
	if profile, ok := profiles[baseName]; ok {
		return profile
	}
	return profiles[defaultProfile]
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
			types = appendUniqueString(types, actionType)
		}
		if actionType := metadataString(rule.Metadata, grantActionTypeKey); actionType != "" {
			types = appendUniqueString(types, actionType)
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

func appendUniqueString(values []string, value string) []string {
	if slices.Contains(values, value) {
		return values
	}
	return append(values, value)
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

	askRules := map[string][]policyRule{
		"file.read":              {allowRule("project file reads are allowed")},
		"git.read":               {allowRule("git read operations are allowed")},
		"command.read":           {allowRule("read-only commands are allowed")},
		"package.test":           {allowRule("test commands are allowed")},
		"package.build":          {allowRule("build commands are allowed")},
		"policy.read":            {allowRule("policy reads are allowed")},
		"file.write":             {askRule("file writes require approval")},
		"file.delete":            {askRule("file deletes require approval")},
		"git.write":              {askRule("git write operations require approval")},
		"git.discard":            {askRule("git discard operations require approval")},
		"git.remote_write":       {askRule("git remote writes require approval")},
		"git.history_rewrite":    {askRule("git history rewrites require approval")},
		"command.write":          {askRule("write commands require approval")},
		"command.exec_local":     {askRule("local command execution requires approval")},
		"network.read":           {askRule("network reads require approval")},
		"network.write":          {askRule("network writes require approval")},
		"package.install":        {askRule("package installs require approval")},
		"package.global_install": {askRule("global package installs require approval")},
		"package.script":         {askRule("package scripts require approval")},
		"secret.read":            {askRule("secret reads require approval")},
		"system.process_signal":  {askRule("process signal operations require approval")},
		"system.service_change":  {askRule("service changes require approval")},
		"unknown":                {askRule("unknown actions require approval")},
	}
	for actionType, reason := range hardBlocks {
		if canApproveHardCommand(actionType) {
			askRules[actionType] = []policyRule{askRule(hardCommandApprovalReason(actionType, reason))}
			continue
		}
		askRules[actionType] = []policyRule{blockRule(reason)}
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
		autoRules[actionType] = append(autoRules[actionType], allowRule(actionType+" is allowed by auto profile"))
	}

	yoloRules := make(map[string][]policyRule, len(askRules))
	for actionType := range askRules {
		yoloRules[actionType] = []policyRule{allowRule(actionType + " is allowed by yolo profile")}
	}
	yoloRules["unknown"] = []policyRule{allowRule("unknown actions are allowed by yolo profile")}
	for actionType, reason := range hardBlocks {
		yoloRules[actionType] = []policyRule{allowRule(reason)}
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
	requestConstraints := requestConstraintsForActionType(req, actionType)

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
	if scope == sdk.GuardianGrantScopeProfile {
		g.persistProfileRule(approval, decision, resolution)
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
	maps.Copy(request.Metadata, grantMetadataForRequest(request, decision))

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

func (g *Guardian) persistProfileRule(approval sdk.GuardianApproval, decision sdk.GuardianDecision, resolution sdk.GuardianResolution) {
	rule, ok := buildProfileRuleFromApproval(approval, decision, resolution)
	if !ok {
		return
	}

	g.persistMu.Lock()
	defer g.persistMu.Unlock()

	g.mu.Lock()
	targetProfile := decision.Profile
	if targetProfile == "" {
		targetProfile = g.cfg.Profile
	}
	updated := cloneGuardianConfig(g.cfg)
	g.mu.Unlock()

	appendProfileRule(&updated, targetProfile, rule)

	if err := g.configWriter.SaveExtensionConfig(extensionName, extensionName, profileRulePatch(targetProfile, updated.Profiles[targetProfile])); err != nil {
		return
	}

	g.mu.Lock()
	g.cfg = updated
	g.profiles = resolveProfiles(updated.Profiles)
	g.mu.Unlock()
	g.publishSnapshot()
}

func profileRulePatch(profileName string, profile sdk.GuardianProfile) map[string]any {
	profile = cloneGuardianProfile(profile)
	profilePatch := map[string]any{
		"rules": profile.Rules,
	}
	if isBuiltInProfileName(profileName) {
		profilePatch["name"] = profile.Name
		profilePatch["metadata"] = maps.Clone(profile.Metadata)
	}
	return map[string]any{
		"profiles": map[string]any{
			profileName: profilePatch,
		},
	}
}

func appendProfileRule(cfg *Config, profileName string, rule sdk.GuardianProfileRule) {
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]sdk.GuardianProfile)
	}

	profile := cfg.Profiles[profileName]
	if profile.Name == "" {
		profile.Name = profileName
	}
	if profile.Metadata == nil {
		profile.Metadata = make(map[string]any)
	}
	if isBuiltInProfileName(profileName) {
		if metadataString(profile.Metadata, "extends") == "" {
			profile.Metadata["extends"] = profileName
		}
	}
	profile.Rules = append(profile.Rules, cloneGuardianProfileRule(rule))
	cfg.Profiles[profileName] = profile
}

func isBuiltInProfileName(profile string) bool {
	return profile == defaultProfile || profile == autoProfile || profile == yoloProfile
}

func buildProfileRuleFromApproval(approval sdk.GuardianApproval, decision sdk.GuardianDecision, resolution sdk.GuardianResolution) (sdk.GuardianProfileRule, bool) {
	actionType := metadataString(decision.Metadata, actionTypeMetadataKey)
	if actionType == "" {
		actionType = requestActionType(approval.Request)
	}
	ruleDecision := profileRuleDecisionFromResolution(resolution)
	if ruleDecision == sdk.GuardianDecisionAllow {
		if _, hard := hardBlockRule(actionType); hard {
			return sdk.GuardianProfileRule{}, false
		}
	}
	reason := resolutionReason(resolution, decision.Reason)
	if reason == "" {
		reason = "approved"
	}

	metadata := map[string]any{
		actionTypeMetadataKey:      actionType,
		grantConstraintsVersionKey: grantConstraintsVersion,
		grantActionTypeKey:         actionType,
	}

	scope := normalizedRuleScope(approval.Request, resolution.RuleScope)
	if !addProfileRuleScopeMetadata(metadata, approval.Request, decision, scope) {
		return sdk.GuardianProfileRule{}, false
	}

	return sdk.GuardianProfileRule{
		Decision: ruleDecision,
		Reason:   reason,
		Metadata: metadata,
	}, true
}

func profileRuleDecisionFromResolution(resolution sdk.GuardianResolution) sdk.GuardianDecisionAction {
	if resolution.Action == sdk.GuardianResolutionDeny {
		return sdk.GuardianDecisionBlock
	}
	return sdk.GuardianDecisionAllow
}

func normalizedRuleScope(req sdk.GuardianRequest, requested sdk.GuardianProfileRuleScope) sdk.GuardianProfileRuleScope {
	switch requested {
	case sdk.GuardianProfileRuleScopeExactFile,
		sdk.GuardianProfileRuleScopeDirectory,
		sdk.GuardianProfileRuleScopeProject,
		sdk.GuardianProfileRuleScopeExactCommand,
		sdk.GuardianProfileRuleScopeCommandPrefix,
		sdk.GuardianProfileRuleScopeCommandFamily,
		sdk.GuardianProfileRuleScopeNetworkHost,
		sdk.GuardianProfileRuleScopeActionType:
		return requested
	default:
		return defaultRuleScopeForRequest(req)
	}
}

func defaultRuleScopeForRequest(req sdk.GuardianRequest) sdk.GuardianProfileRuleScope {
	switch req.Action {
	case sdk.GuardianActionRead, sdk.GuardianActionWrite, sdk.GuardianActionDelete:
		return sdk.GuardianProfileRuleScopeExactFile
	case sdk.GuardianActionExec:
		return sdk.GuardianProfileRuleScopeExactCommand
	case sdk.GuardianActionNetwork:
		return sdk.GuardianProfileRuleScopeNetworkHost
	default:
		return sdk.GuardianProfileRuleScopeActionType
	}
}

func addProfileRuleScopeMetadata(metadata map[string]any, req sdk.GuardianRequest, decision sdk.GuardianDecision, scope sdk.GuardianProfileRuleScope) bool {
	switch scope {
	case sdk.GuardianProfileRuleScopeExactFile:
		if path := normalizedRuleRequestPath(req); path != "" {
			metadata[grantPathExactKey] = path
			return true
		}
	case sdk.GuardianProfileRuleScopeDirectory:
		if path := normalizedRuleRequestPath(req); path != "" {
			metadata[grantPathPrefixKey] = filepath.Dir(path)
			return true
		}
	case sdk.GuardianProfileRuleScopeProject:
		if req.WorkingDir != "" {
			metadata[grantPathPrefixKey] = normalizeGrantWorkingDir(req.WorkingDir)
			return true
		}
	case sdk.GuardianProfileRuleScopeExactCommand:
		if command := normalizedExactCommand(req.Command); command != "" {
			metadata[grantCommandExactKey] = command
			return true
		}
	case sdk.GuardianProfileRuleScopeCommandPrefix:
		if prefix := commandPrefixForProfileRule(req, decision); prefix != "" {
			metadata[grantCommandPrefixKey] = prefix
			return true
		}
	case sdk.GuardianProfileRuleScopeCommandFamily:
		family := commandFamilyForProfileRule(req, decision)
		if family == "" {
			return false
		}
		if req.WorkingDir != "" {
			metadata[grantWorkingDirKey] = normalizeGrantWorkingDir(req.WorkingDir)
		}
		metadata[grantCommandFamilyKey] = family
		return true
	case sdk.GuardianProfileRuleScopeNetworkHost:
		if host := profileRuleNetworkHost(req, decision); host != "" {
			metadata[grantNetworkHostKey] = host
			return true
		}
	case sdk.GuardianProfileRuleScopeActionType:
		return true
	}
	return false
}

func normalizedRuleRequestPath(req sdk.GuardianRequest) string {
	if req.Path == "" {
		return ""
	}
	return normalizeRequestPath(req.Path, req.WorkingDir).resolved
}

func normalizedExactCommand(command string) string {
	return strings.TrimSpace(command)
}

func commandFamilyForProfileRule(req sdk.GuardianRequest, decision sdk.GuardianDecision) string {
	actionType := metadataString(decision.Metadata, actionTypeMetadataKey)
	stage, ok := selectedShellStage(req.Command, req.WorkingDir, actionType)
	if !ok || len(stage.Tokens) == 0 {
		return ""
	}
	return normalizedCommandName(stage.Tokens[0])
}

func commandPrefixForProfileRule(req sdk.GuardianRequest, decision sdk.GuardianDecision) string {
	actionType := metadataString(decision.Metadata, actionTypeMetadataKey)
	stage, ok := selectedShellStage(req.Command, req.WorkingDir, actionType)
	if !ok || len(stage.Tokens) == 0 {
		return normalizedExactCommand(req.Command)
	}

	parts := []string{normalizedCommandName(stage.Tokens[0])}
	for _, token := range stage.Tokens[1:] {
		if strings.HasPrefix(token, "-") {
			continue
		}
		parts = append(parts, token)
		break
	}
	return strings.Join(parts, " ")
}

func profileRuleNetworkHost(req sdk.GuardianRequest, decision sdk.GuardianDecision) string {
	if host := requestNetworkHost(req); host != "" {
		return host
	}
	actionType := metadataString(decision.Metadata, actionTypeMetadataKey)
	stage, ok := selectedShellStage(req.Command, req.WorkingDir, actionType)
	if !ok {
		return ""
	}
	return shellStageNetworkHost(stage)
}

func grantMetadataForRequest(req sdk.GuardianRequest, decision sdk.GuardianDecision) map[string]any {
	actionType := metadataString(decision.Metadata, actionTypeMetadataKey)
	constraints := requestConstraintsForActionType(req, actionType)
	constraints[grantConstraintsVersionKey] = grantConstraintsVersion
	constraints[grantActionTypeKey] = actionType
	constraints[grantProfileKey] = decision.Profile

	delete(constraints, grantCommandExactKey)
	switch actionType {
	case actionFileRead, actionFileWrite:
		delete(constraints, grantPathExactKey)
	}

	return constraints
}

func requestConstraintsForActionType(req sdk.GuardianRequest, actionType string) map[string]any {
	constraints := make(map[string]any)

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
	case sdk.GuardianActionUnknown:
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

	return grantConstraintMetadataMatchesRequest(grantMetadata, requestConstraints)
}

func grantConstraintMetadataMatchesRequest(grantMetadata, requestConstraints map[string]any) bool {
	if !constraintStringMatches(grantMetadata, requestConstraints, grantWorkingDirKey) {
		return false
	}
	if !constraintStringMatches(grantMetadata, requestConstraints, grantCommandFamilyKey) {
		return false
	}
	if !constraintStringMatches(grantMetadata, requestConstraints, grantNetworkHostKey) {
		return false
	}
	if exact := metadataString(grantMetadata, grantCommandExactKey); exact != "" && metadataString(requestConstraints, grantCommandExactKey) != exact {
		return false
	}
	if prefix := metadataString(grantMetadata, grantCommandPrefixKey); prefix != "" {
		requestCommand := metadataString(requestConstraints, grantCommandExactKey)
		if requestCommand != prefix && !strings.HasPrefix(requestCommand, prefix+" ") {
			return false
		}
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
	constraints[grantPathExactKey] = normalized
	switch actionType {
	case actionFileRead, actionFileWrite:
		constraints[grantPathPrefixKey] = filepath.Dir(normalized)
	case actionFileDelete, actionSecretRead:
	}
}

func addExecGrantConstraints(constraints map[string]any, req sdk.GuardianRequest, actionType string) {
	if command := normalizedExactCommand(req.Command); command != "" {
		constraints[grantCommandExactKey] = command
	}
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
	//nolint:goconst // These are distinct request metadata keys that may carry network hosts.
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

func cloneGuardianPolicyOverlay(overlay sdk.GuardianPolicyOverlay) sdk.GuardianPolicyOverlay {
	overlay.Rules = append([]sdk.GuardianProfileRule(nil), overlay.Rules...)
	for i := range overlay.Rules {
		overlay.Rules[i] = cloneGuardianProfileRule(overlay.Rules[i])
	}
	return overlay
}

func cloneGuardianPolicyOverlays(overlays []policyOverlay) []sdk.GuardianPolicyOverlay {
	out := make([]sdk.GuardianPolicyOverlay, 0, len(overlays))
	for _, overlay := range overlays {
		out = append(out, cloneGuardianPolicyOverlay(overlay.overlay))
	}
	return out
}

func cloneSDKProfiles(profiles map[string]sdk.GuardianProfile) map[string]sdk.GuardianProfile {
	out := make(map[string]sdk.GuardianProfile, len(profiles))
	for name, profile := range profiles {
		out[name] = cloneGuardianProfile(profile)
	}
	return out
}

func cloneGuardianConfig(cfg Config) Config {
	cfg.Profiles = cloneSDKProfiles(cfg.Profiles)
	return cfg
}

func cloneGuardianProfile(profile sdk.GuardianProfile) sdk.GuardianProfile {
	profile.Metadata = maps.Clone(profile.Metadata)
	profile.Rules = append([]sdk.GuardianProfileRule(nil), profile.Rules...)
	for i := range profile.Rules {
		profile.Rules[i] = cloneGuardianProfileRule(profile.Rules[i])
	}
	return profile
}

func cloneGuardianProfileRule(rule sdk.GuardianProfileRule) sdk.GuardianProfileRule {
	rule.Actions = append([]sdk.GuardianAction(nil), rule.Actions...)
	rule.Metadata = maps.Clone(rule.Metadata)
	return rule
}

func grantActionType(req sdk.GuardianRequest) string {
	if req.Metadata == nil {
		return requestActionType(req)
	}
	if actionType := metadataString(req.Metadata, grantActionTypeKey); actionType != "" {
		return actionType
	}
	if actionType := metadataString(req.Metadata, actionTypeMetadataKey); actionType != "" {
		return actionType
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

func isHardBlockActionType(actionType string) bool {
	_, ok := hardBlockReasons()[actionType]
	return ok
}

func profileHardBlockRule(profileName, actionType string) (policyRule, bool) {
	if profileName == yoloProfile {
		return policyRule{}, false
	}
	rule, ok := hardBlockRule(actionType)
	if !ok {
		return policyRule{}, false
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

func copyRules(in map[string][]policyRule) map[string][]policyRule {
	out := make(map[string][]policyRule, len(in))
	for actionType, rules := range in {
		out[actionType] = clonePolicyRules(rules)
	}
	return out
}

func clonePolicyRules(in []policyRule) []policyRule {
	out := make([]policyRule, len(in))
	for i, rule := range in {
		out[i] = policyRule{
			decision: rule.decision,
			reason:   rule.reason,
			metadata: maps.Clone(rule.metadata),
		}
	}
	return out
}

func sdkProfiles(profiles map[string]policyProfile) map[string]sdk.GuardianProfile {
	out := make(map[string]sdk.GuardianProfile, len(profiles))
	for name, profile := range profiles {
		rules := make([]sdk.GuardianProfileRule, 0, len(profile.rules))
		for actionType, compiledRules := range profile.rules {
			for _, rule := range slices.Backward(compiledRules) {
				metadata := maps.Clone(rule.metadata)
				if metadata == nil {
					metadata = make(map[string]any)
				}
				metadata[actionTypeMetadataKey] = actionType
				rules = append(rules, sdk.GuardianProfileRule{
					Decision: rule.decision,
					Reason:   rule.reason,
					Metadata: metadata,
				})
			}
		}
		out[name] = sdk.GuardianProfile{
			Name:        profile.name,
			Description: profile.description,
			Rules:       rules,
		}
	}
	return out
}
