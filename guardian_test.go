package guardian

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weave-agent/weave/sdk"
)

type stubBus struct {
	mu        sync.Mutex
	handlers  map[string]sdk.Handler
	published []sdk.Event
}

func newStubBus() *stubBus {
	return &stubBus{handlers: make(map[string]sdk.Handler)}
}

func (b *stubBus) Publish(ev sdk.Event) {
	b.mu.Lock()
	b.published = append(b.published, ev)
	b.mu.Unlock()

	if h, ok := b.handlers[ev.Topic]; ok {
		_ = h(ev)
	}
}

func (b *stubBus) On(topic string, h sdk.Handler) { b.handlers[topic] = h }
func (b *stubBus) OnAll(sdk.Handler)              {}
func (b *stubBus) Off(sdk.Handler)                {}
func (b *stubBus) Close() error                   { return nil }

func (b *stubBus) events() []sdk.Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]sdk.Event(nil), b.published...)
}

type configStub struct {
	scope string
	name  string
	cfg   Config
}

func (c *configStub) FilePath() string   { return "" }
func (c *configStub) ProjectDir() string { return "" }
func (c *configStub) ExtensionConfig(scope, name string, target any) error {
	c.scope = scope
	c.name = name

	cfg, ok := target.(*Config)
	if ok {
		*cfg = c.cfg
	}

	return nil
}
func (c *configStub) IsHeadless() bool          { return true }
func (c *configStub) RespectGitignore() bool    { return true }
func (c *configStub) Preferences(any) error     { return nil }
func (c *configStub) SavePreferences(any) error { return nil }
func (c *configStub) SaveProviderKey(string, string) error {
	return nil
}

func TestGuardianRegisteredWithSDK(t *testing.T) {
	assert.True(t, sdk.ExtensionRegistered(extensionName))
}

func TestGetExtensionLoadsGuardianScopedConfig(t *testing.T) {
	cfg := &configStub{cfg: Config{Profile: "auto"}}

	ext, err := sdk.GetExtension(extensionName, cfg)
	require.NoError(t, err)

	g, ok := ext.(*Guardian)
	require.True(t, ok)
	assert.Equal(t, extensionName, cfg.scope)
	assert.Equal(t, extensionName, cfg.name)
	assert.Equal(t, "auto", g.cfg.Profile)

	snapshot, err := g.Snapshot(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "auto", snapshot.CurrentProfile)
}

func TestNewDefaultsToAskProfile(t *testing.T) {
	g := New(Config{})

	assert.Equal(t, extensionName, g.Name())
	assert.Equal(t, defaultProfile, g.cfg.Profile)
}

func TestSubscribePublishesGuardianRegistered(t *testing.T) {
	g := New(Config{Profile: "ask"})
	bus := newStubBus()

	err := g.Subscribe(bus)
	require.NoError(t, err)

	events := bus.events()
	require.Len(t, events, 1)
	assert.Equal(t, sdk.GuardianRegisteredTopic, events[0].Topic)

	payload, ok := events[0].Payload.(sdk.Guardian)
	require.True(t, ok)
	assert.Same(t, g, payload)
}

func TestBuiltInProfilePolicies(t *testing.T) {
	tests := []struct {
		name       string
		profile    string
		actionType string
		want       sdk.GuardianDecisionAction
	}{
		{
			name:       "ask allows reads",
			profile:    "ask",
			actionType: "file.read",
			want:       sdk.GuardianDecisionAllow,
		},
		{
			name:       "ask asks on writes",
			profile:    "ask",
			actionType: "file.write",
			want:       sdk.GuardianDecisionAsk,
		},
		{
			name:       "ask asks on unknown",
			profile:    "ask",
			actionType: "unknown",
			want:       sdk.GuardianDecisionAsk,
		},
		{
			name:       "auto allows routine writes",
			profile:    "auto",
			actionType: "file.write",
			want:       sdk.GuardianDecisionAllow,
		},
		{
			name:       "auto still asks on unknown",
			profile:    "auto",
			actionType: "unknown",
			want:       sdk.GuardianDecisionAsk,
		},
		{
			name:       "yolo allows unknown",
			profile:    "yolo",
			actionType: "unknown",
			want:       sdk.GuardianDecisionAllow,
		},
		{
			name:       "yolo enforces hard blocks",
			profile:    "yolo",
			actionType: "secret.exfiltrate",
			want:       sdk.GuardianDecisionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New(Config{Profile: tt.profile})

			decision, err := g.Decide(context.Background(), requestForActionType(tt.actionType))
			require.NoError(t, err)

			assert.Equal(t, tt.want, decision.Action)
			assert.Equal(t, tt.profile, decision.Profile)
			assert.Equal(t, tt.actionType, decision.Metadata[actionTypeMetadataKey])
			assert.NotEmpty(t, decision.Reason)
		})
	}
}

func TestCustomProfileMergesWithBaseProfile(t *testing.T) {
	g := New(Config{
		Profile: "team",
		Profiles: map[string]ProfileConfig{
			"team": {
				Extends: "auto",
				Actions: map[string]string{
					"network.read":           string(sdk.GuardianDecisionAsk),
					"package.global_install": string(sdk.GuardianDecisionBlock),
				},
			},
		},
	})

	networkDecision, err := g.Decide(context.Background(), requestForActionType("network.read"))
	require.NoError(t, err)
	assert.Equal(t, sdk.GuardianDecisionAsk, networkDecision.Action)
	assert.Equal(t, "team", networkDecision.Profile)

	writeDecision, err := g.Decide(context.Background(), requestForActionType("file.write"))
	require.NoError(t, err)
	assert.Equal(t, sdk.GuardianDecisionAllow, writeDecision.Action)

	globalInstallDecision, err := g.Decide(context.Background(), requestForActionType("package.global_install"))
	require.NoError(t, err)
	assert.Equal(t, sdk.GuardianDecisionBlock, globalInstallDecision.Action)
}

func TestCustomProfileCanExtendCustomProfile(t *testing.T) {
	g := New(Config{
		Profile: "child",
		Profiles: map[string]ProfileConfig{
			"base": {
				Extends: "ask",
				Actions: map[string]string{
					"file.write": string(sdk.GuardianDecisionAllow),
				},
			},
			"child": {
				Extends: "base",
				Actions: map[string]string{
					"network.write": string(sdk.GuardianDecisionBlock),
				},
			},
		},
	})

	writeDecision, err := g.Decide(context.Background(), requestForActionType("file.write"))
	require.NoError(t, err)
	assert.Equal(t, sdk.GuardianDecisionAllow, writeDecision.Action)

	networkDecision, err := g.Decide(context.Background(), requestForActionType("network.write"))
	require.NoError(t, err)
	assert.Equal(t, sdk.GuardianDecisionBlock, networkDecision.Action)
}

func TestMissingCustomProfileBaseFallsBackToAskProfile(t *testing.T) {
	g := New(Config{
		Profile: "team",
		Profiles: map[string]ProfileConfig{
			"team": {
				Extends: "missing",
				Actions: map[string]string{
					"network.read": string(sdk.GuardianDecisionAllow),
				},
			},
		},
	})

	writeDecision, err := g.Decide(context.Background(), requestForActionType("file.write"))
	require.NoError(t, err)
	assert.Equal(t, sdk.GuardianDecisionAsk, writeDecision.Action)

	networkDecision, err := g.Decide(context.Background(), requestForActionType("network.read"))
	require.NoError(t, err)
	assert.Equal(t, sdk.GuardianDecisionAllow, networkDecision.Action)
}

func TestUnknownConfiguredProfileFallsBackToAskProfile(t *testing.T) {
	g := New(Config{Profile: "missing"})

	decision, err := g.Decide(context.Background(), requestForActionType("file.write"))
	require.NoError(t, err)

	assert.Equal(t, defaultProfile, g.cfg.Profile)
	assert.Equal(t, defaultProfile, decision.Profile)
	assert.Equal(t, sdk.GuardianDecisionAsk, decision.Action)
}

func TestActionWithoutPolicyRuleDefaultsToBlock(t *testing.T) {
	g := New(Config{Profile: "ask"})

	decision, err := g.Decide(context.Background(), requestForActionType("brand.new.action"))
	require.NoError(t, err)

	assert.Equal(t, sdk.GuardianDecisionBlock, decision.Action)
	assert.Contains(t, decision.Reason, "has no policy rule")
}

func TestInvalidCustomDecisionDefaultsToBlock(t *testing.T) {
	g := New(Config{
		Profile: "team",
		Profiles: map[string]ProfileConfig{
			"team": {
				Actions: map[string]string{
					"file.read": "invalid",
				},
			},
		},
	})

	decision, err := g.Decide(context.Background(), requestForActionType("file.read"))
	require.NoError(t, err)

	assert.Equal(t, sdk.GuardianDecisionBlock, decision.Action)
}

func TestSDKActionFallbacksMapToDetailedActionTypes(t *testing.T) {
	g := New(Config{Profile: "ask"})

	decision, err := g.Decide(context.Background(), sdk.GuardianRequest{
		ID:     "req-write",
		Action: sdk.GuardianActionWrite,
	})
	require.NoError(t, err)

	assert.Equal(t, "file.write", decision.Metadata[actionTypeMetadataKey])
	assert.Equal(t, sdk.GuardianDecisionAsk, decision.Action)
}

func TestFileActionClassifier(t *testing.T) {
	projectDir := t.TempDir()
	tests := []struct {
		name     string
		action   sdk.GuardianAction
		path     string
		wantType string
	}{
		{
			name:     "project file read",
			action:   sdk.GuardianActionRead,
			path:     "README.md",
			wantType: actionFileRead,
		},
		{
			name:     "project file write",
			action:   sdk.GuardianActionWrite,
			path:     "src/main.go",
			wantType: actionFileWrite,
		},
		{
			name:     "project file delete",
			action:   sdk.GuardianActionDelete,
			path:     "old.txt",
			wantType: actionFileDelete,
		},
		{
			name:     "env file read is secret",
			action:   sdk.GuardianActionRead,
			path:     ".env.local",
			wantType: actionSecretRead,
		},
		{
			name:     "ssh key read is secret",
			action:   sdk.GuardianActionRead,
			path:     filepath.Join(projectDir, ".ssh", "id_rsa"),
			wantType: actionSecretRead,
		},
		{
			name:     "guardian settings read is policy",
			action:   sdk.GuardianActionRead,
			path:     filepath.Join(projectDir, ".weave", "guardian", "settings.json"),
			wantType: actionPolicyRead,
		},
		{
			name:     "sandbox settings write is policy tampering",
			action:   sdk.GuardianActionWrite,
			path:     filepath.Join(projectDir, ".weave", "sandbox", "config.json"),
			wantType: actionPolicyWrite,
		},
		{
			name:     "extension policy delete is policy tampering",
			action:   sdk.GuardianActionDelete,
			path:     filepath.Join(projectDir, ".weave", "extensions", "tool", "policy.yaml"),
			wantType: actionPolicyWrite,
		},
		{
			name:     "git internals write is protected",
			action:   sdk.GuardianActionWrite,
			path:     filepath.Join(projectDir, ".git", "config"),
			wantType: actionFileProtected,
		},
		{
			name:     "system config write is protected",
			action:   sdk.GuardianActionWrite,
			path:     "/etc/hosts",
			wantType: actionFileProtected,
		},
		{
			name:     "secret write falls back to normal write",
			action:   sdk.GuardianActionWrite,
			path:     ".env",
			wantType: actionFileWrite,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := sdk.GuardianRequest{
				ID:         "req",
				Action:     tt.action,
				Path:       tt.path,
				WorkingDir: projectDir,
			}

			assert.Equal(t, tt.wantType, classifyRequest(req))
		})
	}
}

func TestFileActionClassifierResolvesSymlinks(t *testing.T) {
	projectDir := t.TempDir()
	realDir := filepath.Join(projectDir, "real")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, ".env"), []byte("TOKEN=value"), 0o600))

	secretLink := filepath.Join(projectDir, "safe-name")
	require.NoError(t, os.Symlink(filepath.Join(realDir, ".env"), secretLink))

	req := sdk.GuardianRequest{
		ID:         "req",
		Action:     sdk.GuardianActionRead,
		Path:       secretLink,
		WorkingDir: projectDir,
	}

	assert.Equal(t, actionSecretRead, classifyRequest(req))
}

func TestFileActionClassifierResolvesExistingSymlinkParents(t *testing.T) {
	projectDir := t.TempDir()
	realWeave := filepath.Join(projectDir, "real-weave")
	require.NoError(t, os.MkdirAll(filepath.Join(realWeave, "extensions", "tool"), 0o755))

	link := filepath.Join(projectDir, "linked-weave")
	require.NoError(t, os.Symlink(realWeave, link))

	req := sdk.GuardianRequest{
		ID:         "req",
		Action:     sdk.GuardianActionWrite,
		Path:       filepath.Join(link, "extensions", "tool", "policy.json"),
		WorkingDir: projectDir,
	}

	assert.Equal(t, actionPolicyWrite, classifyRequest(req))
}

func TestDecideUsesFileClassifierWhenMetadataIsAbsent(t *testing.T) {
	g := New(Config{Profile: "ask"})
	projectDir := t.TempDir()

	decision, err := g.Decide(context.Background(), sdk.GuardianRequest{
		ID:         "req-policy",
		Action:     sdk.GuardianActionWrite,
		Path:       filepath.Join(projectDir, ".weave", "guardian", "settings.json"),
		WorkingDir: projectDir,
	})
	require.NoError(t, err)

	assert.Equal(t, actionPolicyWrite, decision.Metadata[actionTypeMetadataKey])
	assert.Equal(t, sdk.GuardianDecisionBlock, decision.Action)
}

func TestSnapshotIncludesResolvedProfiles(t *testing.T) {
	g := New(Config{
		Profile: "team",
		Profiles: map[string]ProfileConfig{
			"team": {
				Extends: "yolo",
				Actions: map[string]string{
					"network.write": string(sdk.GuardianDecisionAsk),
				},
			},
		},
	})

	snapshot, err := g.Snapshot(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "team", snapshot.CurrentProfile)
	require.Contains(t, snapshot.Profiles, "ask")
	require.Contains(t, snapshot.Profiles, "auto")
	require.Contains(t, snapshot.Profiles, "yolo")
	require.Contains(t, snapshot.Profiles, "team")
	assert.Equal(t, "team", snapshot.Profiles["team"].Name)
	assert.NotEmpty(t, snapshot.Profiles["team"].Rules)
}

func requestForActionType(actionType string) sdk.GuardianRequest {
	return sdk.GuardianRequest{
		ID:     "req-" + actionType,
		Action: sdk.GuardianActionUnknown,
		Metadata: map[string]any{
			actionTypeMetadataKey: actionType,
		},
	}
}
