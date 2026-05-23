package guardian

import (
	"context"
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
