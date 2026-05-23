package guardian

import (
	"context"

	"github.com/weave-agent/weave/sdk"
)

const (
	extensionName = "guardian"

	defaultProfile = "ask"
)

// Config holds guardian extension settings.
type Config struct {
	Profile string `json:"profile" default:"ask" env:"PROFILE" description:"Active guardian policy profile"`
}

// Guardian owns action classification, policy decisions, approvals, grants, and
// snapshots.
type Guardian struct {
	cfg Config
	bus sdk.Bus
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

	return &Guardian{cfg: cfg}
}

func (g *Guardian) Name() string { return extensionName }

func (g *Guardian) Subscribe(bus sdk.Bus) error {
	g.bus = bus
	bus.Publish(sdk.NewEvent(sdk.GuardianRegisteredTopic, g))

	return nil
}

func (g *Guardian) Close() error { return nil }

func (g *Guardian) Decide(_ context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
	return sdk.GuardianDecision{
		ID:        req.ID,
		RequestID: req.ID,
		Action:    sdk.GuardianDecisionAsk,
		Reason:    "guardian policy resolution is not configured yet",
		Profile:   g.cfg.Profile,
	}, nil
}

func (g *Guardian) Resolve(context.Context, string, sdk.GuardianResolution) error {
	return nil
}

func (g *Guardian) Snapshot(context.Context) (sdk.GuardianSnapshot, error) {
	return sdk.GuardianSnapshot{
		CurrentProfile: g.cfg.Profile,
	}, nil
}
