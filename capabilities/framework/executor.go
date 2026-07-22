package framework

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/protobuf/types/known/anypb"

	p2ptypes "github.com/smartcontractkit/libocr/ragep2p/types"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/ratelimit"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/limits"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	"github.com/smartcontractkit/chainlink-common/pkg/workflows/host"
	"github.com/smartcontractkit/chainlink-protos/cre/go/sdk"

	enclaveclient "github.com/smartcontractkit/chainlink-confidential-compute/enclave-client"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	framework "github.com/smartcontractkit/chainlink-confidential-compute/types/frameworktypes"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/actions/vault"
	caperrors "github.com/smartcontractkit/chainlink-common/pkg/capabilities/errors"
)

// Re-declare constants and types needed for this file
const (
	DefaultMaxRetries          = 3
	DefaultRetryBackoffSeconds = 2
	DefaultWorkflowOwnerRPS    = 1000
	DefaultWorkflowOwnerBurst  = 1000
	DefaultGlobalRPS           = 1000
	DefaultGlobalBurst         = 1000

	// DefaultEnclaveRefreshIntervalSeconds is how often the executor refreshes
	// enclaves and re-checks DON membership in the background.
	DefaultEnclaveRefreshIntervalSeconds = 10
)

const CapabilityRequestReferenceIDPrefix = "conf_http_vault_request_"

const authHeaderTemplate = "x-api-key: %s" //nolint:gosec
const retryTemplate = "confidential-retry-%s"

type VaultDON struct {
	CryptographyThreshold int
	Capability            capabilities.ExecutableCapability
}

type EnclaveParams struct {
	EnclaveID                 [32]byte
	EnclaveEphemeralPublicKey []byte
}

type Config struct {
	// Enclave communication
	//
	// Deprecated: superseded by the ConfidentialCompute.InsecureSkipTLSVerify
	// cresetting, which is authoritative. Retained only as a transitional
	// per-node override while deployments migrate off the job-spec config.
	InsecureSkipTLSVerify *bool  `json:"InsecureSkipTLSVerify" yaml:"InsecureSkipTLSVerify" mapstructure:"InsecureSkipTLSVerify"`
	EncryptedAPIKeys      string `json:"EncryptedAPIKeys" yaml:"EncryptedAPIKeys" mapstructure:"EncryptedAPIKeys"`
	//
	// Deprecated: superseded by the ConfidentialCompute.EnclaveRequestTimeout
	// cresetting, which is authoritative. Retained only as a transitional
	// per-node override while deployments migrate off the job-spec config.
	EnclaveRequestTimeoutSeconds *int `json:"EnclaveRequestTimeoutSeconds" yaml:"EnclaveRequestTimeoutSeconds" mapstructure:"EnclaveRequestTimeoutSeconds"`

	// PublicKeyRequestTimeoutSeconds is a shorter timeout for GetPublicKeys calls.
	//
	// Deprecated: superseded by the ConfidentialCompute.PublicKeyRequestTimeout
	// cresetting, which is authoritative. Retained only as a transitional
	// per-node override while deployments migrate off the job-spec config.
	PublicKeyRequestTimeoutSeconds *int `json:"PublicKeyRequestTimeoutSeconds" yaml:"PublicKeyRequestTimeoutSeconds" mapstructure:"PublicKeyRequestTimeoutSeconds"`

	// EnclaveRefreshIntervalSeconds is how often the executor refreshes enclaves and
	// re-checks DON membership in the background.
	//
	// Deprecated: superseded by the ConfidentialCompute.EnclaveRefreshInterval
	// cresetting, which is authoritative. Retained only as a transitional
	// per-node override while deployments migrate off the job-spec config.
	EnclaveRefreshIntervalSeconds *int `json:"EnclaveRefreshIntervalSeconds" yaml:"EnclaveRefreshIntervalSeconds" mapstructure:"EnclaveRefreshIntervalSeconds"`

	// Limits
	//
	// Deprecated: superseded by the ConfidentialCompute.MaxRetries cresetting,
	// which is authoritative. Retained only as a transitional per-node override
	// while deployments migrate off the job-spec config.
	MaxRetries *int `json:"MaxRetries" yaml:"MaxRetries" mapstructure:"MaxRetries"`
	//
	// Deprecated: superseded by the ConfidentialCompute.RetryBackoff cresetting,
	// which is authoritative. Retained only as a transitional per-node override
	// while deployments migrate off the job-spec config.
	RetryBackoffSeconds *int `json:"RetryBackoffSeconds" yaml:"RetryBackoffSeconds" mapstructure:"RetryBackoffSeconds"`
	//
	// Deprecated: superseded by the PerOwner.ConfidentialCompute.Rate cresetting,
	// which is authoritative. Retained only as a transitional per-node override
	// while deployments migrate off the job-spec config.
	WorkflowOwnerRPS *float64 `json:"WorkflowOwnerRPS" yaml:"WorkflowOwnerRPS" mapstructure:"WorkflowOwnerRPS"`
	//
	// Deprecated: superseded by the PerOwner.ConfidentialCompute.Rate cresetting,
	// which is authoritative. Retained only as a transitional per-node override
	// while deployments migrate off the job-spec config.
	WorkflowOwnerBurst *int `json:"WorkflowOwnerBurst" yaml:"WorkflowOwnerBurst" mapstructure:"WorkflowOwnerBurst"`
	//
	// Deprecated: superseded by the ConfidentialCompute.GlobalRate cresetting,
	// which is authoritative. Retained only as a transitional per-node override
	// while deployments migrate off the job-spec config.
	GlobalRPS *float64 `json:"GlobalRPS" yaml:"GlobalRPS" mapstructure:"GlobalRPS"`
	//
	// Deprecated: superseded by the ConfidentialCompute.GlobalRate cresetting,
	// which is authoritative. Retained only as a transitional per-node override
	// while deployments migrate off the job-spec config.
	GlobalBurst *int `json:"GlobalBurst" yaml:"GlobalBurst" mapstructure:"GlobalBurst"`

	// Vault DON
	DisableSecretsCacheDeprecated *bool `json:"DisableSecretsCache" yaml:"DisableSecretsCache" mapstructure:"DisableSecretsCache"` // Deprecated. Do not use.
	//
	// Deprecated: superseded by the ConfidentialCompute.SecretsCacheEnabled
	// cresetting, which is authoritative. Retained only as a transitional
	// per-node override while deployments migrate off the job-spec config.
	EnableSecretsCache *bool `json:"EnableSecretsCache" yaml:"EnableSecretsCache" mapstructure:"EnableSecretsCache"`

	// Enclave public key caching
	//
	// Deprecated: superseded by ConfidentialCompute.PublicKeyCache.* cresettings,
	// which are authoritative. Retained only as transitional per-node overrides
	// while deployments migrate off the job-spec config.
	EnableCache               *bool    `json:"EnableCache" yaml:"EnableCache" mapstructure:"EnableCache"`
	CacheTTLSeconds           *int     `json:"CacheTTLSeconds" yaml:"CacheTTLSeconds" mapstructure:"CacheTTLSeconds"`
	CacheMaxTTLSeconds        *int     `json:"CacheMaxTTLSeconds" yaml:"CacheMaxTTLSeconds" mapstructure:"CacheMaxTTLSeconds"`
	CacheCleanupSeconds       *int     `json:"CacheCleanupSeconds" yaml:"CacheCleanupSeconds" mapstructure:"CacheCleanupSeconds"`
	CacheTTLBufferPercent     *float64 `json:"CacheTTLBufferPercent" yaml:"CacheTTLBufferPercent" mapstructure:"CacheTTLBufferPercent"`
	EnableProactiveRefresh    *bool    `json:"EnableProactiveRefresh" yaml:"EnableProactiveRefresh" mapstructure:"EnableProactiveRefresh"`
	RefreshIntervalPercent    *float64 `json:"RefreshIntervalPercent" yaml:"RefreshIntervalPercent" mapstructure:"RefreshIntervalPercent"`
	MinRefreshIntervalSeconds *int     `json:"MinRefreshIntervalSeconds" yaml:"MinRefreshIntervalSeconds" mapstructure:"MinRefreshIntervalSeconds"`
	RefreshTimeoutSeconds     *int     `json:"RefreshTimeoutSeconds" yaml:"RefreshTimeoutSeconds" mapstructure:"RefreshTimeoutSeconds"`

	// Sticky sessions
	//
	// Deprecated: superseded by ConfidentialCompute.Session.* cresettings, which
	// are authoritative. Retained only as transitional per-node overrides while
	// deployments migrate off the job-spec config.
	EnableSessionPersistence *bool   `json:"EnableSessionPersistence" yaml:"EnableSessionPersistence" mapstructure:"EnableSessionPersistence"`
	SessionHeaderName        *string `json:"SessionHeaderName" yaml:"SessionHeaderName" mapstructure:"SessionHeaderName"`
}

type ParsedConfig struct {
	Config                  Config
	MaxRetries              int
	RetryBackoffSeconds     int
	GlobalRPS               float64
	GlobalBurst             int
	WorkflowOwnerRPS        float64
	WorkflowOwnerBurst      int
	EnableSecretsCache      bool
	EnclaveRequestTimeout   time.Duration
	PublicKeyRequestTimeout time.Duration
	EnclaveRefreshInterval  time.Duration
	InsecureSkipTLSVerify   bool
	CacheConfig             enclaveclient.CacheConfig
	SessionConfig           enclaveclient.SessionConfig
}

func ParseConfig(capConfigRaw string) (*ParsedConfig, error) {
	var capConfig Config
	if err := json.Unmarshal([]byte(capConfigRaw), &capConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	parsed := &ParsedConfig{
		Config:                  capConfig,
		MaxRetries:              DefaultMaxRetries,
		RetryBackoffSeconds:     DefaultRetryBackoffSeconds,
		GlobalRPS:               DefaultGlobalRPS,
		GlobalBurst:             DefaultGlobalBurst,
		WorkflowOwnerRPS:        DefaultWorkflowOwnerRPS,
		WorkflowOwnerBurst:      DefaultWorkflowOwnerBurst,
		EnableSecretsCache:      types.DefaultEnableSecretsCache,
		EnclaveRequestTimeout:   types.DefaultEnclaveRequestTimeout,
		PublicKeyRequestTimeout: types.DefaultPublicKeyRequestTimeout,
		EnclaveRefreshInterval:  DefaultEnclaveRefreshIntervalSeconds * time.Second,
		CacheConfig:             enclaveclient.DefaultCacheConfig,
		SessionConfig:           enclaveclient.DefaultSessionConfig,
	}

	// Override with provided values
	if capConfig.MaxRetries != nil {
		parsed.MaxRetries = *capConfig.MaxRetries
	}
	if capConfig.RetryBackoffSeconds != nil {
		parsed.RetryBackoffSeconds = *capConfig.RetryBackoffSeconds
	}
	if capConfig.GlobalRPS != nil {
		parsed.GlobalRPS = *capConfig.GlobalRPS
	}
	if capConfig.GlobalBurst != nil {
		parsed.GlobalBurst = *capConfig.GlobalBurst
	}
	if capConfig.WorkflowOwnerRPS != nil {
		parsed.WorkflowOwnerRPS = *capConfig.WorkflowOwnerRPS
	}
	if capConfig.WorkflowOwnerBurst != nil {
		parsed.WorkflowOwnerBurst = *capConfig.WorkflowOwnerBurst
	}
	if capConfig.EnableSecretsCache != nil {
		parsed.EnableSecretsCache = *capConfig.EnableSecretsCache
	}
	if capConfig.EnclaveRequestTimeoutSeconds != nil {
		parsed.EnclaveRequestTimeout = time.Duration(*capConfig.EnclaveRequestTimeoutSeconds) * time.Second
	}
	if capConfig.PublicKeyRequestTimeoutSeconds != nil {
		parsed.PublicKeyRequestTimeout = time.Duration(*capConfig.PublicKeyRequestTimeoutSeconds) * time.Second
	}
	if capConfig.EnclaveRefreshIntervalSeconds != nil {
		parsed.EnclaveRefreshInterval = time.Duration(*capConfig.EnclaveRefreshIntervalSeconds) * time.Second
	}
	if capConfig.EnableCache != nil {
		parsed.CacheConfig.EnableCache = *capConfig.EnableCache
	}
	if capConfig.CacheTTLSeconds != nil {
		parsed.CacheConfig.DefaultTTL = time.Duration(*capConfig.CacheTTLSeconds) * time.Second
	}
	if capConfig.CacheMaxTTLSeconds != nil {
		parsed.CacheConfig.MaxTTL = time.Duration(*capConfig.CacheMaxTTLSeconds) * time.Second
	}
	if capConfig.CacheCleanupSeconds != nil {
		parsed.CacheConfig.CleanupInterval = time.Duration(*capConfig.CacheCleanupSeconds) * time.Second
	}
	if capConfig.CacheTTLBufferPercent != nil {
		parsed.CacheConfig.TTLBufferPercent = *capConfig.CacheTTLBufferPercent
	}
	if capConfig.EnableProactiveRefresh != nil {
		parsed.CacheConfig.EnableProactiveRefresh = *capConfig.EnableProactiveRefresh
	}
	if capConfig.RefreshIntervalPercent != nil {
		parsed.CacheConfig.RefreshIntervalPercent = *capConfig.RefreshIntervalPercent
	}
	if capConfig.MinRefreshIntervalSeconds != nil {
		parsed.CacheConfig.MinRefreshInterval = time.Duration(*capConfig.MinRefreshIntervalSeconds) * time.Second
	}
	if capConfig.RefreshTimeoutSeconds != nil {
		parsed.CacheConfig.RefreshTimeout = time.Duration(*capConfig.RefreshTimeoutSeconds) * time.Second
	}
	if capConfig.EnableSessionPersistence != nil {
		parsed.SessionConfig.EnableSessionPersistence = *capConfig.EnableSessionPersistence
	}
	if capConfig.SessionHeaderName != nil {
		parsed.SessionConfig.SessionHeaderName = *capConfig.SessionHeaderName
	}

	return parsed, nil
}

// applyLimitSettings overlays the CRE limits framework values onto the parsed
// config: the global + per-workflow-owner request rates, the retry policy, the
// secrets-cache toggle, the enclave/public-key request timeouts, TLS verification,
// enclave refresh interval, public-key cache, and sticky-session settings. These
// are all node-local controls that do not feed the hashed enclave request, so
// reading them from limits cannot affect DON-to-DON determinism.
//
// The timeout values written here are used for logging at init time; the pool's
// RequestTimeout resolver re-reads the limits on each enclave-client call so a
// limit change takes effect without re-initializing the executor.
//
// Resolution order: the limits value is the source of truth, and an explicitly
// set job-spec Config field still overrides it for backward compatibility while
// deployments migrate off the job-spec config. GetOrDefault returns the limits
// default (which mirrors the historical hardcoded defaults) on any lookup error,
// so behavior is preserved if settings are unavailable.
func (e *RealExecutor) applyLimitSettings(ctx context.Context, parsed *ParsedConfig) {
	g := e.limitsFactory.Settings
	cc := cresettings.Default.ConfidentialCompute
	pkc := cc.PublicKeyCache
	sess := cc.Session

	globalRate, _ := cc.GlobalRate.GetOrDefault(ctx, g)
	ownerRate, _ := cresettings.Default.PerOwner.ConfidentialCompute.Rate.GetOrDefault(ctx, g)
	maxRetries, _ := cc.MaxRetries.GetOrDefault(ctx, g)
	retryBackoff, _ := cc.RetryBackoff.GetOrDefault(ctx, g)
	secretsCacheEnabled, _ := cc.SecretsCacheEnabled.GetOrDefault(ctx, g)
	enclaveRequestTimeout, _ := cc.EnclaveRequestTimeout.GetOrDefault(ctx, g)
	publicKeyRequestTimeout, _ := cc.PublicKeyRequestTimeout.GetOrDefault(ctx, g)
	insecureSkipTLSVerify, _ := cc.InsecureSkipTLSVerify.GetOrDefault(ctx, g)
	enclaveRefreshInterval, _ := cc.EnclaveRefreshInterval.GetOrDefault(ctx, g)
	cacheEnabled, _ := pkc.Enabled.GetOrDefault(ctx, g)
	cacheTTL, _ := pkc.TTL.GetOrDefault(ctx, g)
	cacheMaxTTL, _ := pkc.MaxTTL.GetOrDefault(ctx, g)
	cacheCleanup, _ := pkc.CleanupInterval.GetOrDefault(ctx, g)
	cacheTTLBufferPercent, _ := pkc.TTLBufferPercent.GetOrDefault(ctx, g)
	cacheProactiveRefresh, _ := pkc.ProactiveRefreshEnabled.GetOrDefault(ctx, g)
	cacheRefreshIntervalPercent, _ := pkc.RefreshIntervalPercent.GetOrDefault(ctx, g)
	cacheMinRefreshInterval, _ := pkc.MinRefreshInterval.GetOrDefault(ctx, g)
	cacheRefreshTimeout, _ := pkc.RefreshTimeout.GetOrDefault(ctx, g)
	sessionPersistence, _ := sess.PersistenceEnabled.GetOrDefault(ctx, g)
	sessionHeaderName, _ := sess.HeaderName.GetOrDefault(ctx, g)

	parsed.GlobalRPS = float64(globalRate.Limit)
	parsed.GlobalBurst = globalRate.Burst
	parsed.WorkflowOwnerRPS = float64(ownerRate.Limit)
	parsed.WorkflowOwnerBurst = ownerRate.Burst
	parsed.MaxRetries = maxRetries
	parsed.RetryBackoffSeconds = int(retryBackoff / time.Second)
	parsed.EnableSecretsCache = secretsCacheEnabled
	parsed.EnclaveRequestTimeout = enclaveRequestTimeout
	parsed.PublicKeyRequestTimeout = publicKeyRequestTimeout
	parsed.InsecureSkipTLSVerify = insecureSkipTLSVerify
	parsed.EnclaveRefreshInterval = enclaveRefreshInterval
	parsed.CacheConfig = enclaveclient.CacheConfig{
		EnableCache:            cacheEnabled,
		DefaultTTL:             cacheTTL,
		MaxTTL:                 cacheMaxTTL,
		CleanupInterval:        cacheCleanup,
		TTLBufferPercent:       cacheTTLBufferPercent,
		EnableProactiveRefresh: cacheProactiveRefresh,
		RefreshIntervalPercent: cacheRefreshIntervalPercent,
		MinRefreshInterval:     cacheMinRefreshInterval,
		RefreshTimeout:         cacheRefreshTimeout,
	}
	parsed.SessionConfig = enclaveclient.SessionConfig{
		EnableSessionPersistence: sessionPersistence,
		SessionHeaderName:        sessionHeaderName,
	}

	// Deprecated job-spec overrides, retained during migration.
	cfg := parsed.Config
	if cfg.GlobalRPS != nil {
		parsed.GlobalRPS = *cfg.GlobalRPS
	}
	if cfg.GlobalBurst != nil {
		parsed.GlobalBurst = *cfg.GlobalBurst
	}
	if cfg.WorkflowOwnerRPS != nil {
		parsed.WorkflowOwnerRPS = *cfg.WorkflowOwnerRPS
	}
	if cfg.WorkflowOwnerBurst != nil {
		parsed.WorkflowOwnerBurst = *cfg.WorkflowOwnerBurst
	}
	if cfg.MaxRetries != nil {
		parsed.MaxRetries = *cfg.MaxRetries
	}
	if cfg.RetryBackoffSeconds != nil {
		parsed.RetryBackoffSeconds = *cfg.RetryBackoffSeconds
	}
	if cfg.EnableSecretsCache != nil {
		parsed.EnableSecretsCache = *cfg.EnableSecretsCache
	}
	if cfg.EnclaveRequestTimeoutSeconds != nil {
		parsed.EnclaveRequestTimeout = time.Duration(*cfg.EnclaveRequestTimeoutSeconds) * time.Second
	}
	if cfg.PublicKeyRequestTimeoutSeconds != nil {
		parsed.PublicKeyRequestTimeout = time.Duration(*cfg.PublicKeyRequestTimeoutSeconds) * time.Second
	}
	if cfg.InsecureSkipTLSVerify != nil {
		parsed.InsecureSkipTLSVerify = *cfg.InsecureSkipTLSVerify
	}
	if cfg.EnclaveRefreshIntervalSeconds != nil {
		parsed.EnclaveRefreshInterval = time.Duration(*cfg.EnclaveRefreshIntervalSeconds) * time.Second
	}
	if cfg.EnableCache != nil {
		parsed.CacheConfig.EnableCache = *cfg.EnableCache
	}
	if cfg.CacheTTLSeconds != nil {
		parsed.CacheConfig.DefaultTTL = time.Duration(*cfg.CacheTTLSeconds) * time.Second
	}
	if cfg.CacheMaxTTLSeconds != nil {
		parsed.CacheConfig.MaxTTL = time.Duration(*cfg.CacheMaxTTLSeconds) * time.Second
	}
	if cfg.CacheCleanupSeconds != nil {
		parsed.CacheConfig.CleanupInterval = time.Duration(*cfg.CacheCleanupSeconds) * time.Second
	}
	if cfg.CacheTTLBufferPercent != nil {
		parsed.CacheConfig.TTLBufferPercent = *cfg.CacheTTLBufferPercent
	}
	if cfg.EnableProactiveRefresh != nil {
		parsed.CacheConfig.EnableProactiveRefresh = *cfg.EnableProactiveRefresh
	}
	if cfg.RefreshIntervalPercent != nil {
		parsed.CacheConfig.RefreshIntervalPercent = *cfg.RefreshIntervalPercent
	}
	if cfg.MinRefreshIntervalSeconds != nil {
		parsed.CacheConfig.MinRefreshInterval = time.Duration(*cfg.MinRefreshIntervalSeconds) * time.Second
	}
	if cfg.RefreshTimeoutSeconds != nil {
		parsed.CacheConfig.RefreshTimeout = time.Duration(*cfg.RefreshTimeoutSeconds) * time.Second
	}
	if cfg.EnableSessionPersistence != nil {
		parsed.SessionConfig.EnableSessionPersistence = *cfg.EnableSessionPersistence
	}
	if cfg.SessionHeaderName != nil {
		parsed.SessionConfig.SessionHeaderName = *cfg.SessionHeaderName
	}
}

// getCapConfig returns the current parsed config snapshot. The pointer is
// swapped wholesale on refresh, so callers read a consistent, immutable snapshot.
func (e *RealExecutor) getCapConfig() *ParsedConfig {
	e.capConfigMu.RLock()
	defer e.capConfigMu.RUnlock()
	return e.capConfig
}

// setCapConfig atomically swaps in a new parsed config snapshot.
func (e *RealExecutor) setCapConfig(parsed *ParsedConfig) {
	e.capConfigMu.Lock()
	defer e.capConfigMu.Unlock()
	e.capConfig = parsed
}

// refreshLimitSettings re-resolves the CRE limits framework values and swaps in
// a fresh config snapshot.
func (e *RealExecutor) refreshLimitSettings(ctx context.Context) {
	cur := e.getCapConfig()
	if cur == nil {
		return
	}
	next := *cur
	e.applyLimitSettings(ctx, &next)
	e.setCapConfig(&next)
}

// RealExecutor is the concrete implementation of the Executor interface.
type RealExecutor struct {
	lggr                       logger.Logger
	metrics                    types.Emitter
	enclaveClient              enclaveclient.EnclaveClient
	vaultDON                   VaultDON
	keystore                   core.Keystore
	rateLimiter                *ratelimit.RateLimiter
	capabilityID               string
	secretsCache               *util.Cache[*cachedEDKS]
	confidentialComputeVersion string
	apiKey                     string
	limitsFactory              limits.Factory

	// quorumTimeoutIsUserError classifies an enclave quorum timeout as a public
	// user error when true, or as an internal/node error (retried) when false.
	// Set per-capability at construction.
	quorumTimeoutIsUserError bool

	// Lazy initialization fields for the executor itself
	initializedMutex   sync.Mutex
	initialized        bool
	capConfigRaw       string
	capConfigMu        sync.RWMutex
	capConfig          *ParsedConfig
	capabilityRegistry core.CapabilitiesRegistry
	nodeID             string
	proposalInFlight   atomic.Bool
	donMu              sync.RWMutex
	donMembers         [][]byte
	donF               uint32
	enclaves           []types.Enclave

	// Background enclave-refresh ticker, started once on init and stopped on Close.
	refreshCancel context.CancelFunc
	refreshDone   chan struct{}
}

type cachedEDKS struct {
	encryptedSecret           []byte
	encryptedDecryptionShares [][]byte
}

func NewRealExecutor(
	lggr logger.Logger,
	capDependencies core.StandardCapabilitiesDependencies,
	capabilityID string,
	confidentialComputeVersion string,
	limitsFactory limits.Factory,
	quorumTimeoutIsUserError bool,
) *RealExecutor {
	return &RealExecutor{
		lggr:                       lggr,
		keystore:                   capDependencies.P2PKeystore,
		capabilityRegistry:         capDependencies.CapabilityRegistry,
		capConfigRaw:               capDependencies.Config,
		capabilityID:               capabilityID,
		confidentialComputeVersion: confidentialComputeVersion,
		secretsCache:               util.NewCache[*cachedEDKS](nil, nil),
		limitsFactory:              limitsFactory,
		quorumTimeoutIsUserError:   quorumTimeoutIsUserError,
	}
}

// A test-only constructor that returns a RealExecutor with its dependencies set.
// This alternative constructor exists because the standard constructor relies on a real enclave pool,
// in its initialization logic, which indirectly requires real attestation validation.
func NewTestExecutor(
	lggr logger.Logger,
	keystore core.Keystore,
	enclaveClient enclaveclient.EnclaveClient,
	vaultDON VaultDON,
	metrics types.Emitter,
	ratelimiter *ratelimit.RateLimiter,
	maxRetries int,
	retryBackoffSeconds int,
	capabilityID string,
	enableSecretsCache bool,
	nodeID string,
	capabilityRegistry core.CapabilitiesRegistry,
) *RealExecutor {
	return NewTestExecutorWithGate(lggr, keystore, enclaveClient, vaultDON, metrics, ratelimiter, maxRetries, retryBackoffSeconds, capabilityID, enableSecretsCache, nodeID, capabilityRegistry)
}

func NewTestExecutorWithGate(
	lggr logger.Logger,
	keystore core.Keystore,
	enclaveClient enclaveclient.EnclaveClient,
	vaultDON VaultDON,
	metrics types.Emitter,
	ratelimiter *ratelimit.RateLimiter,
	maxRetries int,
	retryBackoffSeconds int,
	capabilityID string,
	enableSecretsCache bool,
	nodeID string,
	capabilityRegistry core.CapabilitiesRegistry,
) *RealExecutor {
	localNode, err := capabilityRegistry.LocalNode(context.Background())
	if err != nil {
		panic(fmt.Sprintf("failed to get local node in test executor: %v", err))
	}
	return &RealExecutor{
		lggr:               lggr,
		keystore:           keystore,
		enclaveClient:      enclaveClient,
		vaultDON:           vaultDON,
		rateLimiter:        ratelimiter,
		metrics:            metrics,
		capabilityRegistry: capabilityRegistry,
		capConfig: &ParsedConfig{
			MaxRetries:          maxRetries,
			RetryBackoffSeconds: retryBackoffSeconds,
			EnableSecretsCache:  enableSecretsCache,
		},
		initialized:              true,
		capabilityID:             capabilityID,
		secretsCache:             util.NewCache[*cachedEDKS](nil, nil),
		nodeID:                   nodeID,
		donMembers:               peerIDsToSortedBytes(localNode.WorkflowDON.Members),
		donF:                     uint32(localNode.WorkflowDON.F),
		limitsFactory:            limits.Factory{},
		quorumTimeoutIsUserError: true,
	}
}

// SetLimitsFactoryForTesting overrides the limits.Factory used by the executor
// for cresettings lookups. Test-only seam; production callers should plumb
// the factory through NewRealExecutor.
func (e *RealExecutor) SetLimitsFactoryForTesting(f limits.Factory) {
	e.limitsFactory = f
}

// SetParsedConfigForTesting sets capConfig for unit tests that exercise timeout
// resolution without full executor initialization.
func (e *RealExecutor) SetParsedConfigForTesting(parsed *ParsedConfig) {
	e.setCapConfig(parsed)
}

// ApplyLimitSettingsForTesting exposes applyLimitSettings for unit tests.
func (e *RealExecutor) ApplyLimitSettingsForTesting(ctx context.Context, parsed *ParsedConfig) {
	e.applyLimitSettings(ctx, parsed)
}

// ResolveRequestTimeoutForTesting exposes resolveRequestTimeout for unit tests.
func (e *RealExecutor) ResolveRequestTimeoutForTesting(ctx context.Context, publicKey bool) (time.Duration, error) {
	return e.resolveRequestTimeout(ctx, publicKey)
}

// Takes a bytes serialized protobuf message as input, and returns a bytes serialized protobuf message as output.
type Executor interface {
	// Initialize performs the executor's one-time setup (config parsing, API
	// key decryption, enclave pool population, HTTP client, etc.). Idempotent
	// and concurrency-safe; subsequent calls are no-ops. Should be called from
	// the capability's Initialise so that enclaves are available before any
	// ProvidedTees or Execute call.
	Initialize(ctx context.Context) error
	Execute(ctx context.Context, protoBytes []byte, secrets []*framework.SecretIdentifier, metadata capabilities.RequestMetadata) ([]byte, error)
	GetEnclaves() []types.Enclave
	// Close releases the executor's background resources (e.g. the enclave-refresh loop).
	Close() error
}

// Check that RealExecutor implements the Executor interface.
var _ Executor = (*RealExecutor)(nil)

func (e *RealExecutor) Execute(ctx context.Context, protoBytes []byte, secrets []*framework.SecretIdentifier, metadata capabilities.RequestMetadata) (output []byte, err error) {
	executionStart := time.Now()

	if err := e.initLazily(ctx); err != nil {
		return nil, err
	}

	// Re-resolve the CRE limits on every run so config changes take effect
	// without re-initializing the executor.
	e.refreshLimitSettings(ctx)

	runLggr := logger.With(e.lggr,
		"workflowID", sanitizeLogString(metadata.WorkflowID),
		"executionID", sanitizeLogString(metadata.WorkflowExecutionID),
		"workflowName", sanitizeLogString(metadata.WorkflowName),
		"workflowOwner", sanitizeLogString(metadata.WorkflowOwner),
		"orgID", sanitizeLogString(metadata.OrgID),
	)

	// Create a scoped emitter with request-level defaults. These labels ride on
	// every enclave metric so confidential workflows can be sliced by workflow
	// and org, matching the DON-mode base labels (workflowName/workflowOwner/orgID).
	// sdk is not available at this layer (not on RequestMetadata), so it is omitted.
	metrics := NewScopedEmitter(e.metrics, map[string]any{
		"node.id":        e.nodeID,
		"workflow.owner": metadata.WorkflowOwner,
		"workflow.id":    metadata.WorkflowID,
		"workflow.name":  metadata.WorkflowName,
		"org.id":         metadata.OrgID,
	})

	// Empty until enclave params are fetched.
	var enclaveIDStr string

	// Emit the total request duration on every exit, success or error. The outcome attribute
	// distinguishes the two.
	defer func() {
		details := map[string]any{
			"duration_seconds": time.Since(executionStart).Seconds(),
			"outcome":          "success",
		}
		if err != nil {
			details["outcome"] = "error"
		}
		if enclaveIDStr != "" {
			details["enclave.id"] = enclaveIDStr
		}
		metrics.Emit("execute_total", details)
	}()

	if !e.rateLimiter.Allow(metadata.WorkflowOwner) {
		runLggr.Warnw("rate limit exceeded")
		metrics.Emit("rate_limit_exceeded", nil)
		return nil, fmt.Errorf("rate limit exceeded for workflow owner %s", sanitizeLogString(metadata.WorkflowOwner))
	}

	runLggr.Debugw("executing")
	metrics.Emit("requests_received_total", nil)

	var enclaveParamsDuration time.Duration
	var vaultDONDuration time.Duration
	var enclaveExecuteDuration time.Duration
	var executeResponses []types.ExecuteResponse

	// Retry logic covering EnclaveParams fetching, VaultDON, and enclave execution
	retryIndex := 0
	vaultDONRequestSent := false
	workflowExecutionID := metadata.WorkflowExecutionID
	reqID := sha256.Sum256([]byte(workflowExecutionID))
	reqIDHex := hex.EncodeToString(reqID[:])

	runLggr = logger.With(runLggr, "reqID", reqIDHex)
	runLggr.Debugw("computed request ID",
		"inputLen", len(protoBytes),
		"secretCount", len(secrets))
	err = e.retryWithBackoff(ctx, func() error {
		// Only update our Vault DON request reference ID if we actually sent a Vault DON request in the last try.
		if vaultDONRequestSent {
			retryIndex++
			metadata.ReferenceID = fmt.Sprintf(retryTemplate, strconv.FormatInt(int64(retryIndex), 10))
		}
		vaultDONRequestSent = false

		err := e.EnsureFreshEnclaves(ctx)
		if err != nil {
			return fmt.Errorf("failed to ensure fresh enclaves: %w", err)
		}

		runLggr.Debugw("fetching enclave params")
		enclaveParamsStart := time.Now()
		enclaveParams, err := e.getEnclaveParams(ctx, reqID, metrics)
		enclaveParamsDuration = time.Since(enclaveParamsStart)

		if err != nil {
			runLggr.Warnw("enclave params fetch failed",
				"duration_ms", enclaveParamsDuration.Milliseconds(),
				"error", err)
			metrics.Emit("enclave_params_error", map[string]any{
				"duration_seconds": enclaveParamsDuration.Seconds(),
			})
			return fmt.Errorf("failed to get enclave params: %w", err)
		} else {
			enclaveIDStr = hex.EncodeToString(enclaveParams.EnclaveID[:])
		}

		// Create an inner logger for operations that know the enclave ID
		innerLggr := logger.With(runLggr, "enclaveID", enclaveIDStr)
		innerLggr.Debugw("enclave params fetched",
			"ephemeralPKLen", len(enclaveParams.EnclaveEphemeralPublicKey),
			"duration_ms", enclaveParamsDuration.Milliseconds())

		// Get encrypted decryption shares from VaultDON
		vaultDONRequestSent = true
		vaultDONAttemptStart := time.Now()
		encryptedSecrets, encryptedDecryptionShares, err := e.GetEncryptedDecryptionShares(
			ctx,
			secrets,
			enclaveParams.EnclaveEphemeralPublicKey,
			metadata,
			metrics)
		if err != nil {
			vaultDONErrDuration := time.Since(vaultDONAttemptStart)
			innerLggr.Warnw("VaultDON request failed",
				"duration_ms", vaultDONErrDuration.Milliseconds(),
				"error", err)
			metrics.Emit("vault_don_error", map[string]any{
				"duration_seconds": vaultDONErrDuration.Seconds(),
			})
			return fmt.Errorf("failed to get encrypted decryption key shares from VaultDON: %w", err)
		}
		vaultDONDuration = time.Since(vaultDONAttemptStart)
		innerLggr.Debugw("VaultDON shares retrieved",
			"secretCount", len(secrets),
			"duration_ms", vaultDONDuration.Milliseconds())

		inputCiphertextNames := make([]string, 0, len(secrets))
		for _, secret := range secrets {
			inputCiphertextNames = append(inputCiphertextNames, secret.Key)
		}

		if protoBytes == nil {
			return errors.New("input cannot be nil")
		}

		computeReq := types.ComputeRequest{
			RequestID:                    reqID,
			ApplicationRequestID:         workflowExecutionID,
			PublicData:                   protoBytes,
			Ciphertexts:                  encryptedSecrets,
			CiphertextNames:              inputCiphertextNames,
			EnclaveEphemeralPublicKey:    enclaveParams.EnclaveEphemeralPublicKey,
			EncryptedDecryptionKeyShares: encryptedDecryptionShares,
			AppID:                        e.capabilityID,
			Version:                      e.confidentialComputeVersion,
		}
		innerLggr.Debugw("signing compute request",
			"appID", e.capabilityID,
			"publicDataLen", len(protoBytes),
			"ciphertextCount", len(encryptedSecrets))
		signedComputeReq, err := e.SignComputeRequest(ctx, computeReq)
		if err != nil {
			innerLggr.Errorw("compute request signing failed",
				"error", err)
			metrics.Emit("compute_request_signature_error", nil)
			return fmt.Errorf("failed to sign compute request: %w", err)
		}

		innerLggr.Debugw("dispatching to enclave")
		enclaveExecuteStart := time.Now()
		executeResponses, err = e.enclaveClient.ExecuteBatch(ctx, []types.SignedComputeRequest{*signedComputeReq}, [][32]byte{enclaveParams.EnclaveID})
		if err != nil {
			enclaveExecuteErrDuration := time.Since(enclaveExecuteStart)
			if strings.Contains(err.Error(), types.ErrQuorumTimeout) {
				metrics.Emit("quorum_timeout", map[string]any{
					"enclave.id":       base64.StdEncoding.EncodeToString(enclaveParams.EnclaveID[:]),
					"workflow.id":      metadata.WorkflowID,
					"duration_seconds": enclaveExecuteErrDuration.Seconds(),
				})
				// When quorumTimeoutIsUserError is disabled, surface the timeout as an
				// internal/node error so it is retried and does not count against the user.
				if e.quorumTimeoutIsUserError {
					return caperrors.NewPublicUserError(fmt.Errorf("enclave quorum timeout: %w", err), caperrors.DeadlineExceeded)
				}
				return fmt.Errorf("enclave quorum timeout: %w", err)
			}
			if strings.Contains(err.Error(), types.ErrEncryptionRequestedNoKey) ||
				strings.Contains(err.Error(), types.ErrKeyPresentNoEncryption) ||
				strings.Contains(err.Error(), types.ErrResponseBodyTooLarge) {
				return caperrors.NewPublicUserError(fmt.Errorf("enclave request failed: %w", err), caperrors.InvalidArgument)
			}
			innerLggr.Warnw("enclave execution failed",
				"duration_ms", enclaveExecuteErrDuration.Milliseconds(),
				"error", err)
			metrics.Emit("execute_error", map[string]any{
				"enclave.id":       base64.StdEncoding.EncodeToString(enclaveParams.EnclaveID[:]),
				"duration_seconds": enclaveExecuteErrDuration.Seconds(),
			})
			return fmt.Errorf("failed to execute enclave request. enclave ID: %s, error: %w", base64.StdEncoding.EncodeToString(enclaveParams.EnclaveID[:]), err)
		}
		enclaveExecuteDuration = time.Since(enclaveExecuteStart)
		innerLggr.Debugw("enclave execution succeeded",
			"duration_ms", enclaveExecuteDuration.Milliseconds())

		if executeResponses[0].AttestationFallbackUsed {
			innerLggr.Warnw("attestation validation used fallback measurements",
				"endpoint", "execute")
			metrics.Emit("attestation_validation_fallback_used", map[string]any{
				"endpoint":   "execute",
				"enclave.id": enclaveIDStr,
			})
		}

		if err := e.validateEnclaveSigners(executeResponses[0].Config); err != nil {
			return fmt.Errorf("execute response config validation failed for request %x: %w", reqID, err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(executeResponses) != 1 {
		return nil, fmt.Errorf("expected one enclave response, got %d", len(executeResponses))
	}

	// Forward enclave metrics through OTel.
	// Add a component tag so enclave metrics can be filtered without encoding
	// enclave into the metric name itself.
	enclaveMetrics := metrics.WithDefaults(map[string]any{
		"component":  "enclave",
		"enclave.id": enclaveIDStr,
	})
	// Prefer the ordered MetricEvents list: it preserves repeated events (e.g. one
	// capability_execution per call) so counts and histogram samples are correct.
	// Fall back to the Metrics map only for older enclaves that don't send the list.
	runLggr.Debugw("forwarding enclave observability events",
		"enclave.id", enclaveIDStr,
		"metric_events", len(executeResponses[0].MetricEvents),
		"metrics_map", len(executeResponses[0].Metrics),
		"workflow_execution_id", metadata.WorkflowExecutionID)
	if len(executeResponses[0].MetricEvents) > 0 {
		for _, ev := range executeResponses[0].MetricEvents {
			runLggr.Debugw("re-emitting enclave event", "event", ev.Event, "details", ev.Details)
			enclaveMetrics.Emit(ev.Event, ev.Details)
			switch ev.Event {
			case "user_log":
				msg, ok := ev.Details["message"].(string)
				runLggr.Debugw("emitting user_log beholder event", "ok", ok, "msg", msg)
				if ok {
					emitUserLog(ctx, runLggr, metadata, msg)
				}
			case "capability_started":
				capID, _ := ev.Details["capability_id"].(string)
				method, _ := ev.Details["method"].(string)
				stepRef := detailInt32(ev.Details, "step_ref")
				runLggr.Debugw("emitting capability_started beholder event", "capability_id", capID, "method", method, "step_ref", stepRef)
				emitCapabilityStarted(ctx, runLggr, metadata, capID, method, stepRef)
			case "capability_finished":
				capID, _ := ev.Details["capability_id"].(string)
				method, _ := ev.Details["method"].(string)
				success, _ := ev.Details["success"].(bool)
				errMsg, _ := ev.Details["error"].(string)
				stepRef := detailInt32(ev.Details, "step_ref")
				runLggr.Debugw("emitting capability_finished beholder event", "capability_id", capID, "method", method, "step_ref", stepRef, "success", success, "error", errMsg)
				emitCapabilityFinished(ctx, runLggr, metadata, capID, method, stepRef, success, errMsg)
			}
		}
	} else if executeResponses[0].Metrics != nil {
		runLggr.Debugw("no MetricEvents list; falling back to Metrics map", "count", len(executeResponses[0].Metrics))
		for eventName, details := range executeResponses[0].Metrics {
			detailsMap, ok := details.(map[string]any)
			if !ok {
				runLggr.Warnw("enclave metric details is not a map", "event", eventName)
				continue
			}
			enclaveMetrics.Emit(eventName, detailsMap)
		}
	} else {
		runLggr.Warnw("enclave response carried no observability events",
			"enclave.id", enclaveIDStr,
			"workflow_execution_id", metadata.WorkflowExecutionID)
	}

	totalExecutionDuration := time.Since(executionStart)

	runLggr.Infow("execution complete",
		"attestation", executeResponses[0].Attestation,
		"total_duration_ms", totalExecutionDuration.Milliseconds(),
		"vault_don_duration_ms", vaultDONDuration.Milliseconds(),
		"enclave_execute_duration_ms", enclaveExecuteDuration.Milliseconds(),
		"enclave_params_duration_ms", enclaveParamsDuration.Milliseconds())

	enclaveMetrics.Emit("requests_completed_total", nil)
	// execute_total is emitted by the deferred call above (success or error).

	return executeResponses[0].Output, nil
}

// Initialize is the exported entry point; see the Executor interface for semantics.
func (e *RealExecutor) Initialize(ctx context.Context) error {
	return e.initLazily(ctx)
}

func (e *RealExecutor) initLazily(ctx context.Context) error {
	e.initializedMutex.Lock()
	defer e.initializedMutex.Unlock()
	if e.initialized {
		return nil
	}

	e.lggr.Infow("initializing executor", "capabilityID", e.capabilityID)
	e.metrics = NewMetricsEmitter(e.capabilityID, e.lggr)
	parsedConfig, err := ParseConfig(e.capConfigRaw)
	if err != nil {
		return fmt.Errorf("failed to parse capability config: %w", err)
	}
	// Overlay the rate limits, retry policy, and secrets-cache toggle from the
	// CRE limits framework. Limits are the source of truth; an explicitly-set
	// job-spec Config field still wins for backward compatibility during
	// migration.
	e.applyLimitSettings(ctx, parsedConfig)
	rateLimiter, err := ratelimit.NewRateLimiter(ratelimit.RateLimiterConfig{
		GlobalRPS:      parsedConfig.GlobalRPS,
		GlobalBurst:    parsedConfig.GlobalBurst,
		PerSenderRPS:   parsedConfig.WorkflowOwnerRPS,
		PerSenderBurst: parsedConfig.WorkflowOwnerBurst,
	})
	if err != nil {
		return fmt.Errorf("failed to create rate limiter: %w", err)
	}

	// We pull an API key from the job spec, encrypted under the workflow key of each respective node. This is for lower-level auth with our hosted enclaves.
	if parsedConfig.Config.EncryptedAPIKeys != "" {
		accounts, err := e.keystore.Accounts(ctx)
		if err != nil {
			return fmt.Errorf("failed to get accounts from keystore: %w", err)
		}
		if len(accounts) == 0 {
			return errors.New("no accounts found in keystore")
		}

		var acct string
		for _, a := range accounts {
			if a == core.StandardCapabilityAccount {
				acct = a
				break
			}
		}
		if acct == "" {
			return fmt.Errorf("no %s account found in keystore", core.StandardCapabilityAccount)
		}

		keys := strings.Split(parsedConfig.Config.EncryptedAPIKeys, ",")
		var apiKeyFound bool
		var decryptErrs []error
		for _, key := range keys {
			keyCtxt, err := hex.DecodeString(key)
			if err != nil {
				return fmt.Errorf("failed to decode hex-encoded encrypted API key: %w", err)
			}
			key, err := e.keystore.Decrypt(ctx, acct, keyCtxt)
			if err != nil {
				decryptErrs = append(decryptErrs, fmt.Errorf("failed to decrypt API key: %w", err))
				continue
			} else {
				e.apiKey = string(key)
				apiKeyFound = true
				break
			}
		}
		if !apiKeyFound {
			return fmt.Errorf("failed to decrypt any provided API keys: %v", decryptErrs)
		}
	}

	localNode, ownCapabilityConfig, err := e.getLocalNodeAndCapConfig(ctx)
	if err != nil {
		return err
	}

	nodes, err := GetEnclaveNodes(ctx, ownCapabilityConfig, parsedConfig.Config, e.apiKey)
	if err != nil {
		return fmt.Errorf("failed to create enclave pool: %w", err)
	}
	e.lggr.Infow("enclave nodes loaded", "nodeCount", len(nodes))
	sortEnclaveNodes(nodes)

	httpClient := &http.Client{}
	if parsedConfig.InsecureSkipTLSVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// Per-call timeouts are resolved by the executor's RequestTimeout callback.
	pool, err := enclaveclient.NewPoolWithConfig(nodes, nil, httpClient, enclaveclient.PoolConfig{
		Cache:                    parsedConfig.CacheConfig,
		Session:                  parsedConfig.SessionConfig,
		Metrics:                  e.metrics,
		Logger:                   e.lggr,
		RequestTimeoutResolverFn: e.newRequestTimeoutResolver(),
	})
	if err != nil {
		return fmt.Errorf("failed to create enclave pool: %w", err)
	}

	vaultDONCapability, err := e.capabilityRegistry.GetExecutable(ctx, vault.CapabilityID)
	if err != nil {
		return fmt.Errorf("failed to get VaultDON capability with ID '%s' from registry: %w", vault.CapabilityID, err)
	}
	vaultDONPossibleFaultyNodes, err := getVaultDONPossibleFaultyNodes(ctx, vaultDONCapability, int(localNode.WorkflowDON.F))
	if err != nil {
		return fmt.Errorf("failed to get VaultDON possible faulty nodes: %w", err)
	}

	e.enclaveClient = pool
	e.enclaves = nodes
	e.rateLimiter = rateLimiter
	e.setCapConfig(parsedConfig)
	e.vaultDON = VaultDON{
		CryptographyThreshold: getVaultDONThreshold(vaultDONPossibleFaultyNodes),
		Capability:            vaultDONCapability,
	}
	e.proposeConfigUpdateIfMembershipChanged(ctx, peerIDsToSortedBytes(localNode.WorkflowDON.Members), uint32(localNode.WorkflowDON.F))

	e.initialized = true
	e.startEnclaveRefreshLoop()
	e.lggr.Infow("executor initialized",
		"capabilityID", e.capabilityID,
		"nodeID", e.nodeID,
		"maxRetries", parsedConfig.MaxRetries,
		"retryBackoffSeconds", parsedConfig.RetryBackoffSeconds,
		"enableSecretsCache", parsedConfig.EnableSecretsCache,
		"vaultDONThreshold", e.vaultDON.CryptographyThreshold,
		"insecureSkipTLS", parsedConfig.InsecureSkipTLSVerify)
	return nil
}

// startEnclaveRefreshLoop launches a background ticker that periodically refreshes
// enclaves and re-checks DON membership, so config-update proposals fire on a timer
// rather than only while handling a request. Called once from initLazily.
func (e *RealExecutor) startEnclaveRefreshLoop() {
	interval := e.getCapConfig().EnclaveRefreshInterval
	ctx, cancel := context.WithCancel(context.Background())
	e.refreshCancel = cancel
	e.refreshDone = make(chan struct{})

	go func() {
		defer close(e.refreshDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := e.EnsureFreshEnclaves(ctx); err != nil {
					e.lggr.Warnw("background enclave refresh failed", "error", err)
				}
			}
		}
	}()
}

// Close stops the background enclave-refresh loop.
func (e *RealExecutor) Close() error {
	e.initializedMutex.Lock()
	cancel := e.refreshCancel
	done := e.refreshDone
	e.refreshCancel = nil
	e.initializedMutex.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}
	return nil
}

func (e *RealExecutor) EnsureFreshEnclaves(ctx context.Context) error {
	localNode, ownCapabilityConfig, err := e.getLocalNodeAndCapConfig(ctx)
	if err != nil {
		return err
	}

	nodes, err := GetEnclaveNodes(ctx, ownCapabilityConfig, e.getCapConfig().Config, e.apiKey)
	if err != nil {
		return fmt.Errorf("failed to create enclave pool: %w", err)
	}

	sortEnclaveNodes(nodes)
	e.enclaveClient.UpdateNodes(nodes)
	e.enclaves = nodes

	vaultDONPossibleFaultyNodes, err := getVaultDONPossibleFaultyNodes(ctx, e.vaultDON.Capability, int(localNode.WorkflowDON.F))
	if err != nil {
		return fmt.Errorf("failed to get VaultDON possible faulty nodes: %w", err)
	}
	e.vaultDON.CryptographyThreshold = getVaultDONThreshold(vaultDONPossibleFaultyNodes)

	newMembers := peerIDsToSortedBytes(localNode.WorkflowDON.Members)
	newF := uint32(localNode.WorkflowDON.F)
	e.proposeConfigUpdateIfMembershipChanged(ctx, newMembers, newF)

	return nil
}

func (e *RealExecutor) getDONMembership() (members [][]byte, f uint32) {
	e.donMu.RLock()
	defer e.donMu.RUnlock()
	return e.donMembers, e.donF
}

func (e *RealExecutor) setDONMembership(members [][]byte, f uint32) {
	e.donMu.Lock()
	defer e.donMu.Unlock()
	e.donMembers = members
	e.donF = f
}

func (e *RealExecutor) proposeConfigUpdateIfMembershipChanged(ctx context.Context, newMembers [][]byte, newF uint32) {
	curMembers, curF := e.getDONMembership()
	// With a recorded baseline, skip the enclave round-trip while membership is unchanged.
	// An empty baseline means we have not yet reconciled against the enclaves (fresh boot, or a
	// membership change that happened while offline), so fall through and reconcile against their
	// actual config until a baseline is recorded.
	if len(curMembers) > 0 && newF == curF && slices.EqualFunc(newMembers, curMembers, bytes.Equal) {
		return
	}

	if len(curMembers) > 0 {
		e.lggr.Infow("DON membership changed, proposing enclave config update",
			"oldMemberCount", len(curMembers), "newMemberCount", len(newMembers), "newF", newF)
	}

	if err := e.broadcastConfigUpdate(ctx, newMembers, newF); err != nil {
		e.lggr.Warnw("enclave config update proposal failed", "error", err)
		if e.metrics != nil {
			e.metrics.Emit("config_update_proposal_failed", map[string]any{"error": err.Error()})
		}
		return
	}
}

// broadcastConfigUpdate builds the proposed config from the new membership, signs it, and broadcasts the vote.
func (e *RealExecutor) broadcastConfigUpdate(ctx context.Context, newMembers [][]byte, newF uint32) error {
	if !e.proposalInFlight.CompareAndSwap(false, true) {
		e.lggr.Debugw("config update proposal already in flight, skipping")
		return nil
	}
	defer e.proposalInFlight.Store(false)
	newMembers = sortedBytesCopy(newMembers)

	enclaveConfigs, err := e.enclaveClient.GetConfigs(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch current enclave config: %w", err)
	}
	if len(enclaveConfigs) == 0 {
		return errors.New("no enclave configs available to read current config")
	}
	var configsMatch bool
	currentConfig := enclaveConfigs[0]
	for i, enclaveConfig := range enclaveConfigs {
		h := enclaveConfig.Hash()
		e.lggr.Debugw("current enclave config", "index", i, "signers", len(enclaveConfig.Signers),
			"f", enclaveConfig.F, "t", enclaveConfig.T, "hash", base64.StdEncoding.EncodeToString(h[:8]))
		if !bytes.Equal(enclaveConfig.MasterPublicKey, currentConfig.MasterPublicKey) || enclaveConfig.T != currentConfig.T {
			return fmt.Errorf("enclave public key %s has a different master public key or T than the first enclave public key (this should never happen)", base64.StdEncoding.EncodeToString(currentConfig.MasterPublicKey))
		}
		currentMembersInEnclave := sortedBytesCopy(enclaveConfig.Signers)
		if enclaveConfig.F != newF || !slices.EqualFunc(currentMembersInEnclave, newMembers, bytes.Equal) {
			configsMatch = false
			break
		}
		configsMatch = true
	}
	if configsMatch {
		e.lggr.Debugw("current enclave config already matches new membership, skipping update")
		e.setDONMembership(newMembers, newF)
		return nil
	}

	newConfig := types.EnclaveConfig{
		Signers:         newMembers,
		MasterPublicKey: currentConfig.MasterPublicKey,
		T:               currentConfig.T,
		F:               newF,
	}
	configBytes, err := json.Marshal(newConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal proposed enclave config: %w", err)
	}

	hash := newConfig.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputeConfigUpdatePrefix(), hash[:])
	sig, err := e.signWithCapabilityAccount(ctx, prefixedHash)
	if err != nil {
		return fmt.Errorf("failed to sign enclave config update: %w", err)
	}

	if err := e.enclaveClient.UpdateConfig(ctx, types.UpdateConfigRequest{Config: configBytes, Signature: sig}); err != nil {
		return fmt.Errorf("config update broadcast reported errors: %w", err)
	}

	e.lggr.Infow("enclave config update proposal broadcast", "newMemberCount", len(newMembers), "newF", newF)
	if e.metrics != nil {
		e.metrics.Emit("config_update_proposed", map[string]any{"member_count": len(newMembers), "f": newF})
	}
	return nil
}

func (e *RealExecutor) GetEnclaves() []types.Enclave {
	return e.enclaves
}

func (e *RealExecutor) getLocalNodeAndCapConfig(ctx context.Context) (capabilities.Node, capabilities.CapabilityConfiguration, error) {
	localNode, err := e.capabilityRegistry.LocalNode(ctx)
	if err != nil {
		return capabilities.Node{}, capabilities.CapabilityConfiguration{}, fmt.Errorf("failed to get local node: %w", err)
	}
	// Note: This should not be necessary.
	if localNode.PeerID != nil {
		if fresh, ferr := e.capabilityRegistry.NodeByPeerID(ctx, *localNode.PeerID); ferr == nil {
			localNode = fresh
		}
	}
	if localNode.WorkflowDON.ID == 0 {
		return capabilities.Node{}, capabilities.CapabilityConfiguration{}, fmt.Errorf("local node does not have a WorkflowDON ID, cannot initialise confidential http action capability")
	}
	if localNode.PeerID != nil {
		e.nodeID = localNode.PeerID.String()
	}

	ownCapabilityConfig, err := e.capabilityRegistry.ConfigForCapability(ctx, e.capabilityID, localNode.WorkflowDON.ID)
	if err != nil {
		return capabilities.Node{}, capabilities.CapabilityConfiguration{}, fmt.Errorf("failed to get confidential http capability config: %w", err)
	}

	return localNode, ownCapabilityConfig, nil
}

func GetEnclaveNodes(ctx context.Context, selfCapConfig capabilities.CapabilityConfiguration, capConfig Config, apiKey string) ([]types.Enclave, error) {
	var enclavesConfig types.EnclavesList
	err := selfCapConfig.DefaultConfig.UnwrapTo(&enclavesConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding enclaves: %v", err)
	}

	if len(apiKey) > 0 {
		for i := range enclavesConfig.Enclaves {
			enclavesConfig.Enclaves[i].EnclaveAuthHeader = fmt.Sprintf(authHeaderTemplate, apiKey)
		}
	}

	return enclavesConfig.Enclaves, nil
}

func getVaultDONPossibleFaultyNodes(ctx context.Context, vaultDONCapability capabilities.ExecutableCapability, localF int) (int, error) {
	capabilityInfo, err := vaultDONCapability.Info(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get VaultDON capability info: %w", err)
	}
	if capabilityInfo.DON == nil {
		return localF, nil
	}
	return int(capabilityInfo.DON.F), nil
}

func (e *RealExecutor) retryWithBackoff(ctx context.Context, fn func() error) error {
	cfg := e.getCapConfig()
	var errs error
	backoff := time.Duration(cfg.RetryBackoffSeconds) * time.Second
	for i := 0; i < cfg.MaxRetries; i++ {
		err := fn()
		if err == nil {
			if i > 0 {
				e.lggr.Infow("retry succeeded", "attempt", i+1)
			}
			return nil
		}

		// Short-circuit on user-classified errors. A non-deterministic workflow, an invalid
		// vault key, a request-size limit hit — none of these become deterministic, valid, or
		// in-bounds on retry. Retrying burns capability-DON capacity and triples the level=error
		// log volume for issues that need a workflow-author fix, not infrastructure retries.
		// Log at Debugw so log-based system-error scrapes don't pick this up.
		var capErr caperrors.Error
		if errors.As(err, &capErr) && capErr.Origin() == caperrors.OriginUser {
			e.lggr.Debugw("user error returned, skipping remaining retries",
				"attempt", i+1,
				"error_origin", capErr.Origin().String(),
				"error_code", capErr.Code().String(),
				"error", err)
			return err
		}

		errs = errors.Join(errs, err)
		e.lggr.Warnw("attempt failed",
			"attempt", i+1,
			"maxRetries", cfg.MaxRetries,
			"nextBackoff", backoff.String(),
			"error", err)

		select {
		case <-ctx.Done():
			e.lggr.Warnw("context cancelled during retry backoff",
				"attempt", i+1,
				"error", ctx.Err())
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}

	// retries-exhausted is only reachable for system errors now (user errors short-circuit above).
	// Extract origin/code from the joined error for log-based filtering.
	errorOrigin := "Unknown"
	errorCode := "Unknown"
	var finalCapErr caperrors.Error
	if errors.As(errs, &finalCapErr) {
		errorOrigin = finalCapErr.Origin().String()
		errorCode = finalCapErr.Code().String()
	}
	e.lggr.Errorw("all retries exhausted",
		"maxRetries", cfg.MaxRetries,
		"error_origin", errorOrigin,
		"error_code", errorCode,
		"error", errs)
	return fmt.Errorf("failed after %d retries: %w", cfg.MaxRetries, errs)
}

// signWithCapabilityAccount signs an already-prefixed payload with the node's
// standard capability account. Callers apply their own domain separator before
// calling this (e.g. the compute-request prefix vs. the config-update prefix).
func (e *RealExecutor) signWithCapabilityAccount(ctx context.Context, prefixedPayload []byte) ([]byte, error) {
	accounts, err := e.keystore.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, errors.New("no accounts found in keystore")
	}

	var acct string
	for _, a := range accounts {
		if a == core.StandardCapabilityAccount {
			acct = a
			break
		}
	}
	if acct == "" {
		return nil, fmt.Errorf("no %s account found in keystore", core.StandardCapabilityAccount)
	}

	return e.keystore.Sign(ctx, acct, prefixedPayload)
}

func (e *RealExecutor) SignComputeRequest(ctx context.Context, computeRequest types.ComputeRequest) (*types.SignedComputeRequest, error) {
	hash := computeRequest.Hash()
	prefixedHash := types.MakePeerIDSignatureDomainSeparatedPayload(util.GetConfidentialComputePayloadPrefix(), hash[:])
	sig, err := e.signWithCapabilityAccount(ctx, prefixedHash)
	if err != nil {
		return nil, err
	}
	return &types.SignedComputeRequest{
		ComputeRequest: computeRequest,
		Signature:      sig,
	}, nil
}

// checkRequirements builds a types.RequirementsChecker that filters enclaves against req.
// A nil req yields a nil checker, which accepts all enclaves.
func checkRequirements(req *sdk.Requirements) types.RequirementsChecker {
	if req == nil {
		return nil
	}
	return func(enc types.Enclave) bool {
		rh := host.RequirementsHandler{Tee: func(ctx context.Context, tee *sdk.Tee) bool {
			return host.NewTeeProvider(MapEnclaveType(enc.EnclaveType), []string{enc.Region})(tee)
		}}
		return host.CheckRequirements(context.Background(), rh, req)
	}
}

func (e *RealExecutor) getEnclaveParams(ctx context.Context, reqID [32]byte, metrics types.Emitter) (*EnclaveParams, error) {
	reqIDHex := hex.EncodeToString(reqID[:])
	ephemeralPubKeyResponse, err := e.enclaveClient.GetPublicKeys(ctx, reqID, checkRequirements(nil))
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}
	if len(ephemeralPubKeyResponse) == 0 || len(ephemeralPubKeyResponse[0].PublicKeys) == 0 {
		return nil, fmt.Errorf("no enclave public keys found for request %x", reqID)
	}

	e.lggr.Debugw("public key responses received",
		"reqID", reqIDHex,
		"enclaveCount", len(ephemeralPubKeyResponse),
		"pubKeyCount", len(ephemeralPubKeyResponse[0].PublicKeys))

	selectedEnclaveResponse := ephemeralPubKeyResponse[0]

	if err := e.validateEnclaveSigners(selectedEnclaveResponse.Config); err != nil {
		return nil, fmt.Errorf("enclave config validation failed for request %x: %w", reqID, err)
	}
	var mostRecentPubKeyIndex, mostRecentPubKeyCreationTime int64
	for i, time := range selectedEnclaveResponse.CreationTimes {
		if time.UnixMicro() > mostRecentPubKeyCreationTime {
			mostRecentPubKeyIndex = int64(i)
			mostRecentPubKeyCreationTime = time.UnixMicro()
		}
	}
	selectedEphemeralPublicKey := selectedEnclaveResponse.PublicKeys[mostRecentPubKeyIndex]
	selectedEnclaveID := selectedEnclaveResponse.EnclaveID
	if selectedEnclaveResponse.AttestationFallbackUsed {
		e.lggr.Warnw("attestation validation used fallback measurements",
			"endpoint", "publicKeys",
			"enclave.id", hex.EncodeToString(selectedEnclaveID[:]))
		metrics.Emit("attestation_validation_fallback_used", map[string]any{
			"endpoint":   "publicKeys",
			"enclave.id": hex.EncodeToString(selectedEnclaveID[:]),
		})
	}
	e.lggr.Infow("selected enclave public key",
		"reqID", reqIDHex,
		"enclaveID", hex.EncodeToString(selectedEnclaveID[:]),
		"pubKeyIndex", mostRecentPubKeyIndex,
		"pubKeyPrefix", fmt.Sprintf("%x", selectedEphemeralPublicKey[:min(8, len(selectedEphemeralPublicKey))]))
	return &EnclaveParams{
		EnclaveID:                 selectedEnclaveID,
		EnclaveEphemeralPublicKey: selectedEphemeralPublicKey,
	}, nil
}

func generateSecretCacheKey(enclaveEphemeralPublicKey []byte, secret *framework.SecretIdentifier, workflowOwner string) [32]byte {
	owner := workflowOwner
	keyData := fmt.Sprintf("%x-%s-%s-%s", enclaveEphemeralPublicKey, secret.Key, secret.Namespace, owner)
	return sha256.Sum256([]byte(keyData))
}

func (e *RealExecutor) GetEncryptedDecryptionShares(
	ctx context.Context,
	vaultDONSecrets []*framework.SecretIdentifier,
	enclaveEphemeralPublicKey []byte,
	metadata capabilities.RequestMetadata,
	metrics types.Emitter,
) ([][]byte, [][][]byte, error) {
	e.lggr.Debugw("Attempting to get encrypted decrypted shares from VaultDON capability",
		"enclaveEphemeralPublicKey", fmt.Sprintf("%x", enclaveEphemeralPublicKey[:8]))

	// Short circuit Vault DON call if no secrets are required.
	if len(vaultDONSecrets) == 0 {
		e.lggr.Debugw("no secrets required, skipping VaultDON call")
		return nil, nil, nil
	}

	if e.vaultDON.Capability == nil {
		return nil, nil, errors.New("VaultDON capability is not initialized")
	}
	enclaveEphemeralPublicKeyHex := hex.EncodeToString(enclaveEphemeralPublicKey)
	enableSecretsCache := e.getCapConfig().EnableSecretsCache

	// It's technically suboptimal to require all secrets be cached to not send a request,
	// but this is simpler logic and practically just as effective for real users.
	if enableSecretsCache {
		var allSecretsAreCached = true
		for i := range vaultDONSecrets {
			if _, ok := e.secretsCache.Get(generateSecretCacheKey(enclaveEphemeralPublicKey, vaultDONSecrets[i], metadata.WorkflowOwner)); !ok {
				allSecretsAreCached = false
				break
			}
		}
		if allSecretsAreCached {
			encryptedSecrets := make([][]byte, 0, len(vaultDONSecrets))
			encryptedDecryptionShares := make([][][]byte, 0, len(vaultDONSecrets))
			for i := range vaultDONSecrets {
				cachedEDKS, _ := e.secretsCache.Get(generateSecretCacheKey(enclaveEphemeralPublicKey, vaultDONSecrets[i], metadata.WorkflowOwner))
				encryptedSecrets = append(encryptedSecrets, cachedEDKS.encryptedSecret)
				encryptedDecryptionShares = append(encryptedDecryptionShares, cachedEDKS.encryptedDecryptionShares)
			}
			e.lggr.Debugw("All secrets retrieved from cache", "num_secrets", len(vaultDONSecrets))
			metrics.Emit("vault_don_cache_hit", nil)
			return encryptedSecrets, encryptedDecryptionShares, nil
		}
		metrics.Emit("vault_don_cache_miss", nil)
	}

	owner := common.HexToAddress(metadata.WorkflowOwner).String()
	secretRequests := make([]*vault.SecretRequest, len(vaultDONSecrets))
	requestedKeys := make([]string, len(vaultDONSecrets))
	for i, secret := range vaultDONSecrets {
		secretRequests[i] = &vault.SecretRequest{
			Id: &vault.SecretIdentifier{
				Key:       secret.Key,
				Namespace: secret.Namespace,
				Owner:     owner,
			},
			EncryptionKeys: []string{string(enclaveEphemeralPublicKeyHex)},
		}
		requestedKeys[i] = fmt.Sprintf("%s::%s::%s", owner, secret.Namespace, secret.Key)
	}
	vaultDONRequestPayload := &vault.GetSecretsRequest{
		Requests: secretRequests,
	}
	vaultDONInputAny, err := anypb.New(vaultDONRequestPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal VaultDON request payload to Any: %w", err)
	}

	vaultMetadata := metadata
	e.applyPropagatedOrgIDToVault(ctx, &vaultMetadata)
	if err := e.applyWorkflowDONBindingToVault(ctx, &vaultMetadata); err != nil {
		return nil, nil, err
	}

	vaultDONRequest := capabilities.CapabilityRequest{
		Payload:  vaultDONInputAny,
		Method:   vault.MethodGetSecrets,
		Metadata: vaultMetadata,
	}
	e.lggr.Debugw("calling VaultDON",
		"secretCount", len(vaultDONSecrets),
		"requestedKeys", requestedKeys,
		"metadata", vaultMetadata)
	vaultDONResponse, err := e.vaultDON.Capability.Execute(ctx, vaultDONRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to execute VaultDON capability: %w", err)
	}
	e.lggr.Debugw("VaultDON response received", "secretCount", len(vaultDONSecrets))

	var vaultDONOutput vault.GetSecretsResponse
	err = vaultDONResponse.Payload.UnmarshalTo(&vaultDONOutput)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal VaultDON response payload: %w", err)
	}

	encryptedSecrets := make([][]byte, 0)
	encryptedDecryptionShares := make([][][]byte, 0)

	var seenKeys []string
	for responseIndex, resp := range vaultDONOutput.Responses {
		if resp.GetError() != "" {
			innerErr := fmt.Errorf("VaultDON returned an error for secret request at index %d with key %s: %s", responseIndex, resp.GetId().GetKey(), resp.GetError())
			// VaultDON's plugin populates SecretResponse.Error via userFacingError(err, fallback):
			// it returns the user-error message for typed *userError instances, otherwise the fixed
			// fallback string "failed to handle get secret request" for system errors. Anything other
			// than that fallback is a user-facing classification (e.g. "key does not exist",
			// "invalid public key size", policy denials). Classify accordingly so the workflow engine
			// routes these to _user_errors instead of _failures and the system-error alerts stop firing.
			// TODO: replace this string match with a typed origin/code field on SecretResponse.
			// Source: chainlink core ocr2 vault plugin, userFacingError() helper.
			if resp.GetError() == types.ErrVaultSystemErrorFallback {
				return nil, nil, innerErr
			}
			return nil, nil, caperrors.NewPublicUserError(innerErr, caperrors.InvalidArgument)
		}
		if resp.GetId() == nil || resp.GetId().GetKey() == "" {
			return nil, nil, fmt.Errorf("VaultDON response at index %d is missing a valid secret identifier", responseIndex)
		}
		if slices.Contains(seenKeys, resp.GetId().GetKey()) {
			return nil, nil, fmt.Errorf("duplicate VaultDON response for secret key %s at index %d", resp.GetId().GetKey(), responseIndex)
		}
		seenKeys = append(seenKeys, resp.GetId().GetKey())
	}
	orderedVaultDONResponses := []*vault.SecretResponse{}
	for _, secretReq := range secretRequests {
		var matchingResp *vault.SecretResponse
		for _, resp := range vaultDONOutput.Responses {
			if resp.GetId().GetKey() == secretReq.Id.GetKey() {
				matchingResp = resp
				break
			}
		}
		if matchingResp == nil {
			return nil, nil, fmt.Errorf("no response from VaultDON for secret with key %s, namespace %s, owner %s", secretReq.Id.GetKey(), secretReq.Id.GetNamespace(), secretReq.Id.GetOwner())
		}
		orderedVaultDONResponses = append(orderedVaultDONResponses, matchingResp)
	}

	for _, secretResp := range orderedVaultDONResponses {
		secretData := secretResp.GetData()
		if secretData == nil {
			return nil, nil, fmt.Errorf("VaultDON returned no data for secret %s", secretResp.GetId().GetKey())
		}

		encryptedSecret, err := hex.DecodeString(secretData.GetEncryptedValue())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode hex-encoded ciphertext for secret %s: %w", secretResp.GetId().GetKey(), err)
		}
		encryptedSecrets = append(encryptedSecrets, encryptedSecret)

		encryptedDecryptionSharesForSecret := make([][]byte, 0)
		if len(secretData.GetEncryptedDecryptionKeyShares()) != 1 {
			return nil, nil, fmt.Errorf("expected exactly one set of encrypted decryption key shares for secret %s, got %d", secretResp.GetId().GetKey(), len(secretData.GetEncryptedDecryptionKeyShares()))
		}
		shares := secretData.GetEncryptedDecryptionKeyShares()[0]
		if len(shares.GetBinaryShares()) > 0 {
			encryptedDecryptionSharesForSecret = shares.GetBinaryShares()
		} else if len(shares.GetShares()) > 0 {
			for _, shareStr := range shares.GetShares() {
				shareBytes, err := hex.DecodeString(shareStr)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to decode hex-encoded share for secret %s: %w", secretResp.GetId().GetKey(), err)
				}
				encryptedDecryptionSharesForSecret = append(encryptedDecryptionSharesForSecret, shareBytes)
			}
		} else {
			return nil, nil, fmt.Errorf("no decryption shares found for secret %s: neither binary nor hex-encoded shares present", secretResp.GetId().GetKey())
		}
		minimumSharesRequired := e.vaultDON.CryptographyThreshold
		if len(encryptedDecryptionSharesForSecret) < minimumSharesRequired {
			return nil, nil, fmt.Errorf("not enough encrypted decryption key shares for secret %s, expected at least %d, got %d", secretResp.GetId().GetKey(), minimumSharesRequired, len(encryptedDecryptionSharesForSecret))
		}
		encryptedDecryptionShares = append(encryptedDecryptionShares, encryptedDecryptionSharesForSecret)
	}

	// Cache the retrieved secrets for next time.
	if enableSecretsCache {
		for i, secret := range vaultDONSecrets {
			cacheKey := generateSecretCacheKey(enclaveEphemeralPublicKey, secret, metadata.WorkflowOwner)
			e.secretsCache.Set(cacheKey, &cachedEDKS{
				encryptedSecret:           encryptedSecrets[i],
				encryptedDecryptionShares: encryptedDecryptionShares[i],
			}, nil)
		}
		e.lggr.Debugw("cached VaultDON secrets", "secretCount", len(vaultDONSecrets))
	}
	return encryptedSecrets, encryptedDecryptionShares, nil
}

func sanitizeLogString(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > 256 {
		s = s[:256] + "..."
	}
	return s
}

func peerIDsToSortedBytes(members []p2ptypes.PeerID) [][]byte {
	result := make([][]byte, len(members))
	for i, m := range members {
		b := make([]byte, len(m))
		copy(b, m[:])
		result[i] = b
	}
	slices.SortFunc(result, bytes.Compare)
	return result
}

// sortedBytesCopy returns a byte-sorted copy of s, leaving the input order untouched.
func sortedBytesCopy(s [][]byte) [][]byte {
	out := make([][]byte, len(s))
	copy(out, s)
	slices.SortFunc(out, bytes.Compare)
	return out
}

func (e *RealExecutor) applyPropagatedOrgIDToVault(ctx context.Context, md *capabilities.RequestMetadata) {
	propagateOrgIDMeta, _ := cresettings.Default.PropagateOrgIDInRequestMetadata.GetOrDefault(ctx, e.limitsFactory.Settings)
	if !propagateOrgIDMeta {
		md.OrgID = ""
	}
}

// applyWorkflowDONBindingToVault sets RequestMetadata.WorkflowDonID to this
// (conf-compute) node's local workflow DON ID when the WorkflowDonID binding
// gate is enabled, so the remote VaultDON server accepts the request. From
// VaultDON's perspective the calling DON is this conf-compute DON, not the
// originating workflow DON carried in the incoming metadata. Any failure must
// fail the whole call rather than silently sending a zero/mismatched WorkflowDonID.
func (e *RealExecutor) applyWorkflowDONBindingToVault(ctx context.Context, md *capabilities.RequestMetadata) error {
	bindingEnabled, err := cresettings.Default.RemoteExecutableWorkflowDONBindingEnabled.GetOrDefault(ctx, e.limitsFactory.Settings)
	if err != nil {
		return fmt.Errorf("failed to read RemoteExecutableWorkflowDONBindingEnabled setting: %w", err)
	}
	if !bindingEnabled {
		return nil
	}
	localNode, err := e.capabilityRegistry.LocalNode(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node for VaultDON request metadata: %w", err)
	}
	md.WorkflowDonID = localNode.WorkflowDON.ID
	return nil
}

func (e *RealExecutor) validateEnclaveSigners(config types.EnclaveConfig) error {
	members, f := e.getDONMembership()
	if len(members) == 0 {
		return fmt.Errorf("cannot validate enclave config: DON members not set")
	}

	if config.F < f {
		return fmt.Errorf("enclave F value %d does not match DON F value %d", config.F, f)
	}

	sortedSigners := sortedBytesCopy(config.Signers)
	sortedMembers := sortedBytesCopy(members)

	if !slices.EqualFunc(sortedSigners, sortedMembers, bytes.Equal) {
		return fmt.Errorf("enclave signers do not match DON members: enclave has %d signers, DON has %d members", len(config.Signers), len(members))
	}
	return nil
}

func sortEnclaveNodes(nodes []types.Enclave) {
	slices.SortFunc(nodes, func(a, b types.Enclave) int {
		return bytes.Compare(b.EnclaveID[:], a.EnclaveID[:])
	})
}

func getVaultDONThreshold(possiblyFaultyNodes int) int {
	return 2*possiblyFaultyNodes + 1
}
