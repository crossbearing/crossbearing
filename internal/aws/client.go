// Package aws provides lean AWS SDK client wrappers with OIDC federation
// support, trimmed to the five services the collector needs: CloudTrail,
// IAM, KMS, S3, and STS.
package aws

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ClientConfig holds configuration for creating AWS clients.
type ClientConfig struct {
	// Region is the AWS region to use.
	Region string

	// RoleARN is the ARN of the IAM role to assume via OIDC.
	RoleARN string

	// OIDCTokenPath is the path to the OIDC token file (for service account token projection).
	OIDCTokenPath string

	// SessionDuration is how long the assumed role session should last.
	SessionDuration time.Duration

	// ExternalID is an optional external ID for the OIDC role assumption.
	ExternalID string

	// AssumeRoleConfig configures cross-account role chaining.
	// When set, after OIDC authentication to the platform account,
	// the client will chain to assume this role in the target account.
	AssumeRoleConfig *AssumeRoleConfig

	// AccountID is the target AWS account ID (for logging/tracking).
	AccountID string
}

// AssumeRoleConfig configures cross-account role assumption via role chaining.
type AssumeRoleConfig struct {
	// RoleARN is the ARN of the role to assume in the target account.
	RoleARN string

	// ExternalID is the external ID required for the role assumption.
	ExternalID string

	// SessionName is an optional session name for the assumed role session.
	SessionName string

	// SessionDuration is how long the assumed role session should last.
	// Defaults to 1 hour. Max for role chaining is 1 hour.
	SessionDuration time.Duration
}

// Client is an AWS client wrapper with OIDC federation support.
// Service clients are lazily initialized using double-checked locking via
// lazyInit for efficient, race-free concurrent access.
type Client struct {
	config    ClientConfig
	awsConfig aws.Config
	logger    *slog.Logger

	mu     sync.RWMutex
	closed bool

	stsClient        *sts.Client
	cloudTrailClient *cloudtrail.Client
	iamClient        *iam.Client
	kmsClient        *kms.Client
	s3Client         *s3.Client
}

// lazyInit provides double-checked locking for lazy service client initialization.
// It uses an RWMutex to allow concurrent reads of already-initialized clients
// while serializing first-time initialization.
//
// The value is captured inside the lock before returning to avoid a race where
// Close() could nil the field pointer between the lock release and the return.
func lazyInit[T any](mu *sync.RWMutex, field **T, construct func() *T) *T {
	mu.RLock()
	v := *field
	mu.RUnlock()
	if v != nil {
		return v
	}
	mu.Lock()
	defer mu.Unlock()
	if *field == nil {
		*field = construct()
	}
	return *field
}

// NewClient creates a new AWS client with OIDC federation.
// If AssumeRoleConfig is provided, it chains to assume a role in the target account.
func NewClient(ctx context.Context, cfg ClientConfig, logger *slog.Logger) (*Client, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("region is required")
	}
	if cfg.SessionDuration == 0 {
		cfg.SessionDuration = time.Hour
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Configure HTTP transport with connection pooling for efficient connection reuse
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	httpClient := &http.Client{
		Transport: transport,
	}

	// Load base AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
		config.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create STS client for role assumption
	stsClient := sts.NewFromConfig(awsCfg)

	// Credential resolution:
	//   - RoleARN set   -> explicit OIDC web-identity federation to that role,
	//     reading the projected service-account token from OIDCTokenPath. This is
	//     the platform-account-role design (and the base for cross-account
	//     chaining via AssumeRoleConfig).
	//   - RoleARN empty -> rely on the SDK default credential chain already
	//     resolved by LoadDefaultConfig, which natively handles IRSA and web
	//     identity federation (AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE),
	//     AWS_* env vars, and the instance/container profile.
	if cfg.RoleARN != "" {
		if cfg.OIDCTokenPath == "" {
			cfg.OIDCTokenPath = "/var/run/secrets/tokens/aws-token"
		}
		oidcProvider := stscreds.NewWebIdentityRoleProvider(
			stsClient,
			cfg.RoleARN,
			stscreds.IdentityTokenFile(cfg.OIDCTokenPath),
			func(opts *stscreds.WebIdentityRoleOptions) {
				opts.RoleSessionName = "crossbearing-session"
				opts.Duration = cfg.SessionDuration
			},
		)
		awsCfg.Credentials = aws.NewCredentialsCache(oidcProvider)
	}

	// If cross-account role chaining is configured, chain to the target account
	if cfg.AssumeRoleConfig != nil {
		awsCfg, stsClient, err = chainToTargetAccount(ctx, awsCfg, cfg.AssumeRoleConfig, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to chain to target account: %w", err)
		}
	}

	client := &Client{
		config:    cfg,
		awsConfig: awsCfg,
		logger:    logger.With("component", "aws-client"),
		stsClient: stsClient,
	}

	return client, nil
}

// chainToTargetAccount assumes a role in the target account using the current credentials.
// This implements role chaining: OIDC -> Platform Account Role -> Target Account Role.
func chainToTargetAccount(ctx context.Context, baseCfg aws.Config, assumeCfg *AssumeRoleConfig, logger *slog.Logger) (aws.Config, *sts.Client, error) {
	if assumeCfg.RoleARN == "" {
		return baseCfg, nil, fmt.Errorf("assume role ARN is required")
	}

	// Create STS client with the OIDC credentials (platform account)
	stsClient := sts.NewFromConfig(baseCfg)

	// Set up session duration (max 1 hour for role chaining)
	sessionDuration := assumeCfg.SessionDuration
	if sessionDuration == 0 {
		sessionDuration = time.Hour
	}
	if sessionDuration > time.Hour {
		// AWS limits role chaining sessions to 1 hour max
		sessionDuration = time.Hour
		logger.InfoContext(ctx, "session duration capped to 1 hour for role chaining")
	}

	// Set up session name
	sessionName := assumeCfg.SessionName
	if sessionName == "" {
		sessionName = "crossbearing-cross-account"
	}

	// Create AssumeRole credentials provider
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(
		stsClient,
		assumeCfg.RoleARN,
		func(opts *stscreds.AssumeRoleOptions) {
			opts.RoleSessionName = sessionName
			opts.Duration = sessionDuration
			if assumeCfg.ExternalID != "" {
				opts.ExternalID = aws.String(assumeCfg.ExternalID)
			}
		},
	)

	// Update config with chained credentials
	newCfg := baseCfg.Copy()
	newCfg.Credentials = aws.NewCredentialsCache(assumeRoleProvider)

	// Create a new STS client with the chained credentials for the target account
	targetStsClient := sts.NewFromConfig(newCfg)

	logger.InfoContext(ctx, "configured cross-account role chaining",
		"targetRoleARN", assumeCfg.RoleARN,
		"sessionName", sessionName,
		"hasExternalID", assumeCfg.ExternalID != "",
	)

	return newCfg, targetStsClient, nil
}

// Logger returns the client's logger for use by service implementations.
func (c *Client) Logger() *slog.Logger {
	return c.logger
}

// closedGuard checks if the client has been closed and logs a warning.
// Returns true if the client is closed and the caller should return a zero value.
func (c *Client) closedGuard(service string) bool {
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		c.logger.Info("AWS client accessed after Close", "service", service)
		return true
	}
	return false
}

// AssumeRoleClient creates a new Client that assumes a role in a target account.
// This is used for cross-account operations like multi-account collection.
func (c *Client) AssumeRoleClient(roleARN, sessionName string) *Client {
	stsClient := sts.NewFromConfig(c.awsConfig)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(opts *stscreds.AssumeRoleOptions) {
		opts.RoleSessionName = sessionName
	})

	newCfg := c.awsConfig.Copy()
	newCfg.Credentials = aws.NewCredentialsCache(provider)

	return &Client{
		config:    c.config,
		awsConfig: newCfg,
		logger:    c.logger.With("assumedRole", roleARN),
		stsClient: sts.NewFromConfig(newCfg),
	}
}

// Config returns the underlying AWS config.
func (c *Client) Config() aws.Config {
	return c.awsConfig
}

// Region returns the configured region.
func (c *Client) Region() string {
	return c.config.Region
}

// VerifyCredentials tests that the OIDC credentials work.
func (c *Client) VerifyCredentials(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
	return c.STS().GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}

// WithRegion returns a new client configured for a different region.
func (c *Client) WithRegion(ctx context.Context, region string) (*Client, error) {
	newCfg := c.config
	newCfg.Region = region
	return NewClient(ctx, newCfg, c.logger)
}

// Close releases all cached AWS service clients and marks the factory as closed.
// After Close, accessor methods (S3(), IAM(), etc.) return nil because
// closedGuard fires and the underlying pointers have been nilled.
// Close is safe to call multiple times.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	c.logger.Info("closing AWS client factory", "region", c.config.Region)

	c.stsClient = nil
	c.cloudTrailClient = nil
	c.iamClient = nil
	c.kmsClient = nil
	c.s3Client = nil

	c.closed = true
}

// Closed reports whether Close has been called.
func (c *Client) Closed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closed
}
