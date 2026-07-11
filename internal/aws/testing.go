package aws

import (
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// NewClientForTesting creates a *Client configured for integration testing.
// All AWS SDK sub-client API calls are directed to the given endpoint URL,
// which typically points at an httptest.Server that returns mock responses.
// Static credentials are injected so no real AWS authentication is required.
//
// This function is intended for use in test code only.
func NewClientForTesting(endpoint, region string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	awsCfg := awssdk.Config{
		Region:       region,
		BaseEndpoint: awssdk.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
	}
	return &Client{
		config:    ClientConfig{Region: region},
		awsConfig: awsCfg,
		logger:    logger,
	}
}
