package aws

import (
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// IAM returns an IAM client, initializing it on first call.
func (c *Client) IAM() *iam.Client {
	if c.closedGuard("IAM") {
		return nil
	}
	return lazyInit(&c.mu, &c.iamClient, func() *iam.Client { return iam.NewFromConfig(c.awsConfig) })
}

// STS returns an STS client, initializing it on first call.
func (c *Client) STS() *sts.Client {
	if c.closedGuard("STS") {
		return nil
	}
	return lazyInit(&c.mu, &c.stsClient, func() *sts.Client { return sts.NewFromConfig(c.awsConfig) })
}

// KMS returns a KMS client, initializing it on first call.
func (c *Client) KMS() *kms.Client {
	if c.closedGuard("KMS") {
		return nil
	}
	return lazyInit(&c.mu, &c.kmsClient, func() *kms.Client { return kms.NewFromConfig(c.awsConfig) })
}

// CloudTrail returns a CloudTrail client, initializing it on first call.
func (c *Client) CloudTrail() *cloudtrail.Client {
	if c.closedGuard("CloudTrail") {
		return nil
	}
	return lazyInit(&c.mu, &c.cloudTrailClient, func() *cloudtrail.Client { return cloudtrail.NewFromConfig(c.awsConfig) })
}
