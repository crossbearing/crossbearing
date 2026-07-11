package aws

import (
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3 returns an S3 client, initializing it on first call.
func (c *Client) S3() *s3.Client {
	if c.closedGuard("S3") {
		return nil
	}
	return lazyInit(&c.mu, &c.s3Client, func() *s3.Client { return s3.NewFromConfig(c.awsConfig) })
}
