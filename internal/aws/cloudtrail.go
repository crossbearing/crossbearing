package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

// cloudTrailAPI is the narrow SDK surface CloudTrailService uses; production resolves
// it from the shared Client, tests inject a mock so the REAL service
// methods (not a shim) are what the suite exercises.
type cloudTrailAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// CloudTrailService provides operations for AWS CloudTrail.
type CloudTrailService struct {
	client *Client
	api    cloudTrailAPI // test seam; nil means resolve from client
}

// NewCloudTrailService creates a new CloudTrail service.
func NewCloudTrailService(client *Client) *CloudTrailService {
	return &CloudTrailService{client: client}
}

func (s *CloudTrailService) sdk() cloudTrailAPI {
	if s.api != nil {
		return s.api
	}
	return s.client.CloudTrail()
}

// LookupEvents looks up management events recorded by CloudTrail.
// Thin typed pass-through to the CloudTrail LookupEvents API; callers
// drive pagination via NextToken on the input/output.
func (s *CloudTrailService) LookupEvents(ctx context.Context, input *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
	result, err := s.sdk().LookupEvents(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup events: %w", err)
	}
	return result, nil
}
