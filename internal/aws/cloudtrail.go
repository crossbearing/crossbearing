package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// cloudTrailAPI is the narrow SDK surface CloudTrailService uses; production resolves
// it from the shared Client, tests inject a mock so the REAL service
// methods (not a shim) are what the suite exercises.
type cloudTrailAPI interface {
	GetTrail(ctx context.Context, params *cloudtrail.GetTrailInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailOutput, error)
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

// GetTrail retrieves a CloudTrail trail ARN by name.
// Returns empty string and nil error if the trail does not exist.
func (s *CloudTrailService) GetTrail(ctx context.Context, name string) (string, error) {
	result, err := s.sdk().GetTrail(ctx, &cloudtrail.GetTrailInput{
		Name: aws.String(name),
	})
	if err != nil {
		var notFound *types.TrailNotFoundException
		if errors.As(err, &notFound) {
			return "", nil
		}
		return "", fmt.Errorf("failed to get trail: %w", err)
	}

	return aws.ToString(result.Trail.TrailARN), nil
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
