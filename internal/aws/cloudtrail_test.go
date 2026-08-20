package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// =============================================================================
// CloudTrail Mock Interface and Implementation
// =============================================================================

// mockCloudTrailClient is a mock implementation of cloudTrailAPI.
type mockCloudTrailClient struct {
	LookupEventsFunc func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

func (m *mockCloudTrailClient) LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if m.LookupEventsFunc != nil {
		return m.LookupEventsFunc(ctx, params, optFns...)
	}
	return &cloudtrail.LookupEventsOutput{}, nil
}

// Compile-time interface compliance check.
var _ cloudTrailAPI = (*mockCloudTrailClient)(nil)

// =============================================================================
// Tests
// =============================================================================

const testTrailARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail"

func TestCloudTrailService_LookupEvents(t *testing.T) {
	t.Parallel()
	t.Run("success forwards input and returns events", func(t *testing.T) {
		t.Parallel()
		mockClient := &mockCloudTrailClient{
			LookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
				if len(params.LookupAttributes) != 1 {
					t.Fatalf("LookupAttributes count = %d, want 1", len(params.LookupAttributes))
				}
				attr := params.LookupAttributes[0]
				if attr.AttributeKey != cttypes.LookupAttributeKeyEventName {
					t.Errorf("AttributeKey = %q, want %q", attr.AttributeKey, cttypes.LookupAttributeKeyEventName)
				}
				if got := aws.ToString(attr.AttributeValue); got != "CreateTrail" {
					t.Errorf("AttributeValue = %q, want %q", got, "CreateTrail")
				}
				return &cloudtrail.LookupEventsOutput{
					Events: []cttypes.Event{
						{
							EventId:   aws.String("event-1"),
							EventName: aws.String("CreateTrail"),
						},
					},
					NextToken: aws.String("next-page"),
				}, nil
			},
		}

		svc := (&CloudTrailService{api: mockClient})
		out, err := svc.LookupEvents(context.Background(), &cloudtrail.LookupEventsInput{
			LookupAttributes: []cttypes.LookupAttribute{
				{
					AttributeKey:   cttypes.LookupAttributeKeyEventName,
					AttributeValue: aws.String("CreateTrail"),
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(out.Events) != 1 {
			t.Fatalf("Events count = %d, want 1", len(out.Events))
		}
		if got := aws.ToString(out.Events[0].EventName); got != "CreateTrail" {
			t.Errorf("EventName = %q, want %q", got, "CreateTrail")
		}
		if aws.ToString(out.NextToken) != "next-page" {
			t.Errorf("NextToken = %q, want %q", aws.ToString(out.NextToken), "next-page")
		}
	})

	t.Run("api error propagates", func(t *testing.T) {
		t.Parallel()
		mockClient := &mockCloudTrailClient{
			LookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
				return nil, errors.New("api error: throttled")
			},
		}

		svc := (&CloudTrailService{api: mockClient})
		if _, err := svc.LookupEvents(context.Background(), &cloudtrail.LookupEventsInput{}); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
