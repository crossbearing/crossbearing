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
	GetTrailFunc     func(ctx context.Context, params *cloudtrail.GetTrailInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailOutput, error)
	LookupEventsFunc func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

func (m *mockCloudTrailClient) GetTrail(ctx context.Context, params *cloudtrail.GetTrailInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailOutput, error) {
	if m.GetTrailFunc != nil {
		return m.GetTrailFunc(ctx, params, optFns...)
	}
	return &cloudtrail.GetTrailOutput{}, nil
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

func TestCloudTrailService_GetTrail(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		trailName string
		mockFn    func(*mockCloudTrailClient)
		want      string
		wantErr   bool
	}{
		{
			name:      "success returns trail ARN",
			trailName: "test-trail",
			mockFn: func(m *mockCloudTrailClient) {
				m.GetTrailFunc = func(ctx context.Context, params *cloudtrail.GetTrailInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailOutput, error) {
					if got := aws.ToString(params.Name); got != "test-trail" {
						t.Errorf("GetTrail Name = %q, want %q", got, "test-trail")
					}
					return &cloudtrail.GetTrailOutput{
						Trail: &cttypes.Trail{
							TrailARN: aws.String(testTrailARN),
						},
					}, nil
				}
			},
			want:    testTrailARN,
			wantErr: false,
		},
		{
			name:      "not found returns empty string",
			trailName: "nonexistent-trail",
			mockFn: func(m *mockCloudTrailClient) {
				m.GetTrailFunc = func(ctx context.Context, params *cloudtrail.GetTrailInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailOutput, error) {
					return nil, &cttypes.TrailNotFoundException{Message: aws.String("trail not found")}
				}
			},
			want:    "",
			wantErr: false,
		},
		{
			name:      "api error propagates",
			trailName: "test-trail",
			mockFn: func(m *mockCloudTrailClient) {
				m.GetTrailFunc = func(ctx context.Context, params *cloudtrail.GetTrailInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailOutput, error) {
					return nil, errors.New("api error: access denied")
				}
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockClient := &mockCloudTrailClient{}
			if tt.mockFn != nil {
				tt.mockFn(mockClient)
			}

			svc := (&CloudTrailService{api: mockClient})
			got, err := svc.GetTrail(context.Background(), tt.trailName)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetTrail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetTrail() = %q, want %q", got, tt.want)
			}
		})
	}
}

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
