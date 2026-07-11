package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// iamAPI is the narrow SDK surface IAMService uses; production resolves
// it from the shared Client, tests inject a mock so the REAL service
// methods (not a shim) are what the suite exercises.
type iamAPI interface {
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
}

// IAMService provides IAM operations.
type IAMService struct {
	client *Client
	api    iamAPI // test seam; nil means resolve from client
}

// NewIAMService creates a new IAM service.
func NewIAMService(client *Client) *IAMService {
	return &IAMService{client: client}
}

func (s *IAMService) sdk() iamAPI {
	if s.api != nil {
		return s.api
	}
	return s.client.IAM()
}

// RoleOutput contains the result of IAM role operations.
type RoleOutput struct {
	RoleARN  string
	RoleName string
	RoleId   string
	// TrustPolicy is the role's assume-role policy document as plain JSON
	// (the API returns it URL-encoded; this is decoded).
	TrustPolicy string
}

// GetRole retrieves an IAM role.
// Returns nil and nil error if the role does not exist.
func (s *IAMService) GetRole(ctx context.Context, roleName string) (*RoleOutput, error) {
	result, err := s.sdk().GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		var notFound *types.NoSuchEntityException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get IAM role: %w", err)
	}

	trust := aws.ToString(result.Role.AssumeRolePolicyDocument)
	if decoded, err := url.QueryUnescape(trust); err == nil {
		trust = decoded
	}

	return &RoleOutput{
		RoleARN:     aws.ToString(result.Role.Arn),
		RoleName:    aws.ToString(result.Role.RoleName),
		RoleId:      aws.ToString(result.Role.RoleId),
		TrustPolicy: trust,
	}, nil
}
