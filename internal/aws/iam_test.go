package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// =============================================================================
// IAM Mock Interface and Implementation
// =============================================================================

// mockIAMClient is a mock implementation of iamAPI.
type mockIAMClient struct {
	GetRoleFunc func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
}

func (m *mockIAMClient) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	if m.GetRoleFunc != nil {
		return m.GetRoleFunc(ctx, params, optFns...)
	}
	return &iam.GetRoleOutput{}, nil
}

// Compile-time interface compliance check.
var _ iamAPI = (*mockIAMClient)(nil)

// =============================================================================
// Tests
// =============================================================================

func TestIAMRole_GetRole_Success(t *testing.T) {
	t.Parallel()
	mock := &mockIAMClient{
		GetRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			if got := aws.ToString(params.RoleName); got != "test-role" {
				t.Errorf("GetRole RoleName = %q, want %q", got, "test-role")
			}
			return &iam.GetRoleOutput{
				Role: &iamtypes.Role{
					Arn:      aws.String("arn:aws:iam::123456789012:role/test-role"),
					RoleName: aws.String("test-role"),
					RoleId:   aws.String("AROA1234567890EXAMPLE"),
				},
			}, nil
		},
	}
	svc := (&IAMService{api: mock})

	output, err := svc.GetRole(context.Background(), "test-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output == nil {
		t.Fatal("output should not be nil")
	}
	if output.RoleName != "test-role" {
		t.Errorf("RoleName = %q, want %q", output.RoleName, "test-role")
	}
	if output.RoleARN != "arn:aws:iam::123456789012:role/test-role" {
		t.Errorf("RoleARN = %q, want %q", output.RoleARN, "arn:aws:iam::123456789012:role/test-role")
	}
	if output.RoleId == "" {
		t.Error("RoleId should not be empty")
	}
}

func TestIAMRole_GetRole_NotFound(t *testing.T) {
	t.Parallel()
	mock := &mockIAMClient{
		GetRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return nil, &iamtypes.NoSuchEntityException{Message: aws.String("role not found")}
		},
	}
	svc := (&IAMService{api: mock})

	output, err := svc.GetRole(context.Background(), "nonexistent-role")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output != nil {
		t.Errorf("expected nil output for not-found role, got %+v", output)
	}
}

func TestIAMRole_GetRole_Error(t *testing.T) {
	t.Parallel()
	mock := &mockIAMClient{
		GetRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return nil, errors.New("api error: access denied")
		},
	}
	svc := (&IAMService{api: mock})

	if _, err := svc.GetRole(context.Background(), "test-role"); err == nil {
		t.Fatal("expected error, got nil")
	}
}
