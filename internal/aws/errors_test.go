package aws

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type mockAPIError struct {
	code    string
	message string
}

func (e *mockAPIError) Error() string                 { return e.message }
func (e *mockAPIError) ErrorCode() string             { return e.code }
func (e *mockAPIError) ErrorMessage() string          { return e.message }
func (e *mockAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestAWSErrors_IsThrottled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"generic", errors.New("generic"), false},
		{"ThrottlingException", &mockAPIError{code: "ThrottlingException", message: "rate exceeded"}, true},
		{"RequestThrottled", &mockAPIError{code: "RequestThrottled", message: "slow down"}, true},
		{"TooManyRequestsException", &mockAPIError{code: "TooManyRequestsException", message: "too many"}, true},
		{"LimitExceededException", &mockAPIError{code: "LimitExceededException", message: "limit"}, true},
		{"SlowDown", &mockAPIError{code: "SlowDown", message: "slow"}, true},
		{"not found", &mockAPIError{code: "NotFoundException", message: "not found"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsThrottled(tt.err); got != tt.want {
				t.Errorf("IsThrottled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAWSErrors_IsNotFound(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"generic", errors.New("generic"), false},
		{"NotFoundException", &mockAPIError{code: "NotFoundException", message: "not found"}, true},
		{"ResourceNotFoundException", &mockAPIError{code: "ResourceNotFoundException", message: "resource"}, true},
		{"NoSuchEntityException", &mockAPIError{code: "NoSuchEntityException", message: "entity"}, true},
		{"NoSuchBucket", &mockAPIError{code: "NoSuchBucket", message: "bucket"}, true},
		{"TrailNotFoundException", &mockAPIError{code: "TrailNotFoundException", message: "trail"}, true},
		{"throttling", &mockAPIError{code: "ThrottlingException", message: "throttle"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAWSErrors_IsConflict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"generic", errors.New("generic"), false},
		{"ConflictException", &mockAPIError{code: "ConflictException", message: "conflict"}, true},
		{"AlreadyExistsException", &mockAPIError{code: "AlreadyExistsException", message: "exists"}, true},
		{"EntityAlreadyExistsException", &mockAPIError{code: "EntityAlreadyExistsException", message: "entity"}, true},
		{"BucketAlreadyExists", &mockAPIError{code: "BucketAlreadyExists", message: "bucket"}, true},
		{"ResourceInUseException", &mockAPIError{code: "ResourceInUseException", message: "in use"}, true},
		{"DeleteConflictException", &mockAPIError{code: "DeleteConflictException", message: "delete"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsConflict(tt.err); got != tt.want {
				t.Errorf("IsConflict() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAWSErrors_IsAccessDenied(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"generic", errors.New("generic"), false},
		{"AccessDeniedException", &mockAPIError{code: "AccessDeniedException", message: "denied"}, true},
		{"UnauthorizedOperation", &mockAPIError{code: "UnauthorizedOperation", message: "unauth"}, true},
		{"ExpiredTokenException", &mockAPIError{code: "ExpiredTokenException", message: "expired"}, true},
		{"not found", &mockAPIError{code: "NotFoundException", message: "not found"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsAccessDenied(tt.err); got != tt.want {
				t.Errorf("IsAccessDenied() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAWSErrors_IsRetryable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"generic", errors.New("generic"), false},
		{"throttling", &mockAPIError{code: "ThrottlingException", message: "throttle"}, true},
		{"not found", &mockAPIError{code: "NotFoundException", message: "not found"}, false},
		{"access denied", &mockAPIError{code: "AccessDeniedException", message: "denied"}, false},
		{"network error", &net.OpError{Op: "read", Err: fmt.Errorf("connection reset")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsRetryable(tt.err); got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAWSErrors_IsAlreadyExists(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"generic", errors.New("generic"), false},
		{"conflict code", &mockAPIError{code: "EntityAlreadyExistsException", message: "entity"}, true},
		{"already exists message", &mockAPIError{code: "InvalidRequest", message: "trail already exists"}, true},
		{"already enabled message", &mockAPIError{code: "InvalidRequest", message: "logging already enabled"}, true},
		{"not found", &mockAPIError{code: "NotFoundException", message: "not found"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsAlreadyExists(tt.err); got != tt.want {
				t.Errorf("IsAlreadyExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Ensure the smithyhttp import is used.
var _ = (*smithyhttp.ResponseError)(nil)
