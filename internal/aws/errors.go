package aws

import (
	"errors"
	"net"
	"strings"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// IsThrottled returns true if the AWS error indicates request throttling.
func IsThrottled(err error) bool {
	if err == nil {
		return false
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.Response.StatusCode == 429 {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return isThrottlingCode(apiErr.ErrorCode())
	}
	return false
}

// IsNotFound returns true if the AWS error indicates the resource was not found.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.Response.StatusCode == 404 {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return isNotFoundCode(apiErr.ErrorCode())
	}
	return false
}

// IsConflict returns true if the AWS error indicates a conflict.
func IsConflict(err error) bool {
	if err == nil {
		return false
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.Response.StatusCode == 409 {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return isConflictCode(apiErr.ErrorCode())
	}
	return false
}

// IsAccessDenied returns true if the AWS error indicates insufficient permissions.
func IsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.Response.StatusCode == 403 {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return isAccessDeniedCode(apiErr.ErrorCode())
	}
	return false
}

// IsRetryable returns true if the AWS error is transient and should be retried.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if IsThrottled(err) {
		return true
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) && respErr.Response.StatusCode >= 500 {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// IsAlreadyExists returns true if the AWS error indicates a resource already exists.
// It checks both standard conflict/already-exists error codes and common API error
// messages indicating idempotent creation.
func IsAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if IsConflict(err) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		msg := strings.ToLower(apiErr.ErrorMessage())
		return strings.Contains(msg, "already exist") || strings.Contains(msg, "already enabled")
	}
	return false
}

var throttlingCodes = map[string]bool{
	"Throttling":                true,
	"ThrottlingException":       true,
	"ThrottledException":        true,
	"RequestThrottled":          true,
	"RequestThrottledException": true,
	"TooManyRequestsException":  true,
	"RequestLimitExceeded":      true,
	"BandwidthLimitExceeded":    true,
	"LimitExceededException":    true,
	"SlowDown":                  true,
}

var notFoundCodes = map[string]bool{
	"NotFound":                  true,
	"NotFoundException":         true,
	"ResourceNotFoundException": true,
	"NoSuchEntity":              true,
	"NoSuchEntityException":     true,
	"NoSuchBucket":              true,
	"NoSuchKey":                 true,
	"NoSuchUpload":              true,
}

var conflictCodes = map[string]bool{
	"ConflictException":               true,
	"ResourceConflictException":       true,
	"AlreadyExistsException":          true,
	"ResourceAlreadyExistsException":  true,
	"EntityAlreadyExists":             true,
	"EntityAlreadyExistsException":    true,
	"BucketAlreadyExists":             true,
	"BucketAlreadyOwnedByYou":         true,
	"ResourceInUseException":          true,
	"DeleteConflictException":         true,
	"OperationAbortedException":       true,
	"ConcurrentModificationException": true,
}

var accessDeniedCodes = map[string]bool{
	"AccessDenied":                true,
	"AccessDeniedException":       true,
	"AuthorizationError":          true,
	"AuthorizationErrorException": true,
	"UnauthorizedAccess":          true,
	"UnauthorizedOperation":       true,
	"InvalidClientTokenId":        true,
	"SignatureDoesNotMatch":       true,
	"ExpiredToken":                true,
	"ExpiredTokenException":       true,
	"InvalidIdentityToken":        true,
}

func isThrottlingCode(code string) bool {
	if throttlingCodes[code] {
		return true
	}
	return strings.Contains(strings.ToLower(code), "throttl")
}

func isNotFoundCode(code string) bool {
	if notFoundCodes[code] {
		return true
	}
	lc := strings.ToLower(code)
	return strings.Contains(lc, "notfound") || strings.Contains(lc, "nosuch")
}

func isConflictCode(code string) bool {
	return conflictCodes[code]
}

func isAccessDeniedCode(code string) bool {
	return accessDeniedCodes[code]
}
