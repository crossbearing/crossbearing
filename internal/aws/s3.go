package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// s3API is the narrow SDK surface S3Service uses; production resolves
// it from the shared Client, tests inject a mock so the REAL service
// methods (not a shim) are what the suite exercises.
type s3API interface {
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3Service provides operations for S3 buckets and objects.
type S3Service struct {
	client *Client
	api    s3API // test seam; nil means resolve from client
}

// NewS3Service creates a new S3 service.
func NewS3Service(client *Client) *S3Service {
	return &S3Service{client: client}
}

func (s *S3Service) sdk() s3API {
	if s.api != nil {
		return s.api
	}
	return s.client.S3()
}

// BucketExists checks if a bucket exists.
// Returns (false, nil) only for genuine "not found" errors (HTTP 404 or
// NoSuchBucket). All other errors (permission denied, network failures,
// etc.) are propagated to the caller.
func (s *S3Service) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	_, err := s.sdk().HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// Check for HTTP 404 (smithy ResponseError)
		var respErr *smithyhttp.ResponseError
		if ok := errors.As(err, &respErr); ok && respErr.Response.StatusCode == 404 {
			return false, nil
		}
		// Check for well-known not-found error strings (e.g., from mocks)
		if isS3NotFoundError(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check bucket existence: %w", err)
	}
	return true, nil
}

// isS3NotFoundError returns true if the error message indicates the bucket was not found.
func isS3NotFoundError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "NotFound") || strings.Contains(msg, "NoSuchBucket")
}

// GetObject retrieves an object from a bucket.
// Thin typed pass-through to the S3 GetObject API; the caller owns
// closing the returned Body.
func (s *S3Service) GetObject(ctx context.Context, bucket, key string) (*s3.GetObjectOutput, error) {
	result, err := s.sdk().GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	return result, nil
}

// PutObject writes an object to a bucket.
// Thin typed pass-through to the S3 PutObject API.
func (s *S3Service) PutObject(ctx context.Context, bucket, key string, body io.Reader) (*s3.PutObjectOutput, error) {
	result, err := s.sdk().PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   body,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to put object: %w", err)
	}
	return result, nil
}
