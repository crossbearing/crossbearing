package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const testBucketName = "test-bucket"

// =============================================================================
// S3 Mock Interface and Implementation
// =============================================================================

// mockS3Client is a mock implementation of s3API.
type mockS3Client struct {
	HeadBucketFunc func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	GetObjectFunc  func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObjectFunc  func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func (m *mockS3Client) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if m.HeadBucketFunc != nil {
		return m.HeadBucketFunc(ctx, params, optFns...)
	}
	return &s3.HeadBucketOutput{}, nil
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.GetObjectFunc != nil {
		return m.GetObjectFunc(ctx, params, optFns...)
	}
	return &s3.GetObjectOutput{}, nil
}

func (m *mockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.PutObjectFunc != nil {
		return m.PutObjectFunc(ctx, params, optFns...)
	}
	return &s3.PutObjectOutput{}, nil
}

// Compile-time interface compliance check.
var _ s3API = (*mockS3Client)(nil)

// =============================================================================
// Tests
// =============================================================================

func TestS3Service_BucketExists(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		bucketName string
		mockFn     func(*mockS3Client)
		want       bool
		wantErr    bool
	}{
		{
			name:       "bucket exists",
			bucketName: testBucketName,
			mockFn: func(m *mockS3Client) {
				m.HeadBucketFunc = func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
					return &s3.HeadBucketOutput{}, nil
				}
			},
			want:    true,
			wantErr: false,
		},
		{
			name:       "bucket does not exist (NotFound)",
			bucketName: "nonexistent-bucket",
			mockFn: func(m *mockS3Client) {
				m.HeadBucketFunc = func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
					return nil, errors.New("NotFound")
				}
			},
			want:    false,
			wantErr: false,
		},
		{
			name:       "bucket does not exist (NoSuchBucket)",
			bucketName: "nonexistent-bucket",
			mockFn: func(m *mockS3Client) {
				m.HeadBucketFunc = func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
					return nil, errors.New("NoSuchBucket: The specified bucket does not exist")
				}
			},
			want:    false,
			wantErr: false,
		},
		{
			// Permission denied and other real errors must be propagated to
			// the caller rather than swallowed as (false, nil).
			name:       "access denied propagates error",
			bucketName: testBucketName,
			mockFn: func(m *mockS3Client) {
				m.HeadBucketFunc = func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
					return nil, fmt.Errorf("AccessDenied: User does not have permission")
				}
			},
			want:    false,
			wantErr: true,
		},
		{
			name:       "network error propagates error",
			bucketName: testBucketName,
			mockFn: func(m *mockS3Client) {
				m.HeadBucketFunc = func(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
					return nil, fmt.Errorf("RequestError: send request failed, connection reset")
				}
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockS3 := &mockS3Client{}
			if tt.mockFn != nil {
				tt.mockFn(mockS3)
			}

			svc := (&S3Service{api: mockS3})
			exists, err := svc.BucketExists(context.Background(), tt.bucketName)

			if (err != nil) != tt.wantErr {
				t.Errorf("BucketExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if exists != tt.want {
				t.Errorf("BucketExists() = %v, want %v", exists, tt.want)
			}
		})
	}
}

func TestS3Service_GetObject(t *testing.T) {
	t.Parallel()
	t.Run("success forwards bucket and key", func(t *testing.T) {
		t.Parallel()
		wantBody := "object-contents"
		mockS3 := &mockS3Client{
			GetObjectFunc: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
				if got := aws.ToString(params.Bucket); got != testBucketName {
					t.Errorf("GetObject Bucket = %q, want %q", got, testBucketName)
				}
				if got := aws.ToString(params.Key); got != "path/to/object" {
					t.Errorf("GetObject Key = %q, want %q", got, "path/to/object")
				}
				return &s3.GetObjectOutput{
					Body: io.NopCloser(strings.NewReader(wantBody)),
				}, nil
			},
		}

		svc := (&S3Service{api: mockS3})
		out, err := svc.GetObject(context.Background(), testBucketName, "path/to/object")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer out.Body.Close()

		body, err := io.ReadAll(out.Body)
		if err != nil {
			t.Fatalf("failed reading body: %v", err)
		}
		if string(body) != wantBody {
			t.Errorf("body = %q, want %q", body, wantBody)
		}
	})

	t.Run("api error propagates", func(t *testing.T) {
		t.Parallel()
		mockS3 := &mockS3Client{
			GetObjectFunc: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
				return nil, errors.New("NoSuchKey: The specified key does not exist")
			},
		}

		svc := (&S3Service{api: mockS3})
		if _, err := svc.GetObject(context.Background(), testBucketName, "missing"); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestS3Service_PutObject(t *testing.T) {
	t.Parallel()
	t.Run("success forwards bucket, key, and body", func(t *testing.T) {
		t.Parallel()
		wantBody := []byte("payload")
		mockS3 := &mockS3Client{
			PutObjectFunc: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
				if got := aws.ToString(params.Bucket); got != testBucketName {
					t.Errorf("PutObject Bucket = %q, want %q", got, testBucketName)
				}
				if got := aws.ToString(params.Key); got != "path/to/object" {
					t.Errorf("PutObject Key = %q, want %q", got, "path/to/object")
				}
				body, err := io.ReadAll(params.Body)
				if err != nil {
					t.Fatalf("failed reading body: %v", err)
				}
				if !bytes.Equal(body, wantBody) {
					t.Errorf("body = %q, want %q", body, wantBody)
				}
				return &s3.PutObjectOutput{ETag: aws.String(`"abc123"`)}, nil
			},
		}

		svc := (&S3Service{api: mockS3})
		out, err := svc.PutObject(context.Background(), testBucketName, "path/to/object", bytes.NewReader(wantBody))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if aws.ToString(out.ETag) == "" {
			t.Error("ETag should not be empty")
		}
	})

	t.Run("api error propagates", func(t *testing.T) {
		t.Parallel()
		mockS3 := &mockS3Client{
			PutObjectFunc: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
				return nil, errors.New("AccessDenied: User does not have permission")
			},
		}

		svc := (&S3Service{api: mockS3})
		if _, err := svc.PutObject(context.Background(), testBucketName, "k", bytes.NewReader(nil)); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
