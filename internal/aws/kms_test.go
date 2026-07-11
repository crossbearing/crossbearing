package aws

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// =============================================================================
// KMS Mock Interface and Implementation
// =============================================================================

// mockKMSClient is a mock implementation of kmsAPI.
type mockKMSClient struct {
	DescribeKeyFunc          func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatusFunc func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
	SignFunc                 func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	VerifyFunc               func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

func (m *mockKMSClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if m.DescribeKeyFunc != nil {
		return m.DescribeKeyFunc(ctx, params, optFns...)
	}
	return &kms.DescribeKeyOutput{}, nil
}

func (m *mockKMSClient) GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	if m.GetKeyRotationStatusFunc != nil {
		return m.GetKeyRotationStatusFunc(ctx, params, optFns...)
	}
	return &kms.GetKeyRotationStatusOutput{}, nil
}

func (m *mockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if m.SignFunc != nil {
		return m.SignFunc(ctx, params, optFns...)
	}
	return &kms.SignOutput{}, nil
}

func (m *mockKMSClient) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, params, optFns...)
	}
	return &kms.VerifyOutput{}, nil
}

// Compile-time interface compliance check.
var _ kmsAPI = (*mockKMSClient)(nil)

// =============================================================================
// Tests
// =============================================================================

const (
	testKeyId  = "1234abcd-12ab-34cd-56ef-1234567890ab"
	testKeyARN = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
)

var testKeyCreation = time.Date(2026, 1, 10, 8, 0, 0, 0, time.UTC)

func makeTestKeyMetadata() *kmstypes.KeyMetadata {
	return &kmstypes.KeyMetadata{
		KeyId:        aws.String(testKeyId),
		Arn:          aws.String(testKeyARN),
		Description:  aws.String("Test KMS key"),
		KeyState:     kmstypes.KeyStateEnabled,
		KeyUsage:     kmstypes.KeyUsageTypeEncryptDecrypt,
		KeySpec:      kmstypes.KeySpecSymmetricDefault,
		Enabled:      true,
		MultiRegion:  aws.Bool(false),
		CreationDate: aws.Time(testKeyCreation),
	}
}

func TestKMSService_DescribeKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		keyId     string
		setupMock func(*mockKMSClient)
		wantErr   bool
		wantNil   bool
		validate  func(t *testing.T, output *DescribeKeyOutput)
	}{
		{
			name:  "success returns key details with rotation enabled",
			keyId: testKeyId,
			setupMock: func(m *mockKMSClient) {
				m.DescribeKeyFunc = func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					if got := aws.ToString(params.KeyId); got != testKeyId {
						t.Errorf("DescribeKey KeyId = %q, want %q", got, testKeyId)
					}
					return &kms.DescribeKeyOutput{
						KeyMetadata: makeTestKeyMetadata(),
					}, nil
				}
				m.GetKeyRotationStatusFunc = func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
					return &kms.GetKeyRotationStatusOutput{
						KeyRotationEnabled: true,
					}, nil
				}
			},
			wantErr: false,
			validate: func(t *testing.T, output *DescribeKeyOutput) {
				if output == nil {
					t.Fatal("output should not be nil")
				}
				if output.KeyId != testKeyId {
					t.Errorf("KeyId = %q, want %q", output.KeyId, testKeyId)
				}
				if output.ARN != testKeyARN {
					t.Errorf("ARN = %q, want %q", output.ARN, testKeyARN)
				}
				if output.Description != "Test KMS key" {
					t.Errorf("Description = %q, want %q", output.Description, "Test KMS key")
				}
				if output.KeyState != string(kmstypes.KeyStateEnabled) {
					t.Errorf("KeyState = %q, want %q", output.KeyState, string(kmstypes.KeyStateEnabled))
				}
				if output.KeyUsage != string(kmstypes.KeyUsageTypeEncryptDecrypt) {
					t.Errorf("KeyUsage = %q, want %q", output.KeyUsage, string(kmstypes.KeyUsageTypeEncryptDecrypt))
				}
				if !output.Enabled {
					t.Error("Enabled should be true")
				}
				if output.MultiRegion {
					t.Error("MultiRegion should be false")
				}
				if !output.KeyRotationEnabled {
					t.Error("KeyRotationEnabled should be true")
				}
				if output.CreationDate == nil {
					t.Fatal("CreationDate should not be nil")
				}
				if output.DeletionDate != nil {
					t.Error("DeletionDate should be nil")
				}
			},
		},
		{
			name:  "success with rotation check error still returns key",
			keyId: testKeyId,
			setupMock: func(m *mockKMSClient) {
				m.DescribeKeyFunc = func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					return &kms.DescribeKeyOutput{
						KeyMetadata: makeTestKeyMetadata(),
					}, nil
				}
				m.GetKeyRotationStatusFunc = func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
					return nil, errors.New("api error: unsupported operation")
				}
			},
			wantErr: false,
			validate: func(t *testing.T, output *DescribeKeyOutput) {
				if output == nil {
					t.Fatal("output should not be nil")
				}
				if output.KeyId != testKeyId {
					t.Errorf("KeyId = %q, want %q", output.KeyId, testKeyId)
				}
				if output.KeyRotationEnabled {
					t.Error("KeyRotationEnabled should be false when rotation check fails")
				}
			},
		},
		{
			name:  "success with pending deletion key",
			keyId: testKeyId,
			setupMock: func(m *mockKMSClient) {
				m.DescribeKeyFunc = func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					deletionTime := time.Date(2026, 2, 15, 10, 30, 0, 0, time.UTC)
					metadata := makeTestKeyMetadata()
					metadata.KeyState = kmstypes.KeyStatePendingDeletion
					metadata.Enabled = false
					metadata.DeletionDate = aws.Time(deletionTime)
					return &kms.DescribeKeyOutput{
						KeyMetadata: metadata,
					}, nil
				}
				m.GetKeyRotationStatusFunc = func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
					return &kms.GetKeyRotationStatusOutput{}, nil
				}
			},
			wantErr: false,
			validate: func(t *testing.T, output *DescribeKeyOutput) {
				if output == nil {
					t.Fatal("output should not be nil")
				}
				if output.KeyState != string(kmstypes.KeyStatePendingDeletion) {
					t.Errorf("KeyState = %q, want %q", output.KeyState, string(kmstypes.KeyStatePendingDeletion))
				}
				if output.Enabled {
					t.Error("Enabled should be false")
				}
				if output.DeletionDate == nil {
					t.Fatal("DeletionDate should not be nil")
				}
			},
		},
		{
			name:  "not found returns nil",
			keyId: "nonexistent-key",
			setupMock: func(m *mockKMSClient) {
				m.DescribeKeyFunc = func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					return nil, &kmstypes.NotFoundException{Message: aws.String("key not found")}
				}
			},
			wantErr: false,
			wantNil: true,
		},
		{
			name:  "api error",
			keyId: testKeyId,
			setupMock: func(m *mockKMSClient) {
				m.DescribeKeyFunc = func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					return nil, errors.New("api error: access denied")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockClient := &mockKMSClient{}
			if tt.setupMock != nil {
				tt.setupMock(mockClient)
			}

			svc := (&KMSService{api: mockClient})
			got, err := svc.DescribeKey(context.Background(), tt.keyId)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil output, got %+v", got)
				}
				return
			}

			if tt.validate != nil {
				tt.validate(t, got)
			}
		})
	}
}

func TestKMSService_Sign(t *testing.T) {
	t.Parallel()
	t.Run("success forwards input and returns signature", func(t *testing.T) {
		t.Parallel()
		wantSignature := []byte("test-signature")
		mockClient := &mockKMSClient{
			SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
				if got := aws.ToString(params.KeyId); got != testKeyId {
					t.Errorf("Sign KeyId = %q, want %q", got, testKeyId)
				}
				if params.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 {
					t.Errorf("SigningAlgorithm = %q, want %q", params.SigningAlgorithm, kmstypes.SigningAlgorithmSpecEcdsaSha256)
				}
				return &kms.SignOutput{
					KeyId:     aws.String(testKeyARN),
					Signature: wantSignature,
				}, nil
			},
		}

		svc := (&KMSService{api: mockClient})
		out, err := svc.Sign(context.Background(), &kms.SignInput{
			KeyId:            aws.String(testKeyId),
			Message:          []byte("payload"),
			SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(out.Signature, wantSignature) {
			t.Errorf("Signature = %q, want %q", out.Signature, wantSignature)
		}
	})

	t.Run("api error propagates", func(t *testing.T) {
		t.Parallel()
		mockClient := &mockKMSClient{
			SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
				return nil, errors.New("api error: access denied")
			},
		}

		svc := (&KMSService{api: mockClient})
		if _, err := svc.Sign(context.Background(), &kms.SignInput{KeyId: aws.String(testKeyId)}); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestKMSService_Verify(t *testing.T) {
	t.Parallel()
	t.Run("success returns signature validity", func(t *testing.T) {
		t.Parallel()
		mockClient := &mockKMSClient{
			VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
				if got := aws.ToString(params.KeyId); got != testKeyId {
					t.Errorf("Verify KeyId = %q, want %q", got, testKeyId)
				}
				return &kms.VerifyOutput{
					KeyId:          aws.String(testKeyARN),
					SignatureValid: true,
				}, nil
			},
		}

		svc := (&KMSService{api: mockClient})
		out, err := svc.Verify(context.Background(), &kms.VerifyInput{
			KeyId:            aws.String(testKeyId),
			Message:          []byte("payload"),
			Signature:        []byte("test-signature"),
			SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !out.SignatureValid {
			t.Error("SignatureValid should be true")
		}
	})

	t.Run("api error propagates", func(t *testing.T) {
		t.Parallel()
		mockClient := &mockKMSClient{
			VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
				return nil, errors.New("api error: invalid signature format")
			},
		}

		svc := (&KMSService{api: mockClient})
		if _, err := svc.Verify(context.Background(), &kms.VerifyInput{KeyId: aws.String(testKeyId)}); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
