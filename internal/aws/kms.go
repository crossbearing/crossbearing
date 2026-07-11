package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// kmsAPI is the narrow SDK surface KMSService uses; production resolves
// it from the shared Client, tests inject a mock so the REAL service
// methods (not a shim) are what the suite exercises.
type kmsAPI interface {
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

// KMSService provides operations for AWS Key Management Service.
type KMSService struct {
	client *Client
	api    kmsAPI // test seam; nil means resolve from client
}

// NewKMSService creates a new KMS service.
func NewKMSService(client *Client) *KMSService {
	return &KMSService{client: client}
}

func (s *KMSService) sdk() kmsAPI {
	if s.api != nil {
		return s.api
	}
	return s.client.KMS()
}

// DescribeKeyOutput contains the result of describing a KMS key.
type DescribeKeyOutput struct {
	KeyId              string
	ARN                string
	Description        string
	KeyState           string
	KeyUsage           string
	KeySpec            string
	Enabled            bool
	MultiRegion        bool
	CreationDate       *int64
	DeletionDate       *int64
	KeyRotationEnabled bool
}

// DescribeKey describes a KMS key.
func (s *KMSService) DescribeKey(ctx context.Context, keyId string) (*DescribeKeyOutput, error) {
	result, err := s.sdk().DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyId),
	})
	if err != nil {
		var notFound *types.NotFoundException
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to describe KMS key: %w", err)
	}

	metadata := result.KeyMetadata
	output := &DescribeKeyOutput{
		KeyId:       aws.ToString(metadata.KeyId),
		ARN:         aws.ToString(metadata.Arn),
		Description: aws.ToString(metadata.Description),
		KeyState:    string(metadata.KeyState),
		KeyUsage:    string(metadata.KeyUsage),
		KeySpec:     string(metadata.KeySpec),
		Enabled:     metadata.Enabled,
		MultiRegion: aws.ToBool(metadata.MultiRegion),
	}

	if metadata.CreationDate != nil {
		ts := metadata.CreationDate.Unix()
		output.CreationDate = &ts
	}

	if metadata.DeletionDate != nil {
		ts := metadata.DeletionDate.Unix()
		output.DeletionDate = &ts
	}

	// Check key rotation status
	rotationResult, err := s.sdk().GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyId),
	})
	if err == nil {
		output.KeyRotationEnabled = rotationResult.KeyRotationEnabled
	}

	return output, nil
}

// Sign signs a message or digest with an asymmetric KMS key.
// Thin typed pass-through to the KMS Sign API.
func (s *KMSService) Sign(ctx context.Context, input *kms.SignInput) (*kms.SignOutput, error) {
	result, err := s.sdk().Sign(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with KMS key: %w", err)
	}
	return result, nil
}

// Verify verifies a signature against a message or digest with an asymmetric
// KMS key. Thin typed pass-through to the KMS Verify API.
func (s *KMSService) Verify(ctx context.Context, input *kms.VerifyInput) (*kms.VerifyOutput, error) {
	result, err := s.sdk().Verify(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to verify with KMS key: %w", err)
	}
	return result, nil
}
