package aws

import (
	"fmt"
	"strings"
)

// ARN represents a parsed Amazon Resource Name.
//
// Format: arn:partition:service:region:account-id:resource-type/resource-id
// or:     arn:partition:service:region:account-id:resource-type:resource-id
type ARN struct {
	Partition string
	Service   string
	Region    string
	AccountID string
	Resource  string
}

// String returns the canonical ARN string representation.
func (a ARN) String() string {
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s",
		a.Partition, a.Service, a.Region, a.AccountID, a.Resource)
}

// ResourceType extracts the resource type from the resource portion.
// For "instance/i-1234", returns "instance". For "i-1234", returns "".
func (a ARN) ResourceType() string {
	if idx := strings.IndexAny(a.Resource, "/:"); idx >= 0 {
		return a.Resource[:idx]
	}
	return ""
}

// ResourceID extracts the resource ID from the resource portion.
// For "instance/i-1234", returns "i-1234". For "i-1234", returns "i-1234".
func (a ARN) ResourceID() string {
	if idx := strings.IndexAny(a.Resource, "/:"); idx >= 0 {
		return a.Resource[idx+1:]
	}
	return a.Resource
}

// ParseARN parses an ARN string into its components.
func ParseARN(arn string) (ARN, error) {
	if !strings.HasPrefix(arn, "arn:") {
		return ARN{}, fmt.Errorf("invalid ARN: must start with 'arn:': %q", arn)
	}

	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ARN{}, fmt.Errorf("invalid ARN: expected at least 6 colon-separated components, got %d: %q", len(parts), arn)
	}

	parsed := ARN{
		Partition: parts[1],
		Service:   parts[2],
		Region:    parts[3],
		AccountID: parts[4],
		Resource:  parts[5],
	}

	if err := validateARNComponents(parsed); err != nil {
		return ARN{}, fmt.Errorf("invalid ARN %q: %w", arn, err)
	}

	return parsed, nil
}

// ValidateARN validates that the given string is a well-formed ARN.
func ValidateARN(arn string) error {
	_, err := ParseARN(arn)
	return err
}

// ValidateARNForService validates the ARN is well-formed and belongs to the expected service.
func ValidateARNForService(arn, service string) error {
	parsed, err := ParseARN(arn)
	if err != nil {
		return err
	}
	if parsed.Service != service {
		return fmt.Errorf("ARN service mismatch: expected %q, got %q in %q", service, parsed.Service, arn)
	}
	return nil
}

// ValidateARNForServiceAndRegion validates ARN, service, and region.
func ValidateARNForServiceAndRegion(arn, service, region string) error {
	parsed, err := ParseARN(arn)
	if err != nil {
		return err
	}
	if parsed.Service != service {
		return fmt.Errorf("ARN service mismatch: expected %q, got %q in %q", service, parsed.Service, arn)
	}
	if region != "" && parsed.Region != "" && parsed.Region != region {
		return fmt.Errorf("ARN region mismatch: expected %q, got %q in %q", region, parsed.Region, arn)
	}
	return nil
}

// IsARN returns true if the string looks like an ARN.
func IsARN(s string) bool {
	return strings.HasPrefix(s, "arn:")
}

var validPartitions = map[string]bool{
	"aws":        true,
	"aws-cn":     true,
	"aws-us-gov": true,
	"aws-iso":    true,
	"aws-iso-b":  true,
	"aws-iso-e":  true,
	"aws-iso-f":  true,
}

func validateARNComponents(a ARN) error {
	if a.Partition == "" {
		return fmt.Errorf("partition must not be empty")
	}
	if !validPartitions[a.Partition] {
		return fmt.Errorf("unknown partition %q", a.Partition)
	}
	if a.Service == "" {
		return fmt.Errorf("service must not be empty")
	}
	if a.Resource == "" {
		return fmt.Errorf("resource must not be empty")
	}
	return nil
}
