module github.com/crossbearing/crossbearing

go 1.26.0

// Patch-current toolchain: govulncheck gates CI, and GO-2026-5856
// (crypto/tls) is reachable from this module's call graph below
// go1.26.5.
toolchain go1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.42.1
	github.com/aws/aws-sdk-go-v2/config v1.32.28
	github.com/aws/aws-sdk-go-v2/credentials v1.19.27
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.57.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.55.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.54.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.44.0
	github.com/aws/smithy-go v1.27.3
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.31 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.3.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.32.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.37.0 // indirect
)
