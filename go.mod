module github.com/crossbearing/crossbearing

go 1.26.0

// Toolchain pin. go.sum is lean, so the standard library is most of the
// third-party code this binary ships, and stdlib advisories are the bulk of
// what govulncheck reports against it.
//
// Advance this when the vulnerability gate fails, not on a calendar. CI runs
// govulncheck on a schedule as well as on push, so an advisory disclosed
// against an unchanged tree fails the build rather than waiting for the next
// commit to notice it.
toolchain go1.26.6

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
