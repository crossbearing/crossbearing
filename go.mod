module github.com/crossbearing/crossbearing

go 1.26.0

// Toolchain pin. go.sum is lean, so the standard library is most of the
// third-party code this binary ships, and stdlib advisories are the bulk of
// what govulncheck reports against it.
//
// Kept on the newest Go release: Renovate proposes each one through the
// go-toolchain group, and the full gate has to pass on it before it lands.
// CI also runs govulncheck on a schedule as well as on push, so an advisory
// disclosed against an unchanged tree fails the build rather than waiting for
// the next commit to notice it.
toolchain go1.27.4

require (
	github.com/aws/aws-sdk-go-v2 v1.47.8
	github.com/aws/aws-sdk-go-v2/config v1.33.16
	github.com/aws/aws-sdk-go-v2/credentials v1.20.16
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.65.11
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.9
	github.com/aws/aws-sdk-go-v2/service/kms v1.62.5
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.9
	github.com/aws/smithy-go v1.28.8
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.4 // indirect
)
