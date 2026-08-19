module github.com/crossbearing/crossbearing

go 1.26.0

// Patch-current toolchain. go.sum is deliberately lean, so the standard
// library is most of the third-party code this binary ships — and it is
// govulncheck's most frequent finding here. Six stdlib advisories were
// reachable from this module's call graph below go1.26.6: GO-2026-6218
// net/url, GO-2026-6091 html/template, GO-2026-6090 crypto/tls,
// GO-2026-6088 encoding/xml, GO-2026-5972 encoding/asn1, GO-2026-5026
// net/http.
//
// Bump this when the gate says to, not on a calendar. CI re-runs govulncheck
// weekly against an unchanged tree precisely so an advisory disclosed after
// the last push still fails the build (3f01890).
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
