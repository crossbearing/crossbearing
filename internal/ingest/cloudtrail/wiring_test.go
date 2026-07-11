package cloudtrail

import (
	"github.com/crossbearing/crossbearing/internal/aws"
)

// The production wiring: internal/aws's CloudTrail service must satisfy the
// ingester's API surface. A signature drift in either package fails this
// compile, not a customer deployment.
var _ EventsAPI = (*aws.CloudTrailService)(nil)
