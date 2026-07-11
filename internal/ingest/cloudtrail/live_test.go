package cloudtrail

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	awsint "github.com/crossbearing/crossbearing/internal/aws"
	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// TestLive_Ingest validates the ingester against a real AWS account: the
// behaviors mocks cannot prove — delivery lag, real event-JSON shapes
// across services, LookupEvents throttling under paging, and whether
// SourceIdentity / session tags actually appear on real sessions.
//
// Skipped unless CROSSBEARING_LIVE=1. Credentials come from the default
// chain (set AWS_PROFILE). Read-only: LookupEvents is the only call made.
//
//	CROSSBEARING_LIVE=1 AWS_PROFILE=... go test ./internal/ingest/cloudtrail -run TestLive -v
func TestLive_Ingest(t *testing.T) {
	if os.Getenv("CROSSBEARING_LIVE") != "1" {
		t.Skip("set CROSSBEARING_LIVE=1 to run against a real account")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-west-2"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	client, err := awsint.NewClient(ctx, awsint.ClientConfig{Region: region}, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	to := time.Now()
	from := to.Add(-12 * time.Hour)
	g := New(awsint.NewCloudTrailService(client), logger, Options{
		SessionTagKeys: []string{"operator", "human", "owner"},
	})

	res, err := g.Ingest(ctx, from, to)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(res.Records) == 0 {
		t.Fatal("no records in a 12h window; expected at least the credentials' own STS activity")
	}

	// Every record must satisfy the provenance hard rule.
	var withSourceIdentity, productionEligible int
	var newest time.Time
	for _, r := range res.Records {
		if r.ID == "" || r.Raw.Digest == "" || r.Raw.Locator == "" {
			t.Errorf("record missing identity/provenance: %+v", r)
		}
		if r.RecordedAt.IsZero() {
			t.Errorf("record %s has zero RecordedAt", r.ID)
		}
		if r.SourceIdentity != "" {
			withSourceIdentity++
		}
		if len(r.Targets) > 0 {
			productionEligible++
		}
		if r.RecordedAt.After(newest) {
			newest = r.RecordedAt
		}
	}

	// Delivery lag: how stale is the newest visible event vs wall clock?
	lag := time.Since(newest).Round(time.Second)
	t.Logf("delivery lag: newest visible event is %v old (expect up to ~15m)", lag)
	t.Logf("records: %d total, %d with sourceIdentity, %d with resource targets",
		len(res.Records), withSourceIdentity, productionEligible)

	t.Logf("sessions: %d", len(res.Sessions))
	for _, s := range res.Sessions {
		human := s.Human
		if human == "" {
			human = "<unattributed>"
		}
		t.Logf("  session %s agent=%q human=%s method=%s window=[%s → %s] evidence=%d",
			s.ID, s.Agent, human, s.Attribution.Method,
			s.StartedAt.Format(time.RFC3339), s.EndedAt.Format(time.RFC3339),
			len(s.Attribution.Evidence))
		if s.Attribution.Method != corroborate.AttrNone && len(s.Attribution.Evidence) == 0 {
			t.Errorf("session %s claims binding %q with no evidence", s.ID, s.Attribution.Method)
		}
	}
}
