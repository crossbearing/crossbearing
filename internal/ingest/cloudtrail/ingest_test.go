package cloudtrail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// mockEventsAPI serves scripted LookupEvents pages and records the inputs
// it was called with.
type mockEventsAPI struct {
	pages  []*ct.LookupEventsOutput
	inputs []*ct.LookupEventsInput
	err    error
}

func (m *mockEventsAPI) LookupEvents(ctx context.Context, input *ct.LookupEventsInput) (*ct.LookupEventsOutput, error) {
	m.inputs = append(m.inputs, input)
	if m.err != nil {
		return nil, m.err
	}
	page := m.pages[0]
	m.pages = m.pages[1:]
	return page, nil
}

func envelope(id, raw string, at time.Time) cttypes.Event {
	return cttypes.Event{
		EventId:         awssdk.String(id),
		CloudTrailEvent: awssdk.String(raw),
		EventTime:       awssdk.Time(at),
	}
}

var (
	testFrom = time.Date(2026, 6, 9, 11, 0, 0, 0, time.UTC)
	testTo   = time.Date(2026, 6, 9, 13, 0, 0, 0, time.UTC)
)

func TestIngest_PagesAndMapsRecords(t *testing.T) {
	t.Parallel()
	api := &mockEventsAPI{
		pages: []*ct.LookupEventsOutput{
			{
				Events:    []cttypes.Event{envelope("evt-assume-1", rawAssumeRoleEvent, testFrom)},
				NextToken: awssdk.String("page-2"),
			},
			{
				Events: []cttypes.Event{envelope("evt-001", rawAssumedRoleEvent, testFrom)},
			},
		},
	}
	g := New(api, nil, Options{})

	res, err := g.Ingest(context.Background(), testFrom, testTo)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}

	// Pagination: two calls, second carries the token, both carry the window.
	if len(api.inputs) != 2 {
		t.Fatalf("LookupEvents calls = %d, want 2", len(api.inputs))
	}
	if got := awssdk.ToString(api.inputs[1].NextToken); got != "page-2" {
		t.Errorf("second call NextToken = %q, want page-2", got)
	}
	for i, in := range api.inputs {
		if !in.StartTime.Equal(testFrom) || !in.EndTime.Equal(testTo) {
			t.Errorf("call %d window = [%v, %v], want [%v, %v]", i, in.StartTime, in.EndTime, testFrom, testTo)
		}
		if awssdk.ToInt32(in.MaxResults) != 50 {
			t.Errorf("call %d MaxResults = %d, want 50", i, awssdk.ToInt32(in.MaxResults))
		}
	}

	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(res.Records))
	}

	rec := res.Records[1] // the s3 PutObject from the assumed-role session
	if rec.ID != "evt-001" {
		t.Errorf("ID = %q, want evt-001", rec.ID)
	}
	if rec.Source != corroborate.SourceCloudTrail {
		t.Errorf("Source = %q, want %q", rec.Source, corroborate.SourceCloudTrail)
	}
	if rec.Operation != "s3:PutObject" {
		t.Errorf("Operation = %q, want s3:PutObject", rec.Operation)
	}
	if rec.SourceIdentity != "bs@example.com" {
		t.Errorf("SourceIdentity = %q, want bs@example.com", rec.SourceIdentity)
	}
	if want := "aws-cloudtrail:us-east-1/evt-001"; rec.Raw.Locator != want {
		t.Errorf("Locator = %q, want %q", rec.Raw.Locator, want)
	}
	sum := sha256.Sum256([]byte(rawAssumedRoleEvent))
	if want := hex.EncodeToString(sum[:]); rec.Raw.Digest != want {
		t.Errorf("Digest = %q, want sha256 of the raw JSON as ingested", rec.Raw.Digest)
	}
}

func TestIngest_RefusesErroredEvents(t *testing.T) {
	t.Parallel()
	// A denied call is an attempt, not a record of the action happening —
	// it must not become a Record it could later corroborate a claim with.
	denied := `{"eventID":"evt-denied","eventTime":"2026-06-09T11:05:00Z",` +
		`"eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy",` +
		`"awsRegion":"us-east-1","errorCode":"AccessDenied",` +
		`"userIdentity":{"type":"AssumedRole",` +
		`"arn":"arn:aws:sts::111122223333:assumed-role/x/y","accessKeyId":"ASIAX"}}`
	api := &mockEventsAPI{
		pages: []*ct.LookupEventsOutput{
			{Events: []cttypes.Event{
				envelope("evt-001", rawAssumedRoleEvent, testFrom),
				envelope("evt-denied", denied, testFrom),
			}},
		},
	}
	g := New(api, nil, Options{})

	res, err := g.Ingest(context.Background(), testFrom, testTo)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1 (the errored event refused)", len(res.Records))
	}
	if res.Records[0].ID != "evt-001" {
		t.Errorf("kept record = %q, want evt-001", res.Records[0].ID)
	}
}

func TestIngest_ProductionScope(t *testing.T) {
	t.Parallel()
	api := &mockEventsAPI{
		pages: []*ct.LookupEventsOutput{
			{Events: []cttypes.Event{envelope("evt-001", rawAssumedRoleEvent, testFrom)}},
		},
	}
	g := New(api, nil, Options{
		IsProduction: func(target string) bool { return strings.Contains(target, ":::prod-") },
	})

	res, err := g.Ingest(context.Background(), testFrom, testTo)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	if !res.Records[0].ProductionTouching {
		t.Error("ProductionTouching = false for a prod-artifacts target")
	}
}

func TestIngest_FallsBackToEnvelopeOnBadRaw(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 6, 9, 12, 30, 0, 0, time.UTC)
	ev := envelope("evt-broken", `{"eventID": not-json`, at)
	ev.EventName = awssdk.String("DeleteObject")
	ev.EventSource = awssdk.String("s3.amazonaws.com")
	ev.Resources = []cttypes.Resource{{ResourceName: awssdk.String("prod-artifacts")}}

	api := &mockEventsAPI{pages: []*ct.LookupEventsOutput{{Events: []cttypes.Event{ev}}}}
	g := New(api, nil, Options{})

	res, err := g.Ingest(context.Background(), testFrom, testTo)
	if err != nil {
		t.Fatalf("Ingest() error = %v", err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1 (window must stay total)", len(res.Records))
	}
	rec := res.Records[0]
	if rec.ID != "evt-broken" {
		t.Errorf("ID = %q, want evt-broken", rec.ID)
	}
	if rec.Operation != "s3:DeleteObject" {
		t.Errorf("Operation = %q, want s3:DeleteObject", rec.Operation)
	}
	if !rec.RecordedAt.Equal(at) {
		t.Errorf("RecordedAt = %v, want envelope time %v", rec.RecordedAt, at)
	}
	if len(rec.Targets) != 1 || rec.Targets[0] != "prod-artifacts" {
		t.Errorf("Targets = %v, want envelope resource names", rec.Targets)
	}
	// Even a salvaged record digests whatever raw bytes were ingested.
	if rec.Raw.Digest == "" {
		t.Error("Digest is empty; provenance must always be present")
	}
}

func TestIngest_APIErrorPropagates(t *testing.T) {
	t.Parallel()
	api := &mockEventsAPI{err: errors.New("throttled")}
	g := New(api, nil, Options{})
	if _, err := g.Ingest(context.Background(), testFrom, testTo); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNew_ClampsPageSize(t *testing.T) {
	t.Parallel()
	for _, size := range []int32{0, -1, 51, 500} {
		g := New(&mockEventsAPI{}, nil, Options{PageSize: size})
		if g.opts.PageSize != 50 {
			t.Errorf("PageSize %d clamped to %d, want 50", size, g.opts.PageSize)
		}
	}
	g := New(&mockEventsAPI{}, nil, Options{PageSize: 10})
	if g.opts.PageSize != 10 {
		t.Errorf("PageSize 10 changed to %d, want kept", g.opts.PageSize)
	}
}
