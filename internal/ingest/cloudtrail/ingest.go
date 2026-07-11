package cloudtrail

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// EventsAPI is the one CloudTrail call this ingester needs. It is satisfied
// by *aws.CloudTrailService (internal/aws) and by mocks in tests.
type EventsAPI interface {
	LookupEvents(ctx context.Context, input *ct.LookupEventsInput) (*ct.LookupEventsOutput, error)
}

// Options bound the ingester's behavior. The zero value is usable.
type Options struct {
	// PageSize is the LookupEvents page size; the API maximum (50) is the
	// default and almost always right — LookupEvents is rate-limited to
	// 2 requests/second, so bigger pages mean fewer throttles.
	PageSize int32

	// SessionTagKeys are the sts:TagSession keys treated as carrying a human
	// identity (e.g. "operator", "human"). Checked in order; first key
	// present on the AssumeRole event wins. Empty means tag-based
	// attribution is off.
	SessionTagKeys []string

	// SessionGap is how long an assumed-role principal must be silent
	// before its next event starts a new Session window. Defaults to 30
	// minutes — comfortably above CloudTrail's ~15-minute delivery lag so
	// late-arriving events don't split a live session.
	SessionGap time.Duration

	// IsProduction reports whether a target ARN falls inside the configured
	// production scope; matching records escalate finding severity. Nil
	// means nothing is marked production-touching.
	IsProduction func(target string) bool
}

const (
	defaultPageSize   = 50
	defaultSessionGap = 30 * time.Minute
)

// Result is one ingestion window's output: every management event as a
// Record, and the assumed-role activity windowed into Sessions.
type Result struct {
	Records  []corroborate.Record
	Sessions []corroborate.Session
}

// Ingester pages CloudTrail LookupEvents into corroborate types.
type Ingester struct {
	api  EventsAPI
	log  *slog.Logger
	opts Options
}

// New creates an Ingester. A nil logger discards logs.
func New(api EventsAPI, logger *slog.Logger, opts Options) *Ingester {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if opts.PageSize <= 0 || opts.PageSize > defaultPageSize {
		opts.PageSize = defaultPageSize
	}
	if opts.SessionGap <= 0 {
		opts.SessionGap = defaultSessionGap
	}
	return &Ingester{api: api, log: logger.With("component", "ingest-cloudtrail"), opts: opts}
}

// Ingest pages all management events in [from, to] and returns them as
// Records plus the Sessions windowed out of assumed-role activity.
//
// Callers own the lag question: CloudTrail delivers events up to ~15
// minutes late, so a window whose upper bound is near now() is not settled
// and should be re-ingested once the lag has passed.
func (g *Ingester) Ingest(ctx context.Context, from, to time.Time) (Result, error) {
	var (
		records   []corroborate.Record
		extracted []Extracted
		pages     int
		errored   int
	)

	input := &ct.LookupEventsInput{
		StartTime:  &from,
		EndTime:    &to,
		MaxResults: awssdk.Int32(g.opts.PageSize),
	}
	for {
		out, err := g.api.LookupEvents(ctx, input)
		if err != nil {
			return Result{}, fmt.Errorf("failed to page cloudtrail events (page %d): %w", pages+1, err)
		}
		pages++

		for _, ev := range out.Events {
			raw := awssdk.ToString(ev.CloudTrailEvent)
			ex, err := ExtractRaw([]byte(raw))
			if err != nil {
				// An unparseable raw document still has a lookup envelope;
				// record it from that so the window stays total, minus the
				// identity fields only the raw JSON carries.
				g.log.Warn("falling back to lookup envelope for unparseable event",
					"eventID", awssdk.ToString(ev.EventId), "error", err)
				ex = extractedFromEnvelope(ev)
			}
			if ex.EventID == "" {
				ex.EventID = awssdk.ToString(ev.EventId)
			}
			if ex.EventTime.IsZero() && ev.EventTime != nil {
				ex.EventTime = *ev.EventTime
			}
			// A denied or failed call must not corroborate a claim of
			// success — an errored event is an attempt, not a record.
			// (The envelope-salvage path above cannot see errorCode; a
			// salvaged event is kept, favoring a total window.)
			if ex.ErrorCode != "" {
				errored++
				continue
			}
			records = append(records, g.record(ex, raw))
			extracted = append(extracted, ex)
		}

		next := awssdk.ToString(out.NextToken)
		if next == "" {
			break
		}
		input.NextToken = out.NextToken
	}

	sessions := g.sessions(extracted)
	g.log.Info("ingested cloudtrail window",
		"from", from, "to", to,
		"pages", pages, "records", len(records), "sessions", len(sessions),
		"errored", errored)
	return Result{Records: records, Sessions: sessions}, nil
}

// IngestFile ingests captured CloudTrail events from a file: a JSON array
// of raw CloudTrail event objects (the CloudTrailEvent payload shape that
// ExtractRaw parses, e.g. `aws cloudtrail lookup-events
// --query 'Events[].CloudTrailEvent'` after un-stringifying, or hand-authored
// fixtures). The offline counterpart to Ingest — for replaying captured
// events, air-gapped review, and the demo. Record and session mapping are
// shared with the live path exactly, so an offline run is byte-faithful.
func (g *Ingester) IngestFile(path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to read cloudtrail file: %w", err)
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return Result{}, fmt.Errorf("failed to parse cloudtrail file (expected a JSON array of event objects): %w", err)
	}

	var (
		records   []corroborate.Record
		extracted []Extracted
		errored   int
	)
	for _, raw := range raws {
		ex, err := ExtractRaw(raw)
		if err != nil {
			g.log.Warn("skipping unparseable captured cloudtrail event", "error", err)
			continue
		}
		// Same refusal as the live path: an errored event is an attempt,
		// not a record of the action happening.
		if ex.ErrorCode != "" {
			errored++
			continue
		}
		records = append(records, g.record(ex, string(raw)))
		extracted = append(extracted, ex)
	}
	sessions := g.sessions(extracted)
	g.log.Info("ingested cloudtrail file", "path", path,
		"records", len(records), "sessions", len(sessions), "errored", errored)
	return Result{Records: records, Sessions: sessions}, nil
}

// record maps one extracted event onto the corroborate vocabulary. The
// provenance digest covers the raw JSON exactly as ingested, and the
// locator is the LookupEvents coordinate (region + event ID) the event can
// be re-fetched at.
func (g *Ingester) record(ex Extracted, raw string) corroborate.Record {
	rec := corroborate.Record{
		ID:             ex.EventID,
		Source:         corroborate.SourceCloudTrail,
		Operation:      ex.Operation(),
		Principal:      ex.Principal,
		SourceIdentity: ex.SourceIdentity,
		AccessKeyID:    ex.AccessKeyID,
		Targets:        ex.Targets,
		RecordedAt:     ex.EventTime,
		Raw: corroborate.Provenance{
			Locator: "aws-cloudtrail:" + ex.Region + "/" + ex.EventID,
			Digest:  corroborate.DigestHex([]byte(raw)),
		},
	}
	if g.opts.IsProduction != nil {
		for _, t := range ex.Targets {
			if g.opts.IsProduction(t) {
				rec.ProductionTouching = true
				break
			}
		}
	}
	return rec
}

// extractedFromEnvelope salvages what the LookupEvents envelope itself
// carries when the raw CloudTrailEvent JSON is missing or malformed.
func extractedFromEnvelope(ev cttypes.Event) Extracted {
	ex := Extracted{
		EventID:     awssdk.ToString(ev.EventId),
		EventName:   awssdk.ToString(ev.EventName),
		EventSource: awssdk.ToString(ev.EventSource),
	}
	if ev.EventTime != nil {
		ex.EventTime = *ev.EventTime
	}
	for _, r := range ev.Resources {
		if n := awssdk.ToString(r.ResourceName); n != "" {
			ex.Targets = append(ex.Targets, n)
		}
	}
	return ex
}
