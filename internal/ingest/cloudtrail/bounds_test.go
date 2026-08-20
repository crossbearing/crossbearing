package cloudtrail

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

// endlessEventsAPI always hands back another NextToken, modelling a window
// whose token never empties.
type endlessEventsAPI struct{ calls int }

func (e *endlessEventsAPI) LookupEvents(_ context.Context, _ *ct.LookupEventsInput) (*ct.LookupEventsOutput, error) {
	e.calls++
	return &ct.LookupEventsOutput{NextToken: awssdk.String("more")}, nil
}

// TestIngest_StopsAtThePageBound holds the pager to a finite number of pages.
// An empty NextToken is the only stopping condition the API itself offers, so
// a service-side cycle — or a window far wider than the operator realised —
// would otherwise spin until the run deadline and return nothing, which reads
// as a hang rather than as too much data.
func TestIngest_StopsAtThePageBound(t *testing.T) {
	api := &endlessEventsAPI{}
	g := New(api, slog.New(slog.DiscardHandler), Options{MaxPages: 5})

	_, err := g.Ingest(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("Ingest returned no error on a window that never terminates")
	}

	// It must be an ERROR, not a quiet truncation. A report built from a
	// silently capped window understates what happened in the account, and a
	// record never read is a record that cannot be reported as unattributed.
	if !strings.Contains(err.Error(), "did not terminate") {
		t.Errorf("error %q does not say the window failed to terminate", err)
	}
	if !strings.Contains(err.Error(), "5 pages") {
		t.Errorf("error %q does not name the bound it hit", err)
	}
	if api.calls > 6 {
		t.Errorf("made %d calls for a 5-page bound; the bound is not holding", api.calls)
	}
}

// TestIngest_PageBoundDefaultsWhenUnset keeps the zero value usable, as the
// Options doc promises.
func TestIngest_PageBoundDefaultsWhenUnset(t *testing.T) {
	g := New(&endlessEventsAPI{}, nil, Options{})
	if g.opts.MaxPages != defaultMaxPages {
		t.Errorf("MaxPages = %d, want the default %d", g.opts.MaxPages, defaultMaxPages)
	}
}

// TestIngest_SinglePageWindowDoesNotTripTheBound guards the other direction:
// the bound must be invisible to every normal run. The validated live window
// read ten pages.
func TestIngest_SinglePageWindowDoesNotTripTheBound(t *testing.T) {
	api := &mockEventsAPI{pages: []*ct.LookupEventsOutput{{}}}
	g := New(api, nil, Options{MaxPages: 1})
	if _, err := g.Ingest(context.Background(), time.Now().Add(-time.Hour), time.Now()); err != nil {
		t.Fatalf("a window that fits in one page tripped the bound: %v", err)
	}
}
