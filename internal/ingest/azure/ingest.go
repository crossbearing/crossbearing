// Package azure ingests Azure Activity Log events into the corroborate
// vocabulary: each completed control-plane operation becomes a
// record-side corroborate.Record, and per-caller activity is windowed
// into corroborate.Sessions with the binding the event's identity carries.
//
// Input is what `az monitor activity-log list -o json` emits — a JSON
// array of EventData objects (or newline-delimited, if piped through
// `jq -c '.[]'`), via io.Reader. The EventData schema is declared
// locally: the lean-go.sum product property means no
// github.com/Azure/azure-sdk-for-go, and this ingester needs a dozen
// fields, not the ARM client.
//
// Azure expresses the same convention every record stream shares —
// "an agent acted for a human" — through the token's claims rather than a
// delegation chain. A human signs in and the caller IS their UPN
// (actor-identity). A service principal or managed identity acts on its
// own and the caller is a GUID with no human in the claims (unattributed,
// the gap). When a workload identity acts with a user-delegated token
// (the OAuth on-behalf-of flow), the caller is the workload but the
// claims carry the user's UPN — that UPN is the human the workload acted
// for, the Azure analogue of STS SourceIdentity / GCP delegation.
package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
	"github.com/crossbearing/crossbearing/internal/ingest"
)

// Azure stamps the caller's JWT claims into the event under these keys.
const (
	claimUPN  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
	claimName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
)

// Options bound the ingester's behavior. The zero value is usable.
type Options struct {
	// Subscription names the subscription the log came from; it anchors
	// locators so provenance says where an eventDataId can be re-fetched.
	Subscription string

	// SessionGap splits a caller's activity into separate Sessions after
	// this much silence. Defaults to 30 minutes, matching the other
	// record-side ingesters.
	SessionGap time.Duration

	// IsProduction marks targets inside the production scope (e.g. a
	// resourceId under a prod resource group). Nil means nothing is
	// production-touching.
	IsProduction func(target string) bool
}

const defaultSessionGap = 30 * time.Minute

// Result is one activity-log ingestion's output.
type Result struct {
	Records  []corroborate.Record
	Sessions []corroborate.Session
}

// Ingester parses Azure Activity Log JSON into corroborate types.
type Ingester struct {
	log  *slog.Logger
	opts Options
}

// New creates an Ingester. A nil logger discards logs.
func New(logger *slog.Logger, opts Options) *Ingester {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if opts.SessionGap <= 0 {
		opts.SessionGap = defaultSessionGap
	}
	return &Ingester{log: logger.With("component", "ingest-azure"), opts: opts}
}

// IngestFile ingests one activity-log file.
func (g *Ingester) IngestFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to open azure activity log: %w", err)
	}
	defer f.Close()
	return g.Ingest(f)
}

// eventData is the slice of an Azure Activity Log EventData this ingester
// reads.
type eventData struct {
	EventDataID    string    `json:"eventDataId"`
	EventTimestamp time.Time `json:"eventTimestamp"`
	OperationName  struct {
		Value string `json:"value"`
	} `json:"operationName"`
	ResourceID        string            `json:"resourceId"`
	ResourceGroupName string            `json:"resourceGroupName"`
	Caller            string            `json:"caller"`
	Claims            map[string]string `json:"claims"`
	Status            struct {
		Value string `json:"value"`
	} `json:"status"`
	Level string `json:"level"`
}

// effective reports whether this event is one completed operation — the
// only shape that becomes a Record. Azure logs Started → Succeeded for
// two-phase operations and Failed for denials/errors; dropping Started
// the only shape that becomes a Record. Validated against a real
// subscription's Activity Log: one resource operation logs as
// Started → Accepted → Succeeded (three entries), so recording any status
// but the terminal Succeeded double-counts it. Failed changed nothing;
// Active / Resolved / Updated are ServiceHealth / Advisor / ResourceHealth
// platform events, not actions. Record only the terminal success — plus
// status-less informational events, which carry no intermediate stage.
func (e *eventData) effective() bool {
	if e.EventDataID == "" || e.OperationName.Value == "" || e.Caller == "" {
		return false
	}
	return e.Status.Value == "Succeeded" || e.Status.Value == ""
}

// Ingest reads activity-log events from r: a JSON array (az cli) or
// newline-delimited events.
func (g *Ingester) Ingest(r io.Reader) (Result, error) {
	raws, bad, err := ingest.SplitJSONArrayOrLines(r)
	if err != nil {
		return Result{}, err
	}
	if bad > 0 {
		g.log.Warn("skipped unparseable azure activity entries", "entries", bad)
	}

	var (
		records  = []corroborate.Record{}
		byCaller = make(map[string][]corroborate.Record)
		skipped  int
	)
	for _, raw := range raws {
		var e eventData
		if err := json.Unmarshal(raw, &e); err != nil {
			skipped++
			continue
		}
		if !e.effective() {
			continue
		}
		rec := g.record(&e, raw)
		records = append(records, rec)
		byCaller[rec.Principal] = append(byCaller[rec.Principal], rec)
	}
	if skipped > 0 {
		g.log.Warn("skipped undecodable azure activity entries", "entries", skipped)
	}

	sessions := g.sessions(byCaller)
	g.log.Info("ingested azure activity log",
		"subscription", g.opts.Subscription, "records", len(records), "sessions", len(sessions))
	return Result{Records: records, Sessions: sessions}, nil
}

func (g *Ingester) record(e *eventData, raw []byte) corroborate.Record {
	var targets []string
	if e.ResourceID != "" {
		targets = append(targets, e.ResourceID)
	}

	rec := corroborate.Record{
		ID:         e.EventDataID,
		Source:     corroborate.SourceAzureActivity,
		Operation:  "azure-activity:" + e.OperationName.Value,
		Principal:  e.Caller,
		Targets:    targets,
		RecordedAt: e.EventTimestamp,
		Raw: corroborate.Provenance{
			Locator: "azure-activity:" + g.opts.Subscription + "#" + e.EventDataID,
			Digest:  corroborate.DigestHex(raw),
		},
	}
	// A workload caller (GUID, no @) acting with a user-delegated token:
	// the claims carry the human, recorded in the SourceIdentity slot the
	// same way STS SourceIdentity and GCP delegation use it.
	if !isHuman(e.Caller) {
		if human := humanFromClaims(e.Claims); human != "" {
			rec.SourceIdentity = human
		}
	}
	if g.opts.IsProduction != nil {
		for _, t := range targets {
			if g.opts.IsProduction(t) {
				rec.ProductionTouching = true
				break
			}
		}
	}
	return rec
}

// sessions windows each caller's activity. Binding precedence, strongest
// first:
//
//  1. a human caller (UPN) → actor-identity (a user authenticated as
//     themselves).
//  2. a workload caller carrying a human UPN in its claims →
//     azure-delegation (acted with a user-delegated token).
//  3. nothing: a bare service principal / managed identity stays
//     unattributed — the gap the convention checker exists to name.
func (g *Ingester) sessions(byCaller map[string][]corroborate.Record) []corroborate.Session {
	var out []corroborate.Session
	for caller, recs := range byCaller {
		sort.Slice(recs, func(i, j int) bool { return recs[i].RecordedAt.Before(recs[j].RecordedAt) })
		start := 0
		for i := 1; i <= len(recs); i++ {
			if i < len(recs) && recs[i].RecordedAt.Sub(recs[i-1].RecordedAt) <= g.opts.SessionGap {
				continue
			}
			out = append(out, g.session(caller, recs[start:i]))
			start = i
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.Before(out[j].StartedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (g *Ingester) session(caller string, window []corroborate.Record) corroborate.Session {
	first, last := window[0], window[len(window)-1]
	sub := g.opts.Subscription
	if sub == "" {
		sub = "subscription"
	}
	s := corroborate.Session{
		ID:          "azure:" + sub + "/" + caller + "@" + first.RecordedAt.UTC().Format(time.RFC3339),
		Agent:       caller,
		StartedAt:   first.RecordedAt,
		EndedAt:     last.RecordedAt,
		Attribution: corroborate.Attribution{Method: corroborate.AttrNone},
	}

	if isHuman(caller) {
		evidence := make([]string, 0, len(window))
		for _, r := range window {
			evidence = append(evidence, r.ID)
		}
		s.Human = caller
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrActorIdentity, Evidence: evidence}
		return s
	}

	// Workload caller: bind to the delegated human if the claims named one.
	var human string
	var evidence []string
	for _, r := range window {
		if r.SourceIdentity == "" {
			continue
		}
		if human == "" {
			human = r.SourceIdentity
		}
		if r.SourceIdentity == human {
			evidence = append(evidence, r.ID)
		}
	}
	if human != "" {
		s.Human = human
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrAzureDelegation, Evidence: evidence}
	}
	return s
}

// isHuman separates users from workload and platform identities. An Azure
// user's caller is a UPN (contains @); a service principal or managed
// identity's caller is a GUID. Microsoft first-party platform callers also
// carry a UPN-shaped name under @microsoft.com (e.g. AcmClient@microsoft.com
// on ServiceHealth events, validated against a real Activity Log) — they
// are not the customer's operators and must not bind as a human.
func isHuman(caller string) bool {
	if strings.HasSuffix(caller, "@microsoft.com") {
		return false
	}
	return strings.Contains(caller, "@")
}

// humanFromClaims returns the UPN the token claims carry, or "".
func humanFromClaims(claims map[string]string) string {
	if c := claims[claimUPN]; strings.Contains(c, "@") {
		return c
	}
	if c := claims[claimName]; strings.Contains(c, "@") {
		return c
	}
	return ""
}
