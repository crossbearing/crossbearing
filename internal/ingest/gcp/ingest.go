// Package gcp ingests Google Cloud Audit Logs into the corroborate
// vocabulary: each completed admin-activity / data-access entry becomes a
// record-side corroborate.Record, and per-principal activity is windowed
// into corroborate.Sessions with the binding the entry's identity
// information supports.
//
// Input is what Cloud Logging exports: a JSON array of LogEntry objects
// (`gcloud logging read --format=json`) or newline-delimited entries (the
// Pub/Sub / Cloud Storage sink shape), via io.Reader. The LogEntry and
// AuditLog schemas are declared locally — the lean-go.sum product
// property means no google.golang.org SDK, and this ingester needs a
// dozen fields, not a client library.
//
// The attribution convention mirrors STS SourceIdentity and K8s
// impersonation exactly, which is the design through-line of every
// record stream: an agent authenticates as its own service account and
// acts on behalf of a human via impersonation
// (iam.serviceAccounts.getAccessToken / actAs), and the audit log records
// both — principalEmail (the agent's SA) and serviceAccountDelegationInfo
// (the human). A project that grants agents impersonation gets per-entry
// human binding; one that hands agents bare SA keys gets unattributed
// sessions, which is the finding.
package gcp

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

// Options bound the ingester's behavior. The zero value is usable.
type Options struct {
	// Project names the GCP project the log came from; it anchors locators
	// so provenance says where an insertId can be re-fetched. Empty falls
	// back to each entry's own resource.labels.project_id.
	Project string

	// SessionGap splits a principal's activity into separate Sessions
	// after this much silence. Defaults to 30 minutes, matching the other
	// record-side ingesters.
	SessionGap time.Duration

	// IsProduction marks targets inside the production scope (e.g. a
	// resourceName under a prod project or bucket). Nil means nothing is
	// production-touching.
	IsProduction func(target string) bool
}

const defaultSessionGap = 30 * time.Minute

// Result is one audit-log ingestion's output.
type Result struct {
	Records  []corroborate.Record
	Sessions []corroborate.Session
}

// Ingester parses GCP Cloud Audit Log JSON into corroborate types.
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
	return &Ingester{log: logger.With("component", "ingest-gcp"), opts: opts}
}

// IngestFile ingests one audit-log file.
func (g *Ingester) IngestFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to open gcp audit log: %w", err)
	}
	defer f.Close()
	return g.Ingest(f)
}

// logEntry is the slice of a Cloud Logging LogEntry this ingester reads.
type logEntry struct {
	InsertID  string    `json:"insertId"`
	Timestamp time.Time `json:"timestamp"`
	LogName   string    `json:"logName"`
	Resource  struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	ProtoPayload auditLog `json:"protoPayload"`
	// Operation groups the entries of a long-running operation; the
	// non-final slice is skipped so an async op records once, at completion.
	Operation *struct {
		ID    string `json:"id"`
		First bool   `json:"first"`
		Last  bool   `json:"last"`
	} `json:"operation"`
}

// auditLog is protoPayload when @type is google.cloud.audit.AuditLog.
type auditLog struct {
	ServiceName        string `json:"serviceName"`
	MethodName         string `json:"methodName"`
	ResourceName       string `json:"resourceName"`
	AuthenticationInfo struct {
		PrincipalEmail               string                `json:"principalEmail"`
		ServiceAccountDelegationInfo []delegationPrincipal `json:"serviceAccountDelegationInfo"`
	} `json:"authenticationInfo"`
	Status *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
}

type delegationPrincipal struct {
	FirstPartyPrincipal *struct {
		PrincipalEmail string `json:"principalEmail"`
	} `json:"firstPartyPrincipal"`
	ThirdPartyPrincipal *struct {
		PrincipalEmail string `json:"principalEmail"`
	} `json:"thirdPartyPrincipal"`
}

func (d delegationPrincipal) email() string {
	if d.FirstPartyPrincipal != nil && d.FirstPartyPrincipal.PrincipalEmail != "" {
		return d.FirstPartyPrincipal.PrincipalEmail
	}
	if d.ThirdPartyPrincipal != nil {
		return d.ThirdPartyPrincipal.PrincipalEmail
	}
	return ""
}

// effective reports whether this entry is one completed, successful
// action — the only shape that becomes a Record. A non-zero status is a
// denied or failed call that changed nothing, and corroborating it would
// let a denied attempt "corroborate" a claim of success; the non-final
// slice of a long-running operation is the request half, recorded once at
// its completion entry.
func (e *logEntry) effective() bool {
	if e.InsertID == "" || e.ProtoPayload.MethodName == "" || e.ProtoPayload.AuthenticationInfo.PrincipalEmail == "" {
		return false
	}
	if e.ProtoPayload.Status != nil && e.ProtoPayload.Status.Code != 0 {
		return false
	}
	if e.Operation != nil && e.Operation.First && !e.Operation.Last {
		return false
	}
	return true
}

// Ingest reads audit entries from r: a JSON array (gcloud export) or
// newline-delimited entries (sink shape).
func (g *Ingester) Ingest(r io.Reader) (Result, error) {
	raws, badEntries, err := ingest.SplitJSONArrayOrLines(r)
	if err != nil {
		return Result{}, err
	}
	if badEntries > 0 {
		g.log.Warn("skipped unparseable gcp audit entries", "entries", badEntries)
	}

	var (
		records     = []corroborate.Record{}
		byPrincipal = make(map[string][]corroborate.Record)
		skipped     int
	)
	for _, raw := range raws {
		var e logEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			skipped++
			continue
		}
		if !e.effective() {
			continue
		}
		rec := g.record(&e, raw)
		records = append(records, rec)
		byPrincipal[rec.Principal] = append(byPrincipal[rec.Principal], rec)
	}
	if skipped > 0 {
		g.log.Warn("skipped undecodable gcp audit entries", "entries", skipped)
	}

	sessions := g.sessions(byPrincipal)
	g.log.Info("ingested gcp audit log",
		"project", g.opts.Project, "records", len(records), "sessions", len(sessions))
	return Result{Records: records, Sessions: sessions}, nil
}

func (g *Ingester) record(e *logEntry, raw []byte) corroborate.Record {
	p := e.ProtoPayload
	project := g.opts.Project
	if project == "" {
		project = e.Resource.Labels["project_id"]
	}

	var targets []string
	if p.ResourceName != "" {
		targets = append(targets, p.ResourceName)
	}

	rec := corroborate.Record{
		ID:         e.InsertID,
		Source:     corroborate.SourceGCPAudit,
		Operation:  "gcp-audit:" + p.MethodName,
		Principal:  p.AuthenticationInfo.PrincipalEmail,
		Targets:    targets,
		RecordedAt: e.Timestamp,
		Raw: corroborate.Provenance{
			Locator: "gcp-audit:" + project + "#" + e.InsertID,
			Digest:  corroborate.DigestHex(raw),
		},
	}
	// The delegated human goes in the SourceIdentity slot, same as K8s
	// impersonatedUser and STS SourceIdentity.
	if human := delegatedHuman(p.AuthenticationInfo.ServiceAccountDelegationInfo); human != "" {
		rec.SourceIdentity = human
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

// delegatedHuman returns the first human (non-service-account) principal
// in a delegation chain, or "" when the chain is empty or all machinery.
func delegatedHuman(chain []delegationPrincipal) string {
	for _, d := range chain {
		if email := d.email(); email != "" && isHuman(email) {
			return email
		}
	}
	return ""
}

// sessions windows each principal's activity. Binding precedence,
// strongest first:
//
//  1. a delegation chain naming a human → gcp-delegation (the
//     impersonation convention; the human is named per entry).
//  2. a human principalEmail → actor-identity (a user authenticated as
//     themselves).
//  3. nothing: a bare service account stays unattributed — the gap the
//     convention checker exists to name.
func (g *Ingester) sessions(byPrincipal map[string][]corroborate.Record) []corroborate.Session {
	var out []corroborate.Session
	for principal, recs := range byPrincipal {
		sort.Slice(recs, func(i, j int) bool { return recs[i].RecordedAt.Before(recs[j].RecordedAt) })
		start := 0
		for i := 1; i <= len(recs); i++ {
			if i < len(recs) && recs[i].RecordedAt.Sub(recs[i-1].RecordedAt) <= g.opts.SessionGap {
				continue
			}
			out = append(out, g.session(principal, recs[start:i]))
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

func (g *Ingester) session(principal string, window []corroborate.Record) corroborate.Session {
	first, last := window[0], window[len(window)-1]
	project := g.opts.Project
	if project == "" {
		project = "project"
	}
	s := corroborate.Session{
		ID:          "gcp:" + project + "/" + principal + "@" + first.RecordedAt.UTC().Format(time.RFC3339),
		Agent:       principal,
		StartedAt:   first.RecordedAt,
		EndedAt:     last.RecordedAt,
		Attribution: corroborate.Attribution{Method: corroborate.AttrNone},
	}

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
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrGCPDelegation, Evidence: evidence}
		return s
	}

	if isHuman(principal) {
		evidence = make([]string, 0, len(window))
		for _, r := range window {
			evidence = append(evidence, r.ID)
		}
		s.Human = principal
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrActorIdentity, Evidence: evidence}
	}
	return s
}

// isHuman separates authenticated people from service accounts. GCP
// service-account emails live under *.gserviceaccount.com; anything else
// (a Workspace/Cloud Identity user, an external IdP subject) is a person.
// system principals Google records for its own automation are also not
// people.
func isHuman(email string) bool {
	if email == "" {
		return false
	}
	if strings.Contains(email, "gserviceaccount.com") {
		return false
	}
	if strings.HasPrefix(email, "system:") || strings.HasPrefix(email, "service-") {
		return false
	}
	return true
}
