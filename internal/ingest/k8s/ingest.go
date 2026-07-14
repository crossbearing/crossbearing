// Package k8s ingests Kubernetes audit events (audit.k8s.io/v1) into the
// corroborate vocabulary: each effective request becomes a record-side
// corroborate.Record, and per-user activity is windowed into
// corroborate.Sessions with the binding the cluster's conventions earn.
//
// Input is what audit backends actually emit: the log backend's JSONL
// (one Event per line) or the webhook backend's EventList, via io.Reader.
// The event schema is declared locally on purpose — the repo's hard rule
// bans k8s.io imports, and this ingester needs six fields, not a client
// machinery.
//
// The attribution convention this stream supports mirrors STS
// SourceIdentity exactly: an agent authenticates as its own
// ServiceAccount and impersonates the human it works for
// (Impersonate-User), so every audit event carries both identities —
// user.username (the agent's credential) and impersonatedUser.username
// (the human). A cluster that grants agents impersonate RBAC gets
// per-event human binding; one that hands agents bare SA tokens gets
// unattributed sessions, which is the finding.
package k8s

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// Options bound the ingester's behavior. The zero value is usable.
type Options struct {
	// Cluster names the cluster the log came from; it anchors locators so
	// provenance says where an auditID can be re-fetched.
	Cluster string

	// SessionGap splits a user's activity into separate Sessions after
	// this much silence. Defaults to 30 minutes, matching the other
	// record-side ingesters.
	SessionGap time.Duration

	// IsProduction marks targets inside the production scope (e.g.
	// "prod/deployments/api"). Nil means nothing is production-touching.
	IsProduction func(target string) bool
}

const defaultSessionGap = 30 * time.Minute

// Result is one audit-log ingestion's output.
type Result struct {
	Records  []corroborate.Record
	Sessions []corroborate.Session
}

// Ingester parses Kubernetes audit JSON into corroborate types.
type Ingester struct {
	log  *slog.Logger
	opts Options
}

// New creates an Ingester. A nil logger discards logs.
func New(logger *slog.Logger, opts Options) *Ingester {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if opts.Cluster == "" {
		opts.Cluster = "cluster"
	}
	if opts.SessionGap <= 0 {
		opts.SessionGap = defaultSessionGap
	}
	return &Ingester{log: logger.With("component", "ingest-k8s"), opts: opts}
}

// IngestFile ingests one audit log file.
func (g *Ingester) IngestFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("failed to open k8s audit log: %w", err)
	}
	defer f.Close()
	return g.Ingest(f)
}

// event is the slice of audit.k8s.io/v1 Event this ingester reads,
// declared locally (no k8s.io imports, by hard rule).
type event struct {
	Kind       string `json:"kind"` // "Event" or "EventList"
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	Verb       string `json:"verb"`
	RequestURI string `json:"requestURI"`
	User       struct {
		Username string `json:"username"`
		// Extra is the authenticator's side-channel. On EKS,
		// aws-iam-authenticator fills it with the IAM facts the username
		// alone loses — above all accessKeyId, the exact STS credential
		// session, which is the same value CloudTrail records. It is the
		// join key between the two planes.
		Extra struct {
			AccessKeyID []string `json:"accessKeyId"`
		} `json:"extra"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	RequestReceived time.Time `json:"requestReceivedTimestamp"`
	StageTimestamp  time.Time `json:"stageTimestamp"`
}

func (e *event) at() time.Time {
	if !e.StageTimestamp.IsZero() {
		return e.StageTimestamp
	}
	return e.RequestReceived
}

// accessKey is the STS credential session behind an IAM-authenticated
// request, or "" on clusters whose authenticator does not supply one
// (kubeadm certs, plain OIDC, in-cluster ServiceAccounts).
func (e *event) accessKey() string {
	if len(e.User.Extra.AccessKeyID) == 0 {
		return ""
	}
	return e.User.Extra.AccessKeyID[0]
}

// effective reports whether this event is one completed, successful action
// on a resource — the only shape that becomes a Record.
//
// RequestReceived stages duplicate ResponseComplete ones. Denied/failed
// requests (4xx/5xx) changed nothing, so corroborating them would let a
// denied attempt "corroborate" a claim of success. A missing user.username
// (anonymous or stripped events) yields no usable principal — a Record with
// an empty Principal can be neither attributed nor joined.
//
// And an event with no objectRef acted on no resource. Those are the
// apiserver's non-resource URLs — /api and /apis discovery, /version,
// /healthz, /openapi — which every kubectl invocation fires automatically
// before it does anything at all. They are the client's machinery, not the
// agent's intent: no one claims them, nothing corroborates them, and nothing
// diverges when they happen. Recording them means every run carries a
// standing pile of unclaimed-record findings that can never be resolved,
// which is not a finding but a permanent false positive — and it buries the
// real ones. On the dev-eks corpus this is 822 of 1,405 events (58%), all of
// them GET /api and GET /apis.
func (e *event) effective() bool {
	if e.Stage != "ResponseComplete" || e.AuditID == "" || e.Verb == "" || e.User.Username == "" {
		return false
	}
	if e.ObjectRef == nil || e.ObjectRef.Resource == "" {
		return false
	}
	return e.ResponseStatus == nil || e.ResponseStatus.Code < 400
}

// k8sReadVerbs are the audit verbs that change nothing. A record with any
// other verb is treated as mutating (the safe default), so the join will not
// freely credit it to a claim without proof of ownership.
var k8sReadVerbs = map[string]bool{"get": true, "list": true, "watch": true}

// Ingest reads audit events from r: JSONL (log backend) or an EventList
// (webhook backend).
func (g *Ingester) Ingest(r io.Reader) (Result, error) {
	raws, badLines, err := splitEvents(r)
	if err != nil {
		return Result{}, err
	}
	if badLines > 0 {
		g.log.Warn("skipped unparseable k8s audit lines", "lines", badLines)
	}

	var (
		records = []corroborate.Record{}
		byKey   = make(map[sessionKey][]userEvent)
		skipped int
	)
	for _, raw := range raws {
		var e event
		if err := json.Unmarshal(raw, &e); err != nil {
			skipped++
			continue
		}
		if !e.effective() {
			continue
		}
		rec := g.record(&e, raw)
		records = append(records, rec)
		k := sessionKey{user: e.User.Username, accessKey: e.accessKey()}
		byKey[k] = append(byKey[k], userEvent{rec: rec, ev: e})
	}
	if skipped > 0 {
		g.log.Warn("skipped undecodable k8s audit events", "events", skipped)
	}
	// A log that parses but yields nothing is the failure mode that looks
	// like success: the join simply finds no k8s records and reports no
	// divergence. It almost always means the input is not audit Events at
	// all (a CloudWatch envelope this version cannot unwrap, the wrong log
	// group, an authenticator/controller-manager stream), so say so rather
	// than let a silent zero read as a clean cluster.
	if len(records) == 0 && len(raws) > 0 {
		g.log.Warn("k8s audit log parsed but produced no records — is this an audit stream?",
			"cluster", g.opts.Cluster, "documents", len(raws))
	}

	sessions := g.sessions(byKey)
	g.log.Info("ingested k8s audit log",
		"cluster", g.opts.Cluster, "records", len(records), "sessions", len(sessions))
	return Result{Records: records, Sessions: sessions}, nil
}

func (g *Ingester) record(e *event, raw []byte) corroborate.Record {
	// effective() guarantees an objectRef: a Record is an action on a
	// resource, and nothing else reaches here.
	op := "k8s-audit:" + e.Verb + ":" + e.ObjectRef.Resource
	if e.ObjectRef.Subresource != "" {
		op += "/" + e.ObjectRef.Subresource
	}
	target := e.ObjectRef.Resource
	if e.ObjectRef.Namespace != "" {
		target = e.ObjectRef.Namespace + "/" + target
	}
	if e.ObjectRef.Name != "" {
		target += "/" + e.ObjectRef.Name
	}
	targets := []string{target}

	rec := corroborate.Record{
		ID:          e.AuditID,
		Source:      corroborate.SourceK8sAudit,
		Operation:   op,
		Principal:   e.User.Username,
		AccessKeyID: e.accessKey(),
		Targets:     targets,
		RecordedAt:  e.at(),
		ReadOnly:    k8sReadVerbs[e.Verb],
		Raw: corroborate.Provenance{
			Locator: "k8s-audit:" + g.opts.Cluster + "#" + e.AuditID,
			Digest:  corroborate.DigestHex(raw),
		},
	}
	if e.ImpersonatedUser != nil {
		// The same slot STS SourceIdentity uses: the human the credential
		// session names on every event.
		rec.SourceIdentity = e.ImpersonatedUser.Username
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

type userEvent struct {
	rec corroborate.Record
	ev  event
}

// sessionKey is the unit a Session windows over: the authenticated user
// AND the credential session behind it. The username alone is not enough
// on EKS — an SSO role ARN is shared by everyone who assumes it, and the
// agent's kubectl, a human's kubectl, and Terraform can all appear under
// one identical username at the same moment. accessKeyId is what tells
// them apart, and it is the same key CloudTrail records, which is why
// cloudtrail's ingester keys on (principal, accessKeyId) too. Clusters
// whose authenticator supplies no access key degrade to username-only
// grouping, exactly as before.
type sessionKey struct{ user, accessKey string }

// sessions windows each credential session's activity. Binding
// precedence, strongest first:
//
//  1. impersonatedUser on the window's events → k8s-impersonation (the
//     cluster-enforced convention; the human is named per event).
//  2. A username that names a person — an OIDC/cert user authenticated as
//     themselves → actor-identity.
//  3. Nothing: ServiceAccounts, system users, and IAM principals without
//     impersonation stay unattributed — the gap the convention checker
//     exists to name.
func (g *Ingester) sessions(byKey map[sessionKey][]userEvent) []corroborate.Session {
	var out []corroborate.Session
	for k, evs := range byKey {
		sort.Slice(evs, func(i, j int) bool { return evs[i].rec.RecordedAt.Before(evs[j].rec.RecordedAt) })
		start := 0
		for i := 1; i <= len(evs); i++ {
			if i < len(evs) && evs[i].rec.RecordedAt.Sub(evs[i-1].rec.RecordedAt) <= g.opts.SessionGap {
				continue
			}
			out = append(out, g.session(k, evs[start:i]))
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

func (g *Ingester) session(k sessionKey, window []userEvent) corroborate.Session {
	first, last := window[0], window[len(window)-1]
	id := "k8s:" + g.opts.Cluster + "/" + k.user + "@" + first.rec.RecordedAt.UTC().Format(time.RFC3339)
	if k.accessKey != "" {
		// The key suffix keeps concurrent same-username sessions distinct,
		// mirroring the cloudtrail session ID.
		id += "/" + k.accessKey
	}
	s := corroborate.Session{
		ID:          id,
		Agent:       k.user,
		StartedAt:   first.rec.RecordedAt,
		EndedAt:     last.rec.RecordedAt,
		Attribution: corroborate.Attribution{Method: corroborate.AttrNone},
	}

	human := ""
	var evidence []string
	for _, ue := range window {
		if ue.rec.SourceIdentity == "" {
			continue
		}
		if human == "" {
			human = ue.rec.SourceIdentity
		}
		if ue.rec.SourceIdentity == human {
			evidence = append(evidence, ue.rec.ID)
		}
	}
	if human != "" {
		s.Human = human
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrK8sImpersonation, Evidence: evidence}
		return s
	}

	if isHumanUsername(k.user) {
		evidence = make([]string, 0, len(window))
		for _, ue := range window {
			evidence = append(evidence, ue.rec.ID)
		}
		s.Human = k.user
		s.Attribution = corroborate.Attribution{Method: corroborate.AttrActorIdentity, Evidence: evidence}
	}
	return s
}

// isHumanUsername separates authenticated people from machinery. A human
// username is one the platform can only have issued to a person: an OIDC
// or client-cert subject. Everything else is a credential that a person,
// an agent, or a CI job may equally be wearing, and naming it as the human
// would be a fabricated attribution — the one error this product must never
// make.
//
// Excluded, and why:
//
//   - system:… — ServiceAccounts and the control plane's own identities.
//   - An IAM ARN — how EKS spells every IAM-authenticated principal
//     (arn:aws:sts::123:assumed-role/AWSReservedSSO_AdminAccess_x/alice).
//     It looks personal because SSO puts a login name in the role-session
//     slot, but it is a *shared role*: every admin assumes the same one,
//     and the ARN is byte-identical whoever (or whatever) is wielding it.
//     Attribution here has to come from the credential's own evidence —
//     impersonation headers above, or STS SourceIdentity on the CloudTrail
//     side — never from the name.
//
// The k8s username is attacker- and operator-influenced (EKS access
// entries let you choose it), so this fails closed: anything ARN-shaped is
// a credential, in any partition.
func isHumanUsername(user string) bool {
	if user == "" || strings.HasPrefix(user, "system:") {
		return false
	}
	return !strings.HasPrefix(user, "arn:")
}

// splitEvents accepts every shape a Kubernetes audit log actually reaches
// us in, by decoding a stream of JSON values and unwrapping each one:
//
//   - the log backend's JSONL and the webhook backend's EventList — an
//     audit Event, or a document of them;
//   - CloudWatch Logs envelopes, which is how EKS delivers audit logs and
//     therefore the shape most real input has. `aws logs filter-log-events`
//     returns {"events":[{"message":"<the audit Event, as a string>"}]},
//     and an exported/subscribed stream is one such envelope per line.
//     The audit Event is a JSON *string* inside, so it decodes to nothing
//     useful unless it is unwrapped first.
//
// Returns each event's exact raw bytes for digesting — for a CloudWatch
// envelope, the bytes of the embedded Event, since that is what the
// auditID identifies and what a re-fetch would return. A malformed tail
// stops the stream (JSON gives no resync point) and is counted, not fatal.
func splitEvents(r io.Reader) (raws []json.RawMessage, badDocs int, err error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read k8s audit log: %w", err)
	}
	for off := 0; off < len(data); {
		dec := json.NewDecoder(bytes.NewReader(data[off:]))
		var doc json.RawMessage
		switch err := dec.Decode(&doc); {
		case err == io.EOF:
			return raws, badDocs, nil
		case err != nil:
			// A malformed document used to ABANDON the stream, counted as ONE bad
			// doc — so a single truncated line 500 of a 100,000-line EKS export
			// produced a confident report over 499 records and a warning that
			// said "1". On an evidence engine that is the worst shape a bug can
			// take: the report does not merely miss a divergence, it
			// affirmatively denies one, over input it never read.
			//
			// The primary input is JSONL, where the newline IS the resync point.
			// Skip the bad line and keep reading — the same contract
			// SplitJSONArrayOrLines already gives github/gcp/azure. Every skipped
			// line is counted, and Ingest warns on any nonzero count.
			badDocs++
			nl := bytes.IndexByte(data[off:], '\n')
			if nl < 0 {
				return raws, badDocs, nil // a malformed tail with no line to resync to
			}
			off += nl + 1
		default:
			raws = append(raws, unwrap(bytes.TrimSpace(doc))...)
			off += int(dec.InputOffset())
		}
	}
	return raws, badDocs, nil
}

// unwrap turns one decoded document into the audit Events inside it. An
// Event that is already an Event passes through untouched, so an ordinary
// audit JSONL file costs one failed probe per line and nothing else.
func unwrap(doc json.RawMessage) []json.RawMessage {
	var probe struct {
		Kind    string            `json:"kind"`
		Items   []json.RawMessage `json:"items"`
		AuditID string            `json:"auditID"`
		// CloudWatch: a batch of log events, or a single one. The audit
		// Event rides in Message as an escaped JSON string.
		Events  []struct{ Message string } `json:"events"`
		Message string                     `json:"message"`
	}
	if json.Unmarshal(doc, &probe) != nil {
		return []json.RawMessage{doc} // let the event decoder count it
	}
	switch {
	case probe.Kind == "EventList":
		return probe.Items
	case probe.AuditID != "":
		return []json.RawMessage{doc} // a bare audit Event; never re-probe
	case len(probe.Events) > 0:
		out := make([]json.RawMessage, 0, len(probe.Events))
		for _, e := range probe.Events {
			out = append(out, json.RawMessage(strings.TrimSpace(e.Message)))
		}
		return out
	case probe.Message != "":
		return []json.RawMessage{json.RawMessage(strings.TrimSpace(probe.Message))}
	}
	return []json.RawMessage{doc}
}
