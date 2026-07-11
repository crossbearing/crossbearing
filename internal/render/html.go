// Package render turns a corroborate.Report into the on-brand, print-to-PDF
// Agent Attribution Audit — the same artifact crossbearing.dev describes,
// emitted directly by `crossbearing report --format html` instead of filled in
// by hand. The numbers, findings, and provenance all come from the real join;
// the copy and chrome are the wedge deliverable's.
//
// Stdlib html/template only (auto-escaped, so log-derived strings are safe to
// interpolate) — no new dependency, the lean-go.sum property holds.
package render

import (
	_ "embed"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

//go:embed report.html.tmpl
var reportHTML string

var reportTmpl = template.Must(template.New("report").Parse(reportHTML))

// Meta is the cover information the report can't derive from the join itself.
type Meta struct {
	PreparedFor string    // org name on the cover; empty omits the field
	Account     string    // AWS account id; empty derives one from a record ARN
	Region      string    // where the run read (or "offline")
	GeneratedAt time.Time // stamp; the caller passes time.Now() so tests can fix it
}

// Stat is one cell of the summary strip.
type Stat struct {
	N     int
	Label string
	Flag  bool // render the number in sea-blue (a number that should worry you)
}

type kv struct{ K, V string }

// card is one unattributed-action finding.
type card struct {
	Operation string
	Badge     string
	KVs       []kv
	Why       string
	Locator   string
	Digest    string
	// Reason is the agent-suspect fingerprint sentence, set only on tier-2
	// cards (the agent-suspect subsection); empty on the full tier-1 list.
	Reason string
}

// divergence is one claim-vs-record finding (mismatch / unrecorded / unclaimed).
type divergence struct {
	ClaimValue    string
	RecordValue   string
	KVs           []kv
	ClaimLocator  string
	RecordLocator string
}

// View is the fully-resolved model the template renders. Everything is
// pre-computed here so the template stays declarative.
type View struct {
	PreparedFor string
	Account     string
	Window      string
	Generated   string
	StreamsLine string

	// headline: one of three honest framings, picked by what the join found —
	//   "unattributed" : ≥1 production action traces to no human (the headline)
	//   "divergent"    : all attributed, but ≥1 claim disagrees with the record
	//   "clean"        : nothing orphaned, nothing diverges
	// "clean" is NOT just "unattributed == 0": that escalation needs
	// --production-match, so a run without it must not silently read as clean
	// when divergences are present.
	Mode          string
	Sessions      int
	UnattributedN int
	ActionWord    string // "action" / "actions"
	TraceSuffix   string // "s" / "" — verb agreement on "trace"
	DivergentN    int
	ClaimWord     string // "claim" / "claims"
	DivergeSuffix string // "s" / "" — verb agreement on "diverge"

	Stats        []Stat
	Unattributed []card
	// UnattributedAgentSuspect is the subset of Unattributed positively
	// fingerprinted to an agent (tier-2). A labeling pass over the same
	// findings — every entry is also present in Unattributed.
	UnattributedAgentSuspect []card
	Divergences              []divergence
}

// HasUnattributed / HasDivergences / HasAgentSuspect gate the optional sections.
func (v View) HasUnattributed() bool { return len(v.Unattributed) > 0 }
func (v View) HasDivergences() bool  { return len(v.Divergences) > 0 }
func (v View) HasAgentSuspect() bool { return len(v.UnattributedAgentSuspect) > 0 }

// SuspectFunc classifies an unattributed record as agent-suspect, returning a
// reason for any positive. cmd supplies one backed by attribute.AgentSuspect; a
// nil func means no agent-suspect tier — keeping the render package decoupled
// from the attribution package.
type SuspectFunc func(r *corroborate.Record) (suspect bool, reason string)

// HTML renders the audit report for the report's view to w.
func HTML(w io.Writer, v View) error {
	return reportTmpl.Execute(w, v)
}

// Render builds the view from a report and renders it in one call.
func Render(w io.Writer, rep *corroborate.Report, meta Meta) error {
	return HTML(w, BuildView(rep, meta))
}

// RenderWith is Render plus the agent-suspect classifier, surfacing the tier-2
// subsection.
func RenderWith(w io.Writer, rep *corroborate.Report, meta Meta, suspect SuspectFunc) error {
	return HTML(w, BuildViewWith(rep, meta, suspect))
}

// BuildView maps a joined report into the audit view model.
func BuildView(rep *corroborate.Report, meta Meta) View {
	return BuildViewWith(rep, meta, nil)
}

// BuildViewWith is BuildView with an agent-suspect classifier; a non-nil suspect
// populates the agent-suspect tier — a labeling pass over the same unattributed
// findings, so the full tier-1 list (and the signed evidence) is unchanged.
func BuildViewWith(rep *corroborate.Report, meta Meta, suspect SuspectFunc) View {
	tally := rep.Tally()

	var attributed int
	for _, s := range rep.Sessions {
		if s.Human != "" {
			attributed++
		}
	}
	unattributed := tally[corroborate.Unattributed]
	divergent := tally[corroborate.Mismatch] + tally[corroborate.UnrecordedClaim] + tally[corroborate.UnclaimedRecord]

	byKind := map[corroborate.FindingKind][]corroborate.Finding{}
	for _, f := range rep.Findings {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	for k := range byKind {
		fs := byKind[k]
		sort.SliceStable(fs, func(i, j int) bool { return findingAt(fs[i]).Before(findingAt(fs[j])) })
	}

	mode := "clean"
	switch {
	case unattributed > 0:
		mode = "unattributed"
	case divergent > 0:
		mode = "divergent"
	}

	v := View{
		PreparedFor:   meta.PreparedFor,
		Account:       meta.Account,
		Window:        windowLabel(rep.From, rep.To),
		Generated:     meta.GeneratedAt.UTC().Format("2006-01-02") + regionSuffix(meta.Region),
		StreamsLine:   streamsLine(rep),
		Mode:          mode,
		Sessions:      len(rep.Sessions),
		UnattributedN: unattributed,
		ActionWord:    plural(unattributed, "action", "actions"),
		TraceSuffix:   plural(unattributed, "s", ""), // "1 action traces" / "5 actions trace"
		DivergentN:    divergent,
		ClaimWord:     plural(divergent, "claim", "claims"),
		DivergeSuffix: plural(divergent, "s", ""), // "1 claim diverges" / "5 claims diverge"
		Stats: []Stat{
			{len(rep.Sessions), "agent sessions", false},
			{attributed, "attributed", false},
			{unattributed, "unattributed", unattributed > 0},
			{tally[corroborate.Corroborated], "corroborated", false},
			{divergent, "divergent", divergent > 0},
		},
	}
	if v.Account == "" {
		v.Account = deriveAccount(rep.Findings)
	}

	for _, f := range byKind[corroborate.Unattributed] {
		if f.Record == nil {
			continue
		}
		r := f.Record
		c := card{
			Operation: r.Operation,
			Badge:     "unattributed",
			Why:       f.Why,
			Locator:   r.Raw.Locator,
			Digest:    shortDigest(r.Raw.Digest),
			KVs: []kv{
				{"Principal", r.Principal},
				{"Recorded", r.RecordedAt.UTC().Format("Jan 2, 15:04:05Z") + keySuffix(r.AccessKeyID)},
			},
		}
		if len(r.Targets) > 0 {
			c.KVs = append(c.KVs, kv{"Target", strings.Join(r.Targets, ", ")})
		}
		v.Unattributed = append(v.Unattributed, c)
		// Tier-2: the same card, labeled, when positively fingerprinted.
		if suspect != nil {
			if ok, reason := suspect(r); ok {
				sc := c
				sc.Reason = reason
				v.UnattributedAgentSuspect = append(v.UnattributedAgentSuspect, sc)
			}
		}
	}
	// Agent-suspect stat cell, inserted right after "unattributed" so the strip
	// reads "… unattributed N · agent-suspect M …". Only when the tier is
	// non-empty, so a run without fingerprints renders the original five cells.
	if n := len(v.UnattributedAgentSuspect); n > 0 {
		stats := make([]Stat, 0, len(v.Stats)+1)
		stats = append(stats, v.Stats[:3]...) // sessions, attributed, unattributed
		stats = append(stats, Stat{n, "agent-suspect", true})
		stats = append(stats, v.Stats[3:]...)
		v.Stats = stats
	}

	for _, kind := range []corroborate.FindingKind{corroborate.Mismatch, corroborate.UnrecordedClaim, corroborate.UnclaimedRecord} {
		for _, f := range byKind[kind] {
			d := divergence{
				ClaimValue:  "— no claim —",
				RecordValue: "— no corroborating record —",
				KVs:         []kv{{"Session", f.SessionID}, {"Why", f.Why}},
			}
			if f.Claim != nil {
				d.ClaimValue = f.Claim.Operation
				d.ClaimLocator = f.Claim.Raw.Locator
			}
			if f.Record != nil {
				d.RecordValue = f.Record.Operation
				d.RecordLocator = f.Record.Raw.Locator
			}
			v.Divergences = append(v.Divergences, d)
		}
	}

	return v
}

func findingAt(f corroborate.Finding) time.Time {
	if f.Claim != nil {
		return f.Claim.ClaimedAt
	}
	if f.Record != nil {
		return f.Record.RecordedAt
	}
	return time.Time{}
}

// streamsLine names the distinct claim and record streams the join drew on,
// for the line under the summary strip.
func streamsLine(rep *corroborate.Report) string {
	seen := map[corroborate.Source]bool{}
	var order []corroborate.Source
	add := func(s corroborate.Source) {
		if s != "" && !seen[s] {
			seen[s] = true
			order = append(order, s)
		}
	}
	for _, f := range rep.Findings {
		if f.Claim != nil {
			add(f.Claim.Source)
		}
		if f.Record != nil {
			add(f.Record.Source)
		}
	}
	names := make([]string, 0, len(order))
	for _, s := range order {
		names = append(names, sourceName(s))
	}
	if len(names) == 0 {
		return ""
	}
	return "streams: " + strings.Join(names, " · ")
}

func sourceName(s corroborate.Source) string {
	switch s {
	case corroborate.SourceCloudTrail:
		return "AWS CloudTrail"
	case corroborate.SourceK8sAudit:
		return "Kubernetes audit"
	case corroborate.SourceGitHubAudit:
		return "GitHub audit"
	case corroborate.SourceGCPAudit:
		return "GCP Cloud Audit"
	case corroborate.SourceAzureActivity:
		return "Azure Activity"
	case corroborate.SourceBedrockInvocation:
		return "Bedrock invocation log"
	case corroborate.SourceClaudeCodeTranscript:
		return "Claude Code transcripts"
	default:
		return string(s)
	}
}

// deriveAccount pulls an AWS account id out of the first assumed-role ARN in
// the findings (arn:aws:sts::ACCT:assumed-role/…), so the cover shows one even
// without --account.
func deriveAccount(findings []corroborate.Finding) string {
	for _, f := range findings {
		if f.Record == nil {
			continue
		}
		if acct := accountFromARN(f.Record.Principal); acct != "" {
			return acct
		}
	}
	return "—"
}

func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 && parts[0] == "arn" && len(parts[4]) == 12 {
		return parts[4]
	}
	return ""
}

func windowLabel(from, to time.Time) string {
	const d = "Jan 2"
	const dy = "Jan 2, 2006"
	fu, tu := from.UTC(), to.UTC()
	if fu.Year() == tu.Year() && fu.YearDay() == tu.YearDay() {
		return fu.Format(dy) // a single day — don't render "Jun 11 – Jun 11, 2026"
	}
	if fu.Year() == tu.Year() {
		return fu.Format(d) + " – " + tu.Format(dy)
	}
	return fu.Format(dy) + " – " + tu.Format(dy)
}

func regionSuffix(region string) string {
	if region == "" {
		return ""
	}
	return " · " + region
}

func keySuffix(accessKeyID string) string {
	if accessKeyID == "" {
		return ""
	}
	return " · access key " + shortKey(accessKeyID)
}

// shortKey / shortDigest keep just the recognizable head and tail, the way an
// operator reads an access key or a hash at a glance.
func shortKey(k string) string {
	if len(k) <= 8 {
		return k
	}
	return k[:4] + "…" + k[len(k)-4:]
}

func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return "sha256 " + d[:4] + "…" + d[len(d)-4:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
