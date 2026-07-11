package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// sampleReport mirrors the synthetic fab dress-rehearsal: two agent sessions,
// one unattributed production action, a mismatch, an unrecorded claim, and two
// corroborated claims.
func sampleReport() *corroborate.Report {
	prov := func(loc, dig string) corroborate.Provenance {
		return corroborate.Provenance{Locator: loc, Digest: dig}
	}
	rep := &corroborate.Report{
		From: at("2026-06-11T09:30:00Z"),
		To:   at("2026-06-11T12:00:00Z"),
		Sessions: []corroborate.Session{
			{ID: "arn:aws:sts::111122223333:assumed-role/agent-runtime/sessA", Agent: "bedrock"},
			{ID: "arn:aws:sts::111122223333:assumed-role/ci-runner/build-99", Agent: "bedrock"},
		},
		Findings: []corroborate.Finding{
			{Kind: corroborate.Corroborated, Why: "ok",
				Claim:  &corroborate.Claim{Operation: "Bash(kubectl -n payments scale deploy/checkout --replicas=4)", Source: corroborate.SourceBedrockInvocation, ClaimedAt: at("2026-06-11T10:00:00Z"), Raw: prov("bedrock:fab#req-a1/tu-1", "aaaa1111bbbb2222")},
				Record: &corroborate.Record{Operation: "k8s-audit:update:deployments/scale", Source: corroborate.SourceK8sAudit, RecordedAt: at("2026-06-11T10:00:04Z"), ID: "k8s-r1", Raw: prov("k8s-audit:prod#k8s-r1", "cccc3333dddd4444")}},
			{Kind: corroborate.Corroborated, Why: "ok",
				Claim:  &corroborate.Claim{Operation: "mcp:github:merge_pull_request", Source: corroborate.SourceBedrockInvocation, ClaimedAt: at("2026-06-11T10:00:20Z"), Raw: prov("bedrock:fab#req-a2/tu-2", "eeee5555ffff6666")},
				Record: &corroborate.Record{Operation: "github-audit:pull_request.merge", Source: corroborate.SourceGitHubAudit, RecordedAt: at("2026-06-11T10:00:24Z"), ID: "gh-r2", Raw: prov("github-audit:acme#gh-r2", "7777aaaa8888bbbb")}},
			{Kind: corroborate.Unattributed, Why: "production-touching action with agent fingerprints and no named human binding",
				Record: &corroborate.Record{Operation: "s3:CreateBucket", Source: corroborate.SourceCloudTrail, Principal: "arn:aws:sts::111122223333:assumed-role/agent-runtime/sessA", AccessKeyID: "ASIAAGENTRT00001", RecordedAt: at("2026-06-11T10:00:40Z"), ID: "ct-r3", Targets: []string{"arn:aws:s3:::payments-prod-exports"}, ProductionTouching: true, Raw: prov("aws-cloudtrail:us-east-1#ct-r3", "9999cccc0000dddd")}},
			{Kind: corroborate.Mismatch, SessionID: "sessA", Why: "claimed get but recorded delete",
				Claim:  &corroborate.Claim{Operation: "Bash(kubectl -n payments get configmaps)", Source: corroborate.SourceBedrockInvocation, ClaimedAt: at("2026-06-11T10:00:55Z"), Raw: prov("bedrock:fab#req-a3/tu-3", "1111eeee2222ffff")},
				Record: &corroborate.Record{Operation: "k8s-audit:delete:configmaps", Source: corroborate.SourceK8sAudit, RecordedAt: at("2026-06-11T10:00:58Z"), ID: "k8s-rdel", Raw: prov("k8s-audit:prod#k8s-rdel", "3333aaaa4444bbbb")}},
			{Kind: corroborate.UnrecordedClaim, SessionID: "build-99", Why: "no record corroborates this claim",
				Claim: &corroborate.Claim{Operation: "Bash(aws dynamodb delete-table --table-name prod-orders)", Source: corroborate.SourceBedrockInvocation, ClaimedAt: at("2026-06-11T11:30:00Z"), Raw: prov("bedrock:fab#req-b1/tu-4", "5555cccc6666dddd")}},
		},
	}
	return rep
}

func TestBuildView(t *testing.T) {
	v := BuildView(sampleReport(), Meta{PreparedFor: "Northwind AI", Region: "us-east-1", GeneratedAt: at("2026-06-12T09:00:00Z")})

	if v.PreparedFor != "Northwind AI" {
		t.Errorf("PreparedFor = %q", v.PreparedFor)
	}
	if v.Account != "111122223333" { // derived from a record ARN
		t.Errorf("Account = %q, want 111122223333", v.Account)
	}
	if v.Sessions != 2 || v.UnattributedN != 1 || v.Mode != "unattributed" {
		t.Errorf("sessions=%d unattributed=%d mode=%q, want 2/1/unattributed", v.Sessions, v.UnattributedN, v.Mode)
	}
	if v.ActionWord != "action" || v.TraceSuffix != "s" { // 1 → "1 action traces"
		t.Errorf("verb agreement: word=%q suffix=%q, want action/s", v.ActionWord, v.TraceSuffix)
	}
	// stats: sessions, attributed, unattributed, corroborated, divergent
	wantStats := []Stat{
		{2, "agent sessions", false},
		{0, "attributed", false},
		{1, "unattributed", true},
		{2, "corroborated", false},
		{2, "divergent", true}, // mismatch + unrecorded
	}
	if len(v.Stats) != len(wantStats) {
		t.Fatalf("stats len = %d, want %d", len(v.Stats), len(wantStats))
	}
	for i, w := range wantStats {
		if v.Stats[i] != w {
			t.Errorf("stat[%d] = %+v, want %+v", i, v.Stats[i], w)
		}
	}
	if !strings.Contains(v.StreamsLine, "Bedrock invocation log") || !strings.Contains(v.StreamsLine, "AWS CloudTrail") {
		t.Errorf("streams line missing expected streams: %q", v.StreamsLine)
	}

	if len(v.Unattributed) != 1 {
		t.Fatalf("unattributed cards = %d, want 1", len(v.Unattributed))
	}
	c := v.Unattributed[0]
	if c.Operation != "s3:CreateBucket" || !strings.HasPrefix(c.Digest, "sha256 ") {
		t.Errorf("unattributed card = {op:%q digest:%q}", c.Operation, c.Digest)
	}
	if len(v.Divergences) != 2 { // mismatch + unrecorded
		t.Fatalf("divergences = %d, want 2", len(v.Divergences))
	}
}

func TestHTML_Content(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sampleReport(), Meta{PreparedFor: "Northwind AI", Region: "us-east-1", GeneratedAt: at("2026-06-12T09:00:00Z")}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<html", "</html>",
		"Northwind AI",
		"111122223333",
		"Of 2 agent sessions",
		"1 production-touching action", // the em-wrapped headline phrase
		"s3:CreateBucket",
		"payments-prod-exports",
		"aws-cloudtrail:us-east-1#ct-r3",
		"k8s-audit:delete:configmaps", // mismatch record side
		"dynamodb delete-table",       // unrecorded claim
		"— no corroborating record —", // unrecorded record side
		"Make it continuous",
		"hello@crossbearing.dev",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Count(out, `class="finding sheet"`) != 3 { // 1 unattributed + 2 divergences
		t.Errorf("finding cards = %d, want 3", strings.Count(out, `class="finding sheet"`))
	}
}

// TestHTML_AgentSuspectTier exercises the tier-2 path: a classifier that
// fingerprints the unattributed s3:CreateBucket must add the 01a subsection, a
// sixth stat cell, and a per-card reason — without touching tier-1.
func TestHTML_AgentSuspectTier(t *testing.T) {
	const reason = "credential session proven to be the agent's by corroborated record ct-1"
	suspect := func(r *corroborate.Record) (bool, string) {
		if r.Operation == "s3:CreateBucket" {
			return true, reason
		}
		return false, ""
	}
	meta := Meta{PreparedFor: "Northwind AI", Region: "us-east-1", GeneratedAt: at("2026-06-12T09:00:00Z")}

	v := BuildViewWith(sampleReport(), meta, suspect)
	if !v.HasAgentSuspect() || len(v.UnattributedAgentSuspect) != 1 {
		t.Fatalf("agent-suspect cards = %d, want 1", len(v.UnattributedAgentSuspect))
	}
	if v.UnattributedAgentSuspect[0].Reason != reason {
		t.Errorf("tier-2 reason = %q", v.UnattributedAgentSuspect[0].Reason)
	}
	if len(v.Unattributed) != 1 { // tier-1 unchanged
		t.Errorf("tier-1 unattributed = %d, want 1", len(v.Unattributed))
	}
	if len(v.Stats) != 6 || v.Stats[3].Label != "agent-suspect" || v.Stats[3].N != 1 {
		t.Fatalf("stats = %+v, want 6 with agent-suspect at index 3", v.Stats)
	}

	var buf bytes.Buffer
	if err := RenderWith(&buf, sampleReport(), meta, suspect); err != nil {
		t.Fatalf("RenderWith: %v", err)
	}
	out := buf.String()
	// The reason carries an apostrophe ("agent's"), which html/template escapes
	// to &#39; in the interpolated value — so assert an escaping-safe substring.
	for _, want := range []string{"01a", "agent-suspect", "corroborated record ct-1",
		"repeat(6, 1fr)"} { // the 6-cell stat strip must widen, not wrap to a 2nd row
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if n := strings.Count(out, `class="finding sheet"`); n != 4 { // 1 tier-2 + 1 tier-1 + 2 divergences
		t.Errorf("finding cards = %d, want 4", n)
	}
}

// The default path (no classifier) must add nothing: no tier-2, five stats.
func TestHTML_NoSuspectFuncIsInert(t *testing.T) {
	v := BuildView(sampleReport(), Meta{GeneratedAt: at("2026-06-12T09:00:00Z")})
	if v.HasAgentSuspect() || len(v.Stats) != 5 {
		t.Errorf("default build: agentSuspect=%v stats=%d, want false/5", v.HasAgentSuspect(), len(v.Stats))
	}
}

func TestHTML_CleanHeadline(t *testing.T) {
	// No unattributed AND no divergent finding → the clean headline.
	rep := &corroborate.Report{
		From: at("2026-06-11T09:30:00Z"), To: at("2026-06-11T10:30:00Z"),
		Sessions: []corroborate.Session{{ID: "s", Agent: "bedrock", Human: "alice@acme.com"}},
		Findings: []corroborate.Finding{
			{Kind: corroborate.Corroborated, Why: "ok",
				Claim:  &corroborate.Claim{Operation: "Bash(aws s3 ls)", ClaimedAt: at("2026-06-11T10:00:00Z")},
				Record: &corroborate.Record{Operation: "s3:ListBuckets", ID: "x", RecordedAt: at("2026-06-11T10:00:02Z")}},
		},
	}
	v := BuildView(rep, Meta{GeneratedAt: at("2026-06-12T09:00:00Z")})
	if v.Mode != "clean" {
		t.Fatalf("expected Mode = clean, got %q", v.Mode)
	}
	var buf bytes.Buffer
	if err := HTML(&buf, v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "traces to a named human") {
		t.Error("clean headline not rendered")
	}
}

// The bug the review caught: a run with no --production-match never escalates
// to Unattributed, so a report with divergences but zero unattributed must NOT
// read as "clean" — it gets the divergent headline.
func TestHTML_DivergentHeadline(t *testing.T) {
	rep := &corroborate.Report{
		From: at("2026-06-11T09:30:00Z"), To: at("2026-06-11T10:30:00Z"),
		Sessions: []corroborate.Session{{ID: "s", Agent: "bedrock"}},
		Findings: []corroborate.Finding{
			{Kind: corroborate.Mismatch, Why: "claimed read, recorded write",
				Claim:  &corroborate.Claim{Operation: "Bash(kubectl get pods)", ClaimedAt: at("2026-06-11T10:00:00Z")},
				Record: &corroborate.Record{Operation: "k8s-audit:delete:pods", ID: "x", RecordedAt: at("2026-06-11T10:00:02Z")}},
		},
	}
	v := BuildView(rep, Meta{GeneratedAt: at("2026-06-12T09:00:00Z")})
	if v.Mode != "divergent" || v.DivergentN != 1 {
		t.Fatalf("mode=%q divergentN=%d, want divergent/1", v.Mode, v.DivergentN)
	}
	var buf bytes.Buffer
	if err := HTML(&buf, v); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "from the record") || !strings.Contains(out, "agent claim") {
		t.Error("divergent headline not rendered")
	}
	if strings.Contains(out, "no named human") {
		t.Error("unattributed headline leaked into a divergent-only report")
	}
}

func TestHelpers(t *testing.T) {
	if got := shortDigest("9999cccc0000dddd"); got != "sha256 9999…dddd" {
		t.Errorf("shortDigest = %q", got)
	}
	if got := shortKey("ASIAAGENTRT00001"); got != "ASIA…0001" {
		t.Errorf("shortKey = %q", got)
	}
	if got := accountFromARN("arn:aws:sts::111122223333:assumed-role/r/s"); got != "111122223333" {
		t.Errorf("accountFromARN = %q", got)
	}
	if got := accountFromARN("not-an-arn"); got != "" {
		t.Errorf("accountFromARN(non-arn) = %q, want empty", got)
	}
	if got := plural(1, "action", "actions"); got != "action" {
		t.Errorf("plural(1) = %q", got)
	}
}
