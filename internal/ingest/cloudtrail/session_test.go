package cloudtrail

import (
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/corroborate"
)

const (
	sessionARN = "arn:aws:sts::111122223333:assumed-role/agent-deployer/claude-code-bs"
	ciARN      = "arn:aws:sts::111122223333:assumed-role/agent-deployer/ci-agent-7"
)

var t0 = time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

// sessionEvent fabricates an event emitted from inside an assumed-role session.
func sessionEvent(id, principal, sourceIdentity string, at time.Time) Extracted {
	return Extracted{
		EventID:        id,
		EventSource:    "s3.amazonaws.com",
		EventName:      "PutObject",
		Principal:      principal,
		PrincipalType:  "AssumedRole",
		SourceIdentity: sourceIdentity,
		EventTime:      at,
	}
}

// grantEvent fabricates the sts:AssumeRole call that created a session.
func grantEvent(id, assumedARN, grantedIdentity string, tags map[string]string, at time.Time) Extracted {
	return Extracted{
		EventID:               id,
		EventSource:           "sts.amazonaws.com",
		EventName:             "AssumeRole",
		Principal:             "arn:aws:iam::111122223333:user/ci-runner",
		PrincipalType:         "IAMUser",
		AssumedSessionARN:     assumedARN,
		GrantedSourceIdentity: grantedIdentity,
		SessionTags:           tags,
		EventTime:             at,
	}
}

func newSessionIngester(opts Options) *Ingester {
	return New(&mockEventsAPI{}, nil, opts)
}

func TestSessions_SourceIdentityBinding(t *testing.T) {
	t.Parallel()
	g := newSessionIngester(Options{})
	got := g.sessions([]Extracted{
		sessionEvent("evt-1", sessionARN, "bs@example.com", t0),
		sessionEvent("evt-2", sessionARN, "bs@example.com", t0.Add(5*time.Minute)),
	})

	if len(got) != 1 {
		t.Fatalf("sessions = %d, want 1", len(got))
	}
	s := got[0]
	if s.Human != "bs@example.com" {
		t.Errorf("Human = %q, want bs@example.com", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrSTSSourceIdentity {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrSTSSourceIdentity)
	}
	if len(s.Attribution.Evidence) != 2 {
		t.Errorf("Evidence = %v, want both event IDs", s.Attribution.Evidence)
	}
	if s.Agent != "claude-code-bs" {
		t.Errorf("Agent = %q, want claude-code-bs", s.Agent)
	}
	if !s.StartedAt.Equal(t0) || !s.EndedAt.Equal(t0.Add(5*time.Minute)) {
		t.Errorf("window = [%v, %v]", s.StartedAt, s.EndedAt)
	}
	if want := sessionARN + "@2026-06-09T12:00:00Z"; s.ID != want {
		t.Errorf("ID = %q, want %q", s.ID, want)
	}
}

func TestSessions_GapSplitsWindows(t *testing.T) {
	t.Parallel()
	g := newSessionIngester(Options{SessionGap: 30 * time.Minute})
	got := g.sessions([]Extracted{
		sessionEvent("evt-1", sessionARN, "", t0),
		sessionEvent("evt-2", sessionARN, "", t0.Add(10*time.Minute)),
		// 45 minutes of silence: a re-assumption, not the same working session.
		sessionEvent("evt-3", sessionARN, "", t0.Add(55*time.Minute)),
	})

	if len(got) != 2 {
		t.Fatalf("sessions = %d, want 2 (gap must split)", len(got))
	}
	if !got[0].EndedAt.Equal(t0.Add(10 * time.Minute)) {
		t.Errorf("first window ends %v, want %v", got[0].EndedAt, t0.Add(10*time.Minute))
	}
	if !got[1].StartedAt.Equal(t0.Add(55 * time.Minute)) {
		t.Errorf("second window starts %v, want %v", got[1].StartedAt, t0.Add(55*time.Minute))
	}
	if got[0].ID == got[1].ID {
		t.Errorf("split windows share ID %q", got[0].ID)
	}
}

func TestSessions_GrantSourceIdentityBinding(t *testing.T) {
	t.Parallel()
	// Events carry no sourceIdentity of their own (e.g. an event version
	// that omits it) but the AssumeRole grant proves one.
	g := newSessionIngester(Options{})
	got := g.sessions([]Extracted{
		grantEvent("evt-grant", ciARN, "dora@example.com", nil, t0.Add(-2*time.Minute)),
		sessionEvent("evt-1", ciARN, "", t0),
	})

	if len(got) != 1 {
		t.Fatalf("sessions = %d, want 1", len(got))
	}
	s := got[0]
	if s.Human != "dora@example.com" {
		t.Errorf("Human = %q, want dora@example.com", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrSTSSourceIdentity {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrSTSSourceIdentity)
	}
	if len(s.Attribution.Evidence) != 1 || s.Attribution.Evidence[0] != "evt-grant" {
		t.Errorf("Evidence = %v, want the grant event ID", s.Attribution.Evidence)
	}
}

func TestSessions_SessionTagBinding(t *testing.T) {
	t.Parallel()
	g := newSessionIngester(Options{SessionTagKeys: []string{"operator"}})
	got := g.sessions([]Extracted{
		grantEvent("evt-grant", ciARN, "", map[string]string{"operator": "carol@example.com", "team": "platform"}, t0.Add(-time.Minute)),
		sessionEvent("evt-1", ciARN, "", t0),
	})

	if len(got) != 1 {
		t.Fatalf("sessions = %d, want 1", len(got))
	}
	s := got[0]
	if s.Human != "carol@example.com" {
		t.Errorf("Human = %q, want carol@example.com", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrSessionTags {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrSessionTags)
	}
}

func TestSessions_TagBindingOffWithoutConfiguredKeys(t *testing.T) {
	t.Parallel()
	g := newSessionIngester(Options{}) // no SessionTagKeys
	got := g.sessions([]Extracted{
		grantEvent("evt-grant", ciARN, "", map[string]string{"operator": "carol@example.com"}, t0.Add(-time.Minute)),
		sessionEvent("evt-1", ciARN, "", t0),
	})

	if got[0].Human != "" || got[0].Attribution.Method != corroborate.AttrNone {
		t.Errorf("got binding %q via %q, want unattributed when no tag keys configured",
			got[0].Human, got[0].Attribution.Method)
	}
}

func TestSessions_Unattributed(t *testing.T) {
	t.Parallel()
	g := newSessionIngester(Options{})
	got := g.sessions([]Extracted{
		sessionEvent("evt-1", sessionARN, "", t0),
	})

	if len(got) != 1 {
		t.Fatalf("sessions = %d, want 1", len(got))
	}
	s := got[0]
	if s.Human != "" {
		t.Errorf("Human = %q, want empty", s.Human)
	}
	if s.Attribution.Method != corroborate.AttrNone {
		t.Errorf("Method = %q, want %q", s.Attribution.Method, corroborate.AttrNone)
	}
}

func TestSessions_LatestGrantWins(t *testing.T) {
	t.Parallel()
	// Same role + session name re-assumed: the window joins to the latest
	// grant at or before its end, not an earlier one.
	g := newSessionIngester(Options{})
	got := g.sessions([]Extracted{
		grantEvent("evt-grant-old", ciARN, "old@example.com", nil, t0.Add(-2*time.Hour)),
		grantEvent("evt-grant-new", ciARN, "new@example.com", nil, t0.Add(-time.Minute)),
		grantEvent("evt-grant-future", ciARN, "future@example.com", nil, t0.Add(time.Hour)),
		sessionEvent("evt-1", ciARN, "", t0),
	})

	if got[0].Human != "new@example.com" {
		t.Errorf("Human = %q, want new@example.com (latest grant not after the window)", got[0].Human)
	}
}

func TestSessions_AccessKeySeparatesConcurrentSessions(t *testing.T) {
	t.Parallel()
	// The shared-credential trap from the first live run: two actors on the
	// same SSO principal at the same time. Different access keys mean
	// different STS sessions, and the windows must not merge.
	keyed := func(id, key string, at time.Time) Extracted {
		ex := sessionEvent(id, sessionARN, "", at)
		ex.AccessKeyID = key
		return ex
	}
	g := newSessionIngester(Options{})
	got := g.sessions([]Extracted{
		keyed("evt-agent-1", "ASIAAGENT", t0),
		keyed("evt-other-1", "ASIAOTHER", t0.Add(time.Minute)),
		keyed("evt-agent-2", "ASIAAGENT", t0.Add(2*time.Minute)),
	})

	if len(got) != 2 {
		t.Fatalf("sessions = %d, want 2 (interleaved keys must not merge)", len(got))
	}
	if got[0].ID == got[1].ID {
		t.Errorf("concurrent sessions share ID %q", got[0].ID)
	}
	for _, s := range got {
		if !strings.Contains(s.ID, "/ASIA") {
			t.Errorf("ID %q missing access-key suffix", s.ID)
		}
	}
}

func TestSessions_NonSessionPrincipalsExcluded(t *testing.T) {
	t.Parallel()
	g := newSessionIngester(Options{})
	got := g.sessions([]Extracted{
		{EventID: "evt-user", Principal: "arn:aws:iam::111122223333:user/alice", PrincipalType: "IAMUser", EventTime: t0},
	})
	if len(got) != 0 {
		t.Fatalf("sessions = %d, want 0 for non-assumed-role principals", len(got))
	}
}

func TestSessions_DeterministicOrder(t *testing.T) {
	t.Parallel()
	g := newSessionIngester(Options{})
	events := []Extracted{
		sessionEvent("evt-b", ciARN, "", t0.Add(time.Minute)),
		sessionEvent("evt-a", sessionARN, "", t0),
	}
	first := g.sessions(events)
	for range 10 {
		if again := g.sessions(events); len(again) != len(first) || again[0].ID != first[0].ID || again[1].ID != first[1].ID {
			t.Fatal("sessions() order is not deterministic across runs")
		}
	}
	if !first[0].StartedAt.Before(first[1].StartedAt) {
		t.Error("sessions not sorted by StartedAt")
	}
}
