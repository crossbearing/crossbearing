package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crossbearing/crossbearing/internal/attribute"
	"github.com/crossbearing/crossbearing/internal/aws"
	"github.com/crossbearing/crossbearing/internal/pack"
)

// The integration test drives the REAL pipeline — transcript ingestion,
// CloudTrail paging, the join, attribution, conventions, rendering, and
// the evidence package — through the production aws.Client pointed at a
// fake AWS endpoint speaking the actual wire protocols (awsjson1.1 for
// CloudTrail, Query/XML for IAM). Nothing is stubbed above the HTTP layer.

const (
	testSessionID = "11111111-aaaa-bbbb-cccc-222222222222"
	testPrincipal = "arn:aws:sts::111122223333:assumed-role/agent-deployer/agent-run"
	testRoleARN   = "arn:aws:iam::111122223333:role/agent-deployer"
	testAccessKey = "ASIATESTKEY00001"
)

// Fixture times sit safely in the past so the now() cap and the
// delivery-lag note never fire.
var (
	claimAt  = time.Date(2026, 6, 8, 3, 0, 0, 0, time.UTC)
	recordAt = claimAt.Add(3 * time.Second)
)

func writeTranscript(t *testing.T) string {
	t.Helper()
	line := func(s string) string { return s + "\n" }
	transcript :=
		line(fmt.Sprintf(`{"type":"assistant","sessionId":%q,"uuid":"u1","timestamp":%q,"message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_aws","name":"Bash","input":{"command":"aws sts get-caller-identity --profile test"}}]}}`,
			testSessionID, claimAt.Format(time.RFC3339))) +
			line(fmt.Sprintf(`{"type":"user","sessionId":%q,"uuid":"u2","timestamp":%q,"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_aws","content":"ok"}]}}`,
				testSessionID, claimAt.Add(5*time.Second).Format(time.RFC3339))) +
			// A claim CloudTrail cannot corroborate: must be scoped out, not
			// reported as a divergence.
			line(fmt.Sprintf(`{"type":"assistant","sessionId":%q,"uuid":"u3","timestamp":%q,"message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_go","name":"Bash","input":{"command":"go test ./..."}}]}}`,
				testSessionID, claimAt.Add(time.Minute).Format(time.RFC3339))) +
			line(fmt.Sprintf(`{"type":"user","sessionId":%q,"uuid":"u4","timestamp":%q,"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_go","content":"ok"}]}}`,
				testSessionID, claimAt.Add(2*time.Minute).Format(time.RFC3339)))

	path := filepath.Join(t.TempDir(), testSessionID+".jsonl")
	if err := os.WriteFile(path, []byte(transcript), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func rawCloudTrailEvent(id, source, name string, at time.Time) string {
	raw, _ := json.Marshal(map[string]any{
		"eventVersion": "1.11",
		"eventID":      id,
		"eventTime":    at.Format(time.RFC3339),
		"eventSource":  source,
		"eventName":    name,
		"awsRegion":    "us-west-2",
		"readOnly":     name == "GetCallerIdentity",
		"userIdentity": map[string]any{
			"type":        "AssumedRole",
			"arn":         testPrincipal,
			"accessKeyId": testAccessKey,
		},
	})
	return string(raw)
}

// fakeAWS serves just enough CloudTrail (awsjson1.1) and IAM (Query/XML)
// for one report run.
func fakeAWS(t *testing.T) *httptest.Server {
	t.Helper()
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:saml-provider/sso"},"Action":["sts:AssumeRoleWithSAML"]}]}`

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Amz-Target"), "LookupEvents") {
			resp, _ := json.Marshal(map[string]any{
				"Events": []map[string]any{
					{
						"EventId":         "evt-corroborated",
						"EventName":       "GetCallerIdentity",
						"EventTime":       recordAt.Unix(),
						"CloudTrailEvent": rawCloudTrailEvent("evt-corroborated", "sts.amazonaws.com", "GetCallerIdentity", recordAt),
					},
					{
						"EventId":         "evt-unclaimed",
						"EventName":       "CreateBucket",
						"EventTime":       claimAt.Add(5 * time.Minute).Unix(),
						"CloudTrailEvent": rawCloudTrailEvent("evt-unclaimed", "s3.amazonaws.com", "CreateBucket", claimAt.Add(5*time.Minute)),
					},
				},
			})
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_, _ = w.Write(resp)
			return
		}

		_ = r.ParseForm()
		if r.Form.Get("Action") == "GetRole" {
			if got := r.Form.Get("RoleName"); got != "agent-deployer" {
				t.Errorf("GetRole RoleName = %q, want agent-deployer", got)
			}
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprintf(w, `<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetRoleResult><Role>
    <Arn>%s</Arn><RoleName>agent-deployer</RoleName><RoleId>AROATEST</RoleId>
    <Path>/</Path><CreateDate>2026-01-01T00:00:00Z</CreateDate>
    <AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument>
  </Role></GetRoleResult>
  <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>
</GetRoleResponse>`, testRoleARN, url.QueryEscape(trustPolicy))
			return
		}

		t.Errorf("unexpected AWS call: target=%q action=%q", r.Header.Get("X-Amz-Target"), r.Form.Get("Action"))
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
}

// writeGitHubAudit fabricates an org audit-log export whose bot actor
// matches the principal filter and acts inside the claim window.
func writeGitHubAudit(t *testing.T) string {
	t.Helper()
	line := fmt.Sprintf(`{"@timestamp":%d,"_document_id":"gh-doc-1","action":"git.push","actor":"agent-deployer[bot]","org":"crossbearing","repo":"crossbearing/engine"}`,
		claimAt.Add(30*time.Second).UnixMilli())
	path := filepath.Join(t.TempDir(), "github-audit.jsonl")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeK8sAudit fabricates an audit log where the agent's ServiceAccount
// impersonates the human — the convention working as designed.
func writeK8sAudit(t *testing.T) string {
	t.Helper()
	line := fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"k8s-audit-1","stage":"ResponseComplete","verb":"create","user":{"username":"system:serviceaccount:agents:agent-deployer"},"impersonatedUser":{"username":"tester@example.com"},"objectRef":{"resource":"deployments","namespace":"prod","name":"api"},"responseStatus":{"code":201},"stageTimestamp":%q}`,
		claimAt.Add(90*time.Second).Format(time.RFC3339))
	path := filepath.Join(t.TempDir(), "k8s-audit.jsonl")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunReportPipeline_EndToEnd(t *testing.T) {
	server := fakeAWS(t)
	defer server.Close()

	client := aws.NewClientForTesting(server.URL, "us-west-2", nil)
	packPath := filepath.Join(t.TempDir(), "aep.json")
	var out bytes.Buffer

	err := runReportPipeline(context.Background(), client, reportParams{
		transcript:  writeTranscript(t),
		region:      "us-west-2",
		operator:    "tester@example.com",
		principal:   "agent-deployer",
		pad:         30 * time.Minute,
		tagKeys:     "operator",
		packOut:     packPath,
		githubAudit: writeGitHubAudit(t),
		githubOrg:   "crossbearing",
		k8sAudit:    writeK8sAudit(t),
		k8sCluster:  "prod-east",
	}, &out, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("runReportPipeline: %v\noutput:\n%s", err, out.String())
	}

	got := out.String()
	for _, want := range []string{
		"corroborated 1",     // the aws CLI claim matched its record
		"unclaimed-record 3", // CreateBucket + github git.push + k8s create, none claimed
		"unrecorded-claim 0", // the go-test claim was scoped out, not diverged
		"ATTRIBUTION",
		"⇄", // access-key proof binds the credential session
		"key=" + testAccessKey,
		"human=tester@example.com (declared)",
		// the k8s impersonation convention binds record-side and outranks declared
		"(k8s-impersonation)",
		"gap: trust policy does not require sts:SourceIdentity",
		"github-audit:git.push",        // the github stream joined
		"k8s-audit:create:deployments", // the k8s stream joined
		"evidence package: " + packPath,
		"explicitly unsigned",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report output missing %q\n---\n%s", want, got)
		}
	}

	// The emitted package must satisfy its own integrity contract.
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatalf("evidence package not written: %v", err)
	}
	var p pack.Package
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("package does not parse: %v", err)
	}
	if err := pack.VerifyChain(&p); err != nil {
		t.Fatalf("emitted package fails chain verification: %v", err)
	}
	if p.Signature != nil {
		t.Error("package claims a signature with no --kms-key")
	}
	if p.Chain.Length != 4 {
		t.Errorf("chain length = %d, want 4 findings (1 corroborated + 3 unclaimed across 3 streams)", p.Chain.Length)
	}
	if len(p.Controls) != 6 {
		t.Errorf("controls = %d, want 3 SOC 2 + 3 ISO 42001", len(p.Controls))
	}
}

func TestRunReport_FlagValidation(t *testing.T) {
	if err := runReport([]string{}); err == nil || !strings.Contains(err.Error(), "--transcript") {
		t.Errorf("missing transcript: err = %v", err)
	}
	t.Setenv("AWS_REGION", "") // the region flag defaults from this env var
	if err := runReport([]string{"--transcript", "x.jsonl", "--region", ""}); err == nil || !strings.Contains(err.Error(), "--region") {
		t.Errorf("missing region: err = %v", err)
	}
}

func TestRoleFromPrincipal(t *testing.T) {
	t.Parallel()
	tests := []struct{ arn, want string }{
		{testPrincipal, "agent-deployer"},
		{"arn:aws:iam::111122223333:user/alice", ""},
		{"arn:aws:sts::111122223333:assumed-role/broken", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := roleFromPrincipal(tt.arn); got != tt.want {
			t.Errorf("roleFromPrincipal(%q) = %q, want %q", tt.arn, got, tt.want)
		}
	}
}

func TestCredentialSessionLabel(t *testing.T) {
	t.Parallel()
	b := attribute.Binding{
		Principal:       testPrincipal,
		RecordSessionID: testPrincipal + "@2026-06-08T03:00:03Z/" + testAccessKey,
	}
	if got, want := credentialSessionLabel(b), "agent-run@2026-06-08T03:00:03Z key="+testAccessKey; got != want {
		t.Errorf("credentialSessionLabel = %q, want %q", got, want)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate(short) = %q", got)
	}
	if got := truncate("0123456789abc", 10); got != "0123456789…" {
		t.Errorf("truncate long = %q", got)
	}
}
