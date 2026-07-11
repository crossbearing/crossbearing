package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// fabParams is the offline fab/Bedrock dress-rehearsal pipeline (demo/fab/run.sh).
func fabParams(format string) reportParams {
	return reportParams{
		bedrockAudit:    "../../demo/fab/bedrock-invocations.jsonl",
		k8sAudit:        "../../demo/fab/k8s-audit.jsonl",
		k8sCluster:      "prod-eks",
		cloudtrailFile:  "../../demo/fab/aws-cloudtrail.json",
		githubAudit:     "../../demo/fab/github-audit.jsonl",
		githubOrg:       "acme",
		productionMatch: "prod",
		format:          format,
		preparedFor:     "Northwind AI",
		tagKeys:         "operator,human,owner",
		pad:             30 * time.Minute,
	}
}

// TestDemo_DeterministicOutput pins the demo to its committed expected
// output. It runs the exact offline pipeline demo/run.sh runs (no AWS
// client), so the demo can never silently drift from the artifact in
// demo/expected-output.txt — a sales-call demo that prints something
// other than what the README promises is worse than no demo.
func TestDemo_DeterministicOutput(t *testing.T) {
	want, err := os.ReadFile("../../demo/expected-output.txt")
	if err != nil {
		t.Fatalf("read expected output: %v", err)
	}

	var out bytes.Buffer
	err = runReportPipeline(context.Background(), nil, reportParams{
		transcript:      "../../demo/transcript.jsonl",
		cloudtrailFile:  "../../demo/aws-cloudtrail.json",
		k8sAudit:        "../../demo/k8s-audit.jsonl",
		k8sCluster:      "prod-east",
		githubAudit:     "../../demo/github-audit.jsonl",
		githubOrg:       "acme",
		productionMatch: "prod-",
		tagKeys:         "operator,human,owner",
		pad:             30 * time.Minute,
	}, &out, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("demo pipeline: %v", err)
	}

	if out.String() != string(want) {
		t.Errorf("demo output drifted from demo/expected-output.txt.\nRegenerate with ./demo/run.sh if the change is intended.\n--- got ---\n%s", out.String())
	}
}

// TestAWSDemo_DeterministicOutput pins the pure-AWS/CloudTrail demo: one agent
// session whose transcript claims a few read-only aws calls, joined against a
// CloudTrail capture that exercises EVERY finding kind in one run —
// corroborated, mismatch, unclaimed-record, unrecorded-claim, and the
// unattributed production action that the agent-suspect tier then pins to the
// agent's proven credential. The screencast on crossbearing.dev is a recording
// of exactly this run; the golden keeps the two from drifting. Mirrors
// demo/aws/run.sh.
func TestAWSDemo_DeterministicOutput(t *testing.T) {
	want, err := os.ReadFile("../../demo/aws/expected-output.txt")
	if err != nil {
		t.Fatalf("read expected output: %v", err)
	}

	var out bytes.Buffer
	err = runReportPipeline(context.Background(), nil, reportParams{
		transcript:      "../../demo/aws/transcript.jsonl",
		cloudtrailFile:  "../../demo/aws/aws-cloudtrail.json",
		productionMatch: "prod-",
		tagKeys:         "operator,human,owner",
		pad:             30 * time.Minute,
	}, &out, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("aws demo pipeline: %v", err)
	}

	if out.String() != string(want) {
		t.Errorf("aws demo output drifted from demo/aws/expected-output.txt.\nRegenerate with ./demo/aws/run.sh if the change is intended.\n--- got ---\n%s", out.String())
	}
}

// TestFabDemo_DeterministicOutput pins the fab/Bedrock dress-rehearsal demo:
// a synthetic Bedrock model-invocation log (Bash + MCP tool calls) joined
// against K8s audit, CloudTrail, and GitHub audit records. It exercises the
// whole bedrock-ingest → claim-translate → join → attribution path offline,
// so the substrate the live EKS run will use is regression-locked. Mirrors
// demo/fab/run.sh.
func TestFabDemo_DeterministicOutput(t *testing.T) {
	want, err := os.ReadFile("../../demo/fab/expected-output.txt")
	if err != nil {
		t.Fatalf("read expected output: %v", err)
	}

	var out bytes.Buffer
	err = runReportPipeline(context.Background(), nil, fabParams("text"), &out, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("fab demo pipeline: %v", err)
	}

	if out.String() != string(want) {
		t.Errorf("fab demo output drifted from demo/fab/expected-output.txt.\nRegenerate with ./demo/fab/run.sh if the change is intended.\n--- got ---\n%s", out.String())
	}
}

// TestFabDemo_HTML pins the --format html path through the real
// bedrock→join→BuildView integration (not the hand-built sampleReport in the
// render package). The Generated cell uses time.Now(), so this asserts stable,
// time-independent substrings rather than a full golden.
func TestFabDemo_HTML(t *testing.T) {
	var out bytes.Buffer
	if err := runReportPipeline(context.Background(), nil, fabParams("html"), &out, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("fab demo html pipeline: %v", err)
	}
	html := out.String()
	for _, want := range []string{
		"<html", "</html>",
		"Northwind AI",                 // --prepared-for on the cover
		"Of 2 agent sessions",          // headline driven by the real join
		"1 production-touching action", // the unattributed escalation
		"s3:CreateBucket",
		"payments-prod-exports",
		"k8s-audit:delete:configmaps", // the mismatch record side
		"dynamodb delete-table",       // the unrecorded claim
		"Bedrock invocation log",      // streams line
	} {
		if !strings.Contains(html, want) {
			t.Errorf("fab html missing %q", want)
		}
	}
	if n := strings.Count(html, `class="finding sheet"`); n != 3 { // 1 unattributed + 2 divergences
		t.Errorf("finding cards = %d, want 3", n)
	}
}
