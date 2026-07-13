// Command crossbearing is the evidence engine: read-only ingestion of
// claim-side and record-side streams, the corroboration join, and Agent
// Evidence Package emission. Runs in the customer's own AWS account.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/crossbearing/crossbearing/internal/attribute"
	"github.com/crossbearing/crossbearing/internal/aws"
	"github.com/crossbearing/crossbearing/internal/corroborate"
	"github.com/crossbearing/crossbearing/internal/evidence"
	"github.com/crossbearing/crossbearing/internal/ingest/azure"
	"github.com/crossbearing/crossbearing/internal/ingest/bedrock"
	"github.com/crossbearing/crossbearing/internal/ingest/claudecode"
	"github.com/crossbearing/crossbearing/internal/ingest/cloudtrail"
	"github.com/crossbearing/crossbearing/internal/ingest/gcp"
	"github.com/crossbearing/crossbearing/internal/ingest/github"
	"github.com/crossbearing/crossbearing/internal/ingest/k8s"
	"github.com/crossbearing/crossbearing/internal/pack"
	htmlrender "github.com/crossbearing/crossbearing/internal/render"
)

var version = "0.0.1-dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println("crossbearing", version)
			return
		case "report":
			if err := runReport(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "crossbearing report:", err)
				os.Exit(1)
			}
			return
		}
	}
	fmt.Fprintln(os.Stderr, "crossbearing: ingest → attribute → corroborate → package")
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  crossbearing report --transcript <session.jsonl> [flags]")
	fmt.Fprintln(os.Stderr, "  crossbearing version")
	os.Exit(2)
}

// reportParams carries the report flags into the pipeline.
type reportParams struct {
	transcript      string
	bedrockAudit    string
	bedrockSession  string
	region          string
	operator        string
	principal       string
	agentSessionPat string
	tagKeys         string
	packOut         string
	kmsKey          string
	githubAudit     string
	githubOrg       string
	githubAppHumans string
	k8sAudit        string
	k8sCluster      string
	gcpAudit        string
	gcpProject      string
	azureAudit      string
	azureSub        string
	cloudtrailFile  string
	productionMatch string
	format          string
	preparedFor     string
	color           string
	pad             time.Duration
}

// runReport parses flags, builds the real AWS client, and hands off to the
// pipeline. Kept thin: everything testable lives in runReportPipeline.
func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	var p reportParams
	fs.StringVar(&p.transcript, "transcript", "", "Claude Code session transcript (.jsonl) claim stream (one of --transcript / --bedrock-audit required)")
	fs.StringVar(&p.bedrockAudit, "bedrock-audit", "", "Bedrock model-invocation log (CloudWatch/S3 JSON array or JSONL export, gzip ok) to join as a claim stream")
	fs.StringVar(&p.bedrockSession, "bedrock-session-key", "", "requestMetadata key that carries the agent session id in the Bedrock log (default: group by calling role ARN)")
	fs.StringVar(&p.region, "region", os.Getenv("AWS_REGION"), "AWS region to read CloudTrail in")
	fs.StringVar(&p.operator, "operator", "", "declared human operator for the session (self-reported)")
	fs.StringVar(&p.principal, "principal", "", "substring filter: only join records whose acting principal contains this")
	fs.StringVar(&p.agentSessionPat, "agent-session-pattern", "", "substring of the assumed-role session name to treat as the agent's; promotes matching unattributed records into the agent-suspect tier of the report (operator-asserted; proven-credential matches need no flag)")
	fs.DurationVar(&p.pad, "pad", 30*time.Minute, "how far beyond the session window to ingest records")
	fs.StringVar(&p.tagKeys, "tag-keys", "operator,human,owner", "comma-separated session-tag keys that may carry a human binding")
	fs.StringVar(&p.packOut, "pack", "", "write the Agent Evidence Package (JSON) to this path")
	fs.StringVar(&p.kmsKey, "kms-key", "", "KMS signing key ARN for the evidence package (omit = explicitly unsigned)")
	fs.StringVar(&p.githubAudit, "github-audit", "", "GitHub org audit-log file (API JSON or JSONL export) to join as a record stream")
	fs.StringVar(&p.githubOrg, "github-org", "", "organization the GitHub audit log belongs to (anchors provenance locators)")
	fs.StringVar(&p.githubAppHumans, "github-app-humans", "", "JSON file mapping bot/App actor logins to their accountable humans ({\"ci[bot]\": \"alice@example.com\"}) — the GitHub analogue of an STS SourceIdentity convention")
	fs.StringVar(&p.k8sAudit, "k8s-audit", "", "Kubernetes audit-log file (JSONL or EventList) to join as a record stream")
	fs.StringVar(&p.k8sCluster, "k8s-cluster", "", "cluster name the K8s audit log belongs to (anchors provenance locators)")
	fs.StringVar(&p.gcpAudit, "gcp-audit", "", "GCP Cloud Audit Log file (gcloud --format=json array or JSONL) to join as a record stream")
	fs.StringVar(&p.gcpProject, "gcp-project", "", "GCP project the audit log belongs to (anchors provenance locators)")
	fs.StringVar(&p.azureAudit, "azure-audit", "", "Azure Activity Log file (az monitor activity-log list -o json) to join as a record stream")
	fs.StringVar(&p.azureSub, "azure-subscription", "", "Azure subscription the activity log belongs to (anchors provenance locators)")
	fs.StringVar(&p.cloudtrailFile, "aws-cloudtrail", "", "captured CloudTrail events (JSON array of event objects); replaces the live API — runs offline, no AWS creds")
	fs.StringVar(&p.productionMatch, "production-match", "", "comma-separated substrings marking a record target as production-touching; an unclaimed production action with no human binding escalates to Unattributed")
	fs.StringVar(&p.format, "format", "text", "output format: text (the operator report) or html (the print-to-PDF Agent Attribution Audit)")
	fs.StringVar(&p.preparedFor, "prepared-for", "", "organization name on the report cover (html only)")
	fs.StringVar(&p.color, "color", "auto", "colorize the text report: auto (only when stdout is a terminal) / always / never; NO_COLOR is honored")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if p.format != "text" && p.format != "html" {
		return fmt.Errorf("--format must be text or html (got %q)", p.format)
	}
	if p.transcript == "" && p.bedrockAudit == "" {
		return fmt.Errorf("a claim stream is required: pass --transcript and/or --bedrock-audit")
	}
	if p.cloudtrailFile == "" && p.region == "" {
		return fmt.Errorf("--region is required for live CloudTrail (or pass --aws-cloudtrail to run offline)")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// The AWS client is only needed for the live paths (CloudTrail API, IAM
	// convention checks, KMS signing). A fully offline run — captured
	// CloudTrail, no region — skips it entirely.
	var client *aws.Client
	if p.region != "" {
		c, err := aws.NewClient(ctx, aws.ClientConfig{Region: p.region}, logger)
		if err != nil {
			return err
		}
		defer c.Close()
		client = c
	}

	return runReportPipeline(ctx, client, p, os.Stdout, logger)
}

// runReportPipeline produces the divergence report for one Claude Code
// session: what the transcript claims the agent did, joined against what
// CloudTrail recorded in the same window, with attribution and an optional
// evidence package. Read-only against the account by construction —
// cloudtrail:LookupEvents and iam:GetRole are the only AWS reads, kms:Sign
// the only other call and only when a key is given.
func runReportPipeline(ctx context.Context, client *aws.Client, p reportParams, stdout io.Writer, logger *slog.Logger) error {
	// Claim side: the agent's own account of what it did. A Claude Code
	// transcript and/or a Bedrock model-invocation log (kagent and other
	// Bedrock agents) — both self-reported, merged into one claim stream.
	var claimSide struct {
		Sessions []corroborate.Session
		Claims   []corroborate.Claim
	}
	if p.transcript != "" {
		r, err := claudecode.New(logger, claudecode.Options{DeclaredOperator: p.operator}).IngestFile(p.transcript)
		if err != nil {
			return err
		}
		claimSide.Sessions = append(claimSide.Sessions, r.Sessions...)
		claimSide.Claims = append(claimSide.Claims, r.Claims...)
	}
	if p.bedrockAudit != "" {
		r, err := bedrock.New(logger, bedrock.Options{DeclaredOperator: p.operator, SessionKey: p.bedrockSession}).IngestFile(p.bedrockAudit)
		if err != nil {
			return err
		}
		claimSide.Sessions = append(claimSide.Sessions, r.Sessions...)
		claimSide.Claims = append(claimSide.Claims, r.Claims...)
	}
	if len(claimSide.Sessions) == 0 {
		return fmt.Errorf("claim streams yielded no sessions")
	}

	// Record side: CloudTrail over the session window, padded.
	from, to := claimSide.Sessions[0].StartedAt, claimSide.Sessions[0].EndedAt
	for _, s := range claimSide.Sessions {
		if s.StartedAt.Before(from) {
			from = s.StartedAt
		}
		if s.EndedAt.After(to) {
			to = s.EndedAt
		}
	}
	from, to = from.Add(-p.pad), to.Add(p.pad)
	// Live LookupEvents must not ask for the future; a captured file defines
	// its own record horizon, and clamping it to wall clock would make an
	// offline report depend on when it was run.
	if now := time.Now(); p.cloudtrailFile == "" && to.After(now) {
		to = now
	}

	// A target is production-touching when it matches any --production-match
	// term; the same scope applies to every stream so an unclaimed production
	// action with no human binding escalates to Unattributed.
	//
	// A list, not one substring: production is rarely a single prefix. On a
	// cluster it is a set of namespaces (argocd, monitoring, kube-system) and
	// in an account a set of ARN fragments, and an operator who can only name
	// one of them silently under-scopes the report — which reads as a clean
	// cluster rather than an unmeasured one.
	var isProd func(string) bool
	if terms := splitTerms(p.productionMatch); len(terms) > 0 {
		isProd = func(target string) bool {
			for _, m := range terms {
				if strings.Contains(target, m) {
					return true
				}
			}
			return false
		}
	}

	var ctAPI cloudtrail.EventsAPI
	if client != nil {
		ctAPI = aws.NewCloudTrailService(client)
	}
	ct := cloudtrail.New(ctAPI, logger, cloudtrail.Options{
		SessionTagKeys: strings.Split(p.tagKeys, ","),
		IsProduction:   isProd,
	})
	var (
		recordSide cloudtrail.Result
		err        error
	)
	if p.cloudtrailFile != "" {
		recordSide, err = ct.IngestFile(p.cloudtrailFile)
	} else {
		recordSide, err = ct.Ingest(ctx, from, to)
	}
	if err != nil {
		return err
	}

	// Additional record streams: independent reference lines crossing the
	// same window — the more streams, the smaller the cocked hat.
	if p.githubAudit != "" {
		appHumans, err := loadAppHumans(p.githubAppHumans)
		if err != nil {
			return err
		}
		gh, err := github.New(logger, github.Options{Org: p.githubOrg, IsProduction: isProd, AppHumans: appHumans}).IngestFile(p.githubAudit)
		if err != nil {
			return err
		}
		recordSide.Records = append(recordSide.Records, gh.Records...)
		recordSide.Sessions = append(recordSide.Sessions, gh.Sessions...)
	}
	if p.k8sAudit != "" {
		ku, err := k8s.New(logger, k8s.Options{Cluster: p.k8sCluster, IsProduction: isProd}).IngestFile(p.k8sAudit)
		if err != nil {
			return err
		}
		recordSide.Records = append(recordSide.Records, ku.Records...)
		recordSide.Sessions = append(recordSide.Sessions, ku.Sessions...)
	}
	if p.gcpAudit != "" {
		gc, err := gcp.New(logger, gcp.Options{Project: p.gcpProject, IsProduction: isProd}).IngestFile(p.gcpAudit)
		if err != nil {
			return err
		}
		recordSide.Records = append(recordSide.Records, gc.Records...)
		recordSide.Sessions = append(recordSide.Sessions, gc.Sessions...)
	}
	if p.azureAudit != "" {
		az, err := azure.New(logger, azure.Options{Subscription: p.azureSub, IsProduction: isProd}).IngestFile(p.azureAudit)
		if err != nil {
			return err
		}
		recordSide.Records = append(recordSide.Records, az.Records...)
		recordSide.Sessions = append(recordSide.Sessions, az.Sessions...)
	}

	// Scope the join. Records: only the principal the agent's credentials
	// acted as (session→principal correlation is internal/attribute's job;
	// until then the operator names it). Claims: only those whose derived
	// vocabulary can produce CloudTrail records at all — a Write to a local
	// file is not corroborable by this record stream, so its absence there
	// is not a divergence.
	records := recordSide.Records
	if p.principal != "" {
		records = records[:0:0]
		for _, r := range recordSide.Records {
			if strings.Contains(r.Principal, p.principal) {
				records = append(records, r)
			}
		}
	}
	policy := corroborate.DefaultMatchPolicy()
	policy.OperationMap = corroborate.MergeOperationMaps(
		corroborate.DeriveOperationMap(claimSide.Claims), // claim-specific, wins
		corroborate.MCPGitHubOperationMap(),              // static attested seed
	)
	var scoped []corroborate.Claim
	for _, c := range claimSide.Claims {
		if len(policy.OperationMap[corroborate.ClaimKey(c)]) > 0 {
			scoped = append(scoped, c)
		}
	}

	rep := corroborate.Join(claimSide.Sessions, scoped, records, policy)
	rep.From, rep.To = from, to

	// Attribution: bind the agent session to the credential sessions it
	// provably wielded, and check whether the roles involved even permit
	// human binding.
	recordSessions := recordSide.Sessions
	if p.principal != "" {
		recordSessions = recordSessions[:0:0]
		for _, s := range recordSide.Sessions {
			if strings.Contains(s.ID, p.principal) {
				recordSessions = append(recordSessions, s)
			}
		}
	}
	bindings := attribute.Bind(claimSide.Sessions, recordSessions, rep.Findings)
	// The trust-policy convention check is a live IAM read; offline runs
	// (no client) skip it — the Unattributed finding still lands from the
	// join, carrying its own explanation.
	var conventions []attribute.RoleConventions
	if client != nil {
		conventions = checkRoleConventions(ctx, client, records, logger)
	}

	// Agent-suspect scoping: a post-Join labeling pass that surfaces the
	// unattributed records positively fingerprinted to the agent (a proven
	// credential, or an operator-named session). Fail-open and never asserts a
	// human; the full finding set above is unchanged and is what the evidence
	// package signs.
	scope := attribute.NewScopeIndex(rep.Findings, p.agentSessionPat)

	// HTML emits the print-to-PDF Agent Attribution Audit to stdout; the text
	// report is the operator-facing default. The pack confirmation then goes to
	// stderr so it never lands inside the redirected HTML.
	packNote := stdout
	if p.format == "html" {
		packNote = os.Stderr
		suspect := func(r *corroborate.Record) (bool, string) { return attribute.AgentSuspect(*r, scope) }
		if err := htmlrender.RenderWith(stdout, &rep, htmlrender.Meta{
			PreparedFor: p.preparedFor,
			Region:      cmp.Or(p.region, "offline"),
			GeneratedAt: time.Now(),
		}, suspect); err != nil {
			return err
		}
	} else {
		render(stdout, &rep, bindings, conventions, scope, renderContext{
			region:          cmp.Or(p.region, "offline (captured CloudTrail)"),
			offline:         p.cloudtrailFile != "",
			principalFilter: p.principal,
			claimsIngested:  len(claimSide.Claims),
			claimsScoped:    len(scoped),
			recordsIngested: len(recordSide.Records),
			recordsJoined:   len(records),
			color:           resolveColor(p.color, stdout),
		})
	}

	if p.packOut != "" {
		if err := writePack(ctx, p, &rep, policy, bindings, conventions, client, packNote); err != nil {
			return err
		}
	}
	return nil
}

// writePack builds, optionally signs, self-verifies, and writes the Agent
// Evidence Package.
func writePack(ctx context.Context, params reportParams, rep *corroborate.Report, policy corroborate.MatchPolicy, bindings []attribute.Binding, conventions []attribute.RoleConventions, client *aws.Client, stdout io.Writer) error {
	p, err := pack.Build(pack.Input{
		Report:      rep,
		Policy:      policy,
		Bindings:    bindings,
		Conventions: conventions,
		Region:      params.region,
		GeneratedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}

	var signer evidence.Signer = evidence.NoopSigner{}
	if params.kmsKey != "" {
		if client == nil {
			return fmt.Errorf("--kms-key needs AWS credentials; pass --region (offline runs cannot sign)")
		}
		signer = evidence.NewKMSSigner(client.KMS(), params.kmsKey)
	}
	if err := p.Sign(ctx, signer); err != nil {
		return err
	}
	if err := pack.VerifyChain(p); err != nil {
		return fmt.Errorf("refusing to write a package that fails self-verification: %w", err)
	}

	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize evidence package: %w", err)
	}
	if err := os.WriteFile(params.packOut, append(out, '\n'), 0o644); err != nil {
		return fmt.Errorf("failed to write evidence package: %w", err)
	}

	signed := "explicitly unsigned (no --kms-key)"
	if p.Signature != nil {
		signed = "signed " + p.Signature.Algo + " key " + p.Signature.KeyRef
	}
	fmt.Fprintf(stdout, "\nevidence package: %s\n  chain %s…(%d findings) · %s\n", params.packOut, truncate(p.Chain.Head, 16), p.Chain.Length, signed)
	return nil
}

// checkRoleConventions runs the trust-policy checker over every role the
// joined records acted as. Read-only: iam:GetRole only. A role we cannot
// fetch is reported as a gap in coverage, not silently dropped.
func checkRoleConventions(ctx context.Context, client *aws.Client, records []corroborate.Record, logger *slog.Logger) []attribute.RoleConventions {
	roles := make(map[string]bool)
	for _, r := range records {
		if name := roleFromPrincipal(r.Principal); name != "" {
			roles[name] = true
		}
	}
	if len(roles) == 0 {
		return nil
	}

	iamSvc := aws.NewIAMService(client)
	var out []attribute.RoleConventions
	for name := range roles {
		role, err := iamSvc.GetRole(ctx, name)
		if err != nil || role == nil {
			logger.Warn("could not fetch role for convention check", "role", name, "error", err)
			continue
		}
		rc, err := attribute.CheckTrustPolicy(role.RoleARN, role.TrustPolicy)
		if err != nil {
			logger.Warn("could not parse trust policy", "role", name, "error", err)
			continue
		}
		out = append(out, rc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RoleARN < out[j].RoleARN })
	return out
}

// roleFromPrincipal extracts the role name from an assumed-role principal
// ARN: arn:aws:sts::ACCT:assumed-role/ROLE/SESSION → ROLE. Delegates to
// corroborate, the single source of assumed-role ARN parsing.
func roleFromPrincipal(arn string) string {
	return corroborate.RoleNameFromARN(arn)
}

type renderContext struct {
	region          string
	offline         bool
	principalFilter string
	claimsIngested  int
	claimsScoped    int
	recordsIngested int
	recordsJoined   int
	color           bool
}

// resolveColor decides whether the text report carries ANSI color: never for
// files/pipes (so captured output and the golden tests stay plain), only a real
// terminal under "auto", and honoring NO_COLOR. "always"/"never" force it.
func resolveColor(mode string, w io.Writer) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// colorizer adds ANSI truecolor to the text report, on-brand and tasteful: the
// findings color-code by kind so a dense report reads at a glance. Off renders
// plain text (the zero value), so it never leaks into captured output.
type colorizer struct{ on bool }

func (c colorizer) p(code, s string) string {
	if !c.on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func (c colorizer) bold(s string) string  { return c.p("1", s) }
func (c colorizer) blue(s string) string  { return c.p("1;38;2;11;150;214", s) } // the fix — the headline gap
func (c colorizer) red(s string) string   { return c.p("1;38;2;181;67;46", s) }  // mismatch
func (c colorizer) amber(s string) string { return c.p("1;38;2;181;125;30", s) } // unclaimed / unrecorded
// green marks corroborated findings — the agent's account of an action matched
// the record. It is an honesty verdict, NOT a safety one: a corroborated action
// can be the worst thing in the window. Green says "this one needs no chasing
// down", never "this one was fine".
func (c colorizer) green(s string) string { return c.p("1;38;2;58;138;94", s) }
func (c colorizer) dim(s string) string   { return c.p("38;2;130;144;160", s) } // detail / why

// kind paints a string in the finding kind's color (no-op for unknown kinds).
func (c colorizer) kind(k corroborate.FindingKind, s string) string {
	switch k {
	case corroborate.Unattributed:
		return c.blue(s)
	case corroborate.Mismatch:
		return c.red(s)
	case corroborate.UnclaimedRecord, corroborate.UnrecordedClaim:
		return c.amber(s)
	case corroborate.Corroborated:
		return c.green(s)
	}
	return s
}

var kindOrder = []corroborate.FindingKind{
	corroborate.Unattributed,
	corroborate.Mismatch,
	corroborate.UnclaimedRecord,
	corroborate.UnrecordedClaim,
	corroborate.Corroborated,
}

func render(w io.Writer, rep *corroborate.Report, bindings []attribute.Binding, conventions []attribute.RoleConventions, scope attribute.ScopeIndex, rc renderContext) {
	const ts = "2006-01-02 15:04:05Z"
	c := colorizer{on: rc.color}
	claimDeclared := make(map[string]bool, len(rep.Sessions))
	for _, s := range rep.Sessions {
		claimDeclared[s.ID] = s.Human != ""
	}
	fmt.Fprintf(w, "%s\n", c.bold("crossbearing divergence report"))
	fmt.Fprintf(w, "  window   %s → %s (%s)\n", rep.From.UTC().Format(ts), rep.To.UTC().Format(ts), rc.region)
	for _, s := range rep.Sessions {
		human := s.Human
		if human == "" {
			human = c.blue("UNATTRIBUTED")
		}
		fmt.Fprintf(w, "  session  %s\n           agent=%s human=%s (%s) active %s → %s\n",
			s.ID, s.Agent, human, s.Attribution.Method,
			s.StartedAt.UTC().Format(ts), s.EndedAt.UTC().Format(ts))
	}
	fmt.Fprintf(w, "  claims   %d in transcript · %d record-corroborable (aws CLI vocabulary)\n",
		rc.claimsIngested, rc.claimsScoped)
	filter := "no principal filter"
	if rc.principalFilter != "" {
		filter = fmt.Sprintf("principal ~ %q", rc.principalFilter)
	}
	fmt.Fprintf(w, "  records  %d in window · %d joined (%s)\n\n", rc.recordsIngested, rc.recordsJoined, filter)

	tally := rep.Tally()
	var parts []string
	for _, k := range kindOrder {
		part := fmt.Sprintf("%s %d", k, tally[k])
		if tally[k] > 0 {
			part = c.kind(k, part)
		} else {
			part = c.dim(part)
		}
		parts = append(parts, part)
	}
	fmt.Fprintf(w, "  %s\n", strings.Join(parts, " · "))
	// The tally reads like a scorecard, and a scorecard invites a verdict the
	// evidence cannot give. Every kind above answers "who acted, and did they
	// say so" — none answers "should they have". A corroborated action can be
	// the worst thing in the window, and the reader must never take the green
	// column for a clean bill of health. Say so where the numbers are, not in
	// a footnote nobody reaches.
	fmt.Fprintf(w, "  %s\n",
		c.dim("who acted · did they say so. not: was it allowed — that judgment is yours."))
	// Delivery lag is measured against wall clock, which says nothing about
	// when a captured file was exported — the note only makes sense live.
	if !rc.offline && time.Since(rep.To) < 15*time.Minute {
		fmt.Fprintf(w, "  note: window ends <15m ago; CloudTrail delivery lag may still hide records\n")
	}

	if len(bindings) > 0 || len(conventions) > 0 {
		fmt.Fprintf(w, "\n%s\n", c.bold("ATTRIBUTION"))
	}
	for _, b := range bindings {
		human := b.Human
		if human == "" {
			human = c.blue("UNATTRIBUTED")
		}
		mark := "≈" // window overlap only
		if b.Confidence == attribute.ConfidenceCorroborated {
			mark = "⇄"
		}
		fmt.Fprintf(w, "  agent session %s %s credential session %s\n",
			truncate(b.ClaimSessionID, 16), mark, credentialSessionLabel(b))
		fmt.Fprintf(w, "    %s · human=%s (%s) · evidence: %d item(s)\n",
			b.Confidence, human, b.Method, len(b.Evidence))
		if b.Conflict != "" {
			fmt.Fprintf(w, "    CONFLICT: %s\n", b.Conflict)
		}
		// Records naming a human the harness never declared is a convention
		// gap, not a headline: the cloud side is doing its half of the
		// binding; the launch side should do its half so the two can be
		// cross-checked.
		if b.Human != "" && !claimDeclared[b.ClaimSessionID] {
			fmt.Fprintf(w, "    %s\n", c.dim("gap: records name the human; the agent session declared no operator — pass --operator so the declaration can be cross-checked against the records"))
		}
	}
	for _, rc := range conventions {
		gaps := rc.Gaps()
		if len(gaps) == 0 {
			fmt.Fprintf(w, "  role %s: attribution conventions in place ✓\n", truncate(rc.RoleARN, 90))
			continue
		}
		fmt.Fprintf(w, "  role %s:\n", truncate(rc.RoleARN, 90))
		for _, g := range gaps {
			fmt.Fprintf(w, "    gap: %s\n", g)
		}
	}

	byKind := make(map[corroborate.FindingKind][]corroborate.Finding)
	for _, f := range rep.Findings {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	for _, kind := range kindOrder {
		fs := byKind[kind]
		if len(fs) == 0 {
			continue
		}
		sort.SliceStable(fs, func(i, j int) bool { return findingAt(fs[i]).Before(findingAt(fs[j])) })
		fmt.Fprintf(w, "\n%s\n", c.kind(kind, fmt.Sprintf("%s (%d)", strings.ToUpper(string(kind)), len(fs))))
		for _, f := range fs {
			renderFinding(w, f, c)
		}
	}

	// Agent-suspect tier: the subset of unattributed findings positively
	// fingerprinted to the agent, each with its reason. A labeling pass over the
	// same findings — the UNATTRIBUTED section above is the complete, signed
	// trail; this only says where to look first.
	type suspectEntry struct {
		f      corroborate.Finding
		reason string
	}
	var suspect []suspectEntry
	for _, f := range byKind[corroborate.Unattributed] {
		if f.Record == nil {
			continue
		}
		if ok, reason := attribute.AgentSuspect(*f.Record, scope); ok {
			suspect = append(suspect, suspectEntry{f, reason})
		}
	}
	if len(suspect) > 0 {
		n := len(byKind[corroborate.Unattributed])
		sort.SliceStable(suspect, func(i, j int) bool { return findingAt(suspect[i].f).Before(findingAt(suspect[j].f)) })
		fmt.Fprintf(w, "\n%s\n", c.blue(fmt.Sprintf("AGENT-SUSPECT (%d of %d unattributed)", len(suspect), n)))
		if rest := n - len(suspect); rest > 0 {
			fmt.Fprintf(w, "  %s\n", c.dim(fmt.Sprintf("the other %d unattributed action(s) above are in-window but not positively fingerprinted — look harder, not noise.", rest)))
		}
		for _, s := range suspect {
			if s.f.Record != nil {
				fmt.Fprintf(w, "  record       %s by %s (event %s)\n",
					s.f.Record.Operation, truncate(s.f.Record.Principal, 70), s.f.Record.ID)
			}
			fmt.Fprintf(w, "  %s  %s\n\n", c.blue("fingerprint"), s.reason)
		}
	}
}

func renderFinding(w io.Writer, f corroborate.Finding, c colorizer) {
	const ts = "15:04:05Z"
	if f.Claim != nil {
		fmt.Fprintf(w, "  %s   %s at %s\n", c.dim("claim"), truncate(f.Claim.Operation, 90), c.dim(f.Claim.ClaimedAt.UTC().Format(ts)))
	}
	if f.Record != nil {
		// A record-carried identity is the strongest binding there is — when
		// present it belongs on the record line, where it explains why this
		// action is accountable (and why it did not escalate).
		as := ""
		if f.Record.SourceIdentity != "" {
			as = " as " + f.Record.SourceIdentity
		}
		// The target, not just the verb. "k8s-audit:get:secrets" says a
		// secret was read; only the target says WHICH — and the difference
		// between a ConfigMap-shaped secret and the Grafana admin token is
		// the entire finding. A finding an auditor cannot act on, or
		// falsify, is not evidence.
		on := ""
		if len(f.Record.Targets) > 0 {
			on = " on " + truncate(strings.Join(f.Record.Targets, ", "), 70)
		}
		fmt.Fprintf(w, "  %s  %s%s at %s by %s%s\n          %s\n",
			c.dim("record"), f.Record.Operation, on, c.dim(f.Record.RecordedAt.UTC().Format(ts)),
			truncate(f.Record.Principal, 80), as, c.dim("event "+f.Record.ID))
	}
	fmt.Fprintf(w, "  %s     %s\n\n", c.dim("why"), c.dim(f.Why))
}

// loadAppHumans reads the bot→human installation mapping. A missing flag is
// an empty mapping; a named file that cannot be read or parsed is an error —
// a silently dropped mapping would report accountable actions as unattributed.
func loadAppHumans(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read --github-app-humans file: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse --github-app-humans file (expected a JSON object of {\"bot-login\": \"human\"}): %w", err)
	}
	return m, nil
}

// credentialSessionLabel renders a record session ID so the parts that
// distinguish concurrent sessions — start time and access key — survive
// where a blind truncation would cut them off.
func credentialSessionLabel(b attribute.Binding) string {
	rest := strings.TrimPrefix(b.RecordSessionID, b.Principal)
	name := b.Principal
	if i := strings.LastIndexByte(b.Principal, '/'); i >= 0 {
		name = b.Principal[i+1:]
	}
	return name + strings.Replace(rest, "/", " key=", 1)
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// splitTerms parses a comma-separated flag value into its non-empty,
// space-trimmed terms.
func splitTerms(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}
