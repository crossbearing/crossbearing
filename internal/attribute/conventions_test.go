package attribute

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

const roleARN = "arn:aws:iam::111122223333:role/agent-deployer"

// The convention done right: assumption requires a SourceIdentity and
// session tagging is allowed.
const goodPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
      "Condition": {
        "StringLike": {"sts:SourceIdentity": "*"}
      }
    }
  ]
}`

// What real estates look like: an SSO/SAML trust policy that never
// mentions SourceIdentity — anonymous-by-default.
const ssoPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::111122223333:saml-provider/AWSSSO_DO_NOT_DELETE"},
      "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
      "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}
    }
  ]
}`

func TestCheckTrustPolicy_RequiredConvention(t *testing.T) {
	t.Parallel()
	rc, err := CheckTrustPolicy(roleARN, goodPolicy)
	if err != nil {
		t.Fatalf("CheckTrustPolicy() error = %v", err)
	}
	if !rc.RequiresSourceIdentity {
		t.Error("RequiresSourceIdentity = false for a StringLike condition")
	}
	if rc.ForbidsSourceIdentity {
		t.Error("ForbidsSourceIdentity = true, want false")
	}
	if !rc.AllowsTagSession {
		t.Error("AllowsTagSession = false despite sts:TagSession in actions")
	}
	if gaps := rc.Gaps(); len(gaps) != 0 {
		t.Errorf("Gaps() = %v, want none", gaps)
	}
	sum := sha256.Sum256([]byte(goodPolicy))
	if rc.Evidence.Digest != hex.EncodeToString(sum[:]) {
		t.Error("Evidence.Digest is not the sha256 of the policy as checked")
	}
	if rc.Evidence.Locator != "iam:"+roleARN+"#trust-policy" {
		t.Errorf("Evidence.Locator = %q", rc.Evidence.Locator)
	}
}

func TestCheckTrustPolicy_SSORealityIsAnonymous(t *testing.T) {
	t.Parallel()
	rc, err := CheckTrustPolicy(roleARN, ssoPolicy)
	if err != nil {
		t.Fatalf("CheckTrustPolicy() error = %v", err)
	}
	if rc.RequiresSourceIdentity {
		t.Error("RequiresSourceIdentity = true for a policy that never mentions sts:SourceIdentity")
	}
	if !rc.AllowsTagSession {
		t.Error("AllowsTagSession = false despite sts:TagSession")
	}
	gaps := rc.Gaps()
	if len(gaps) != 2 || !strings.Contains(gaps[0], "does not require sts:SourceIdentity") || !strings.Contains(gaps[1], "tag convention exists but is optional") {
		t.Errorf("Gaps() = %v, want anonymous-by-default + tags-optional", gaps)
	}
}

func TestCheckTrustPolicy_RequiredTags(t *testing.T) {
	t.Parallel()
	policy := `{"Statement":{"Effect":"Allow","Action":["sts:AssumeRole","sts:TagSession"],"Condition":{
	  "StringLike":{"aws:RequestTag/operator":"*@example.com"},
	  "StringEquals":{"aws:RequestTag/team":"platform"},
	  "StringNotEquals":{"aws:RequestTag/env":"prod"},
	  "Null":{"aws:RequestTag/ticket":"true"}
	}}}`
	rc, err := CheckTrustPolicy(roleARN, policy)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	// operator and team are required; env (NotEquals excludes values) and
	// ticket (Null:true = must be absent) are not enforcement.
	if want := []string{"operator", "team"}; !reflect.DeepEqual(rc.RequiredTagKeys, want) {
		t.Errorf("RequiredTagKeys = %v, want %v", rc.RequiredTagKeys, want)
	}
	gaps := rc.Gaps()
	if len(gaps) != 1 || !strings.Contains(gaps[0], "binds via required session tags (operator, team)") {
		t.Errorf("Gaps() = %v, want the tags-bind-but-SourceIdentity-stronger note", gaps)
	}
}

func TestCheckTrustPolicy_SourceIdentityPlusRequiredTagsIsClean(t *testing.T) {
	t.Parallel()
	policy := `{"Statement":{"Effect":"Allow","Action":["sts:AssumeRole","sts:TagSession"],"Condition":{
	  "StringLike":{"sts:SourceIdentity":"*","aws:RequestTag/operator":"*"}
	}}}`
	rc, err := CheckTrustPolicy(roleARN, policy)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if gaps := rc.Gaps(); len(gaps) != 0 {
		t.Errorf("Gaps() = %v, want none for the full convention", gaps)
	}
	if len(rc.RequiredTagKeys) != 1 || rc.RequiredTagKeys[0] != "operator" {
		t.Errorf("RequiredTagKeys = %v", rc.RequiredTagKeys)
	}
}

func TestCheckTrustPolicy_NullConditions(t *testing.T) {
	t.Parallel()
	nullRequired := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Condition":{"Null":{"sts:SourceIdentity":"false"}}}}`
	rc, err := CheckTrustPolicy(roleARN, nullRequired)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !rc.RequiresSourceIdentity {
		t.Error("Null:false must read as required-present")
	}

	nullForbidden := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Condition":{"Null":{"sts:SourceIdentity":true}}}}`
	rc, err = CheckTrustPolicy(roleARN, nullForbidden)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !rc.ForbidsSourceIdentity || rc.RequiresSourceIdentity {
		t.Errorf("Null:true must read as forbidden, got %+v", rc)
	}
	if gaps := rc.Gaps(); len(gaps) == 0 || !strings.Contains(gaps[0], "FORBIDS") {
		t.Errorf("Gaps() = %v, want the forbidden gap first", gaps)
	}
}

func TestCheckTrustPolicy_ShapeTolerance(t *testing.T) {
	t.Parallel()
	// Single statement object, single action string, wildcard action.
	policy := `{"Statement":{"Effect":"Allow","Action":"sts:*","Condition":{"StringEquals":{"sts:SourceIdentity":["alice","bob"]}}}}`
	rc, err := CheckTrustPolicy(roleARN, policy)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !rc.RequiresSourceIdentity || !rc.AllowsTagSession {
		t.Errorf("wildcard sts:* with list condition: %+v", rc)
	}
}

func TestCheckTrustPolicy_DenyStatementsIgnored(t *testing.T) {
	t.Parallel()
	policy := `{"Statement":[{"Effect":"Deny","Action":"sts:AssumeRole","Condition":{"StringLike":{"sts:SourceIdentity":"*"}}}]}`
	rc, err := CheckTrustPolicy(roleARN, policy)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if rc.RequiresSourceIdentity {
		t.Error("a Deny statement's condition must not read as a requirement")
	}
}

func TestCheckTrustPolicy_MalformedJSON(t *testing.T) {
	t.Parallel()
	if _, err := CheckTrustPolicy(roleARN, `{"Statement": [`); err == nil {
		t.Fatal("expected error for malformed policy")
	}
}

func TestCheckTrustPolicy_StringNotEqualsIsNotARequirement(t *testing.T) {
	t.Parallel()
	policy := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Condition":{"StringNotEquals":{"sts:SourceIdentity":"banned"}}}}`
	rc, err := CheckTrustPolicy(roleARN, policy)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if rc.RequiresSourceIdentity {
		t.Error("StringNotEquals excludes values; it does not force presence")
	}
}
