package gcp

import (
	"strings"
	"testing"
)

func FuzzIngest(f *testing.F) {
	f.Add(`[{"insertId":"i1","timestamp":"2026-06-10T03:00:00Z","protoPayload":{"methodName":"storage.objects.create","authenticationInfo":{"principalEmail":"sa@p.iam.gserviceaccount.com","serviceAccountDelegationInfo":[{"firstPartyPrincipal":{"principalEmail":"h@x"}}]}}}]`)
	f.Add(`{"insertId":"i1","protoPayload":{"methodName":"x","authenticationInfo":{"principalEmail":"h@x"}}}`)
	f.Add(`[`)
	f.Add("not json")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, data string) {
		res, err := New(nil, Options{Project: "p"}).Ingest(strings.NewReader(data))
		if err != nil {
			return
		}
		for _, r := range res.Records {
			if r.ID == "" || r.Operation == "" || r.Principal == "" {
				t.Fatalf("emitted a record with empty identity: %+v", r)
			}
		}
	})
}
