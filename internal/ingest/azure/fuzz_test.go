package azure

import (
	"strings"
	"testing"
)

func FuzzIngest(f *testing.F) {
	f.Add(`[{"eventDataId":"e1","eventTimestamp":"2026-06-10T03:00:00Z","operationName":{"value":"Microsoft.Compute/virtualMachines/write"},"caller":"11111111-2222-3333-4444-555555555555","status":{"value":"Succeeded"},"claims":{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn":"h@x"}}]`)
	f.Add(`{"eventDataId":"e1","operationName":{"value":"x"},"caller":"u@x"}`)
	f.Add(`[`)
	f.Add("not json")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, data string) {
		res, err := New(nil, Options{Subscription: "s"}).Ingest(strings.NewReader(data))
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
