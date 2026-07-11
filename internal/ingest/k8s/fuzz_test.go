package k8s

import (
	"strings"
	"testing"
)

func FuzzIngest(f *testing.F) {
	f.Add(`{"kind":"Event","auditID":"a1","stage":"ResponseComplete","verb":"create","user":{"username":"system:serviceaccount:agents:x"},"impersonatedUser":{"username":"h@x"},"objectRef":{"resource":"deployments","namespace":"prod","name":"api"},"responseStatus":{"code":201},"stageTimestamp":"2026-06-10T03:00:00Z"}`)
	f.Add(`{"kind":"EventList","items":[{"auditID":"a1","stage":"ResponseComplete","verb":"get","user":{"username":"u"}}]}`)
	f.Add("not json")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, data string) {
		res, err := New(nil, Options{Cluster: "c"}).Ingest(strings.NewReader(data))
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
