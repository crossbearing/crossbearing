package github

import (
	"strings"
	"testing"
)

// FuzzIngest holds the whole untrusted parse path panic-free: audit-log
// files are attacker-influenceable, and Ingest runs the JSON reader,
// per-entry unmarshal, record mapping, and session windowing over them.
func FuzzIngest(f *testing.F) {
	f.Add(`[{"_document_id":"d1","action":"repo.create","actor":"alice","@timestamp":1700000000000}]`)
	f.Add(`{"_document_id":"d1","action":"git.push","actor":"bot[bot]","repo":"o/r"}`)
	f.Add(`[`)
	f.Add("{}\n{}\nnot json")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, data string) {
		res, err := New(nil, Options{Org: "o", AppHumans: map[string]string{"bot[bot]": "h@x"}}).Ingest(strings.NewReader(data))
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
