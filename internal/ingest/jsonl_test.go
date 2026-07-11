package ingest

import (
	"strings"
	"testing"
)

func TestSplitJSONArrayOrLines(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		wantRaws  int
		wantBad   int
		wantError bool
	}{
		{"empty", "", 0, 0, false},
		{"whitespace only", "  \n\t ", 0, 0, false},
		{"json array", `[{"a":1},{"b":2}]`, 2, 0, false},
		{"array with leading whitespace", "\n  [{\"a\":1}]", 1, 0, false},
		{"jsonl", "{\"a\":1}\n{\"b\":2}\n", 2, 0, false},
		{"jsonl no trailing newline", "{\"a\":1}\n{\"b\":2}", 2, 0, false},
		{"jsonl with a bad line", "{\"a\":1}\nnot json\n{\"b\":2}\n", 2, 1, false},
		{"jsonl blank lines skipped", "{\"a\":1}\n\n\n{\"b\":2}\n", 2, 0, false},
		{"malformed array errors", `[{"a":1},`, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raws, bad, err := SplitJSONArrayOrLines(strings.NewReader(tt.input))
			if (err != nil) != tt.wantError {
				t.Fatalf("err = %v, wantError %v", err, tt.wantError)
			}
			if err != nil {
				return
			}
			if len(raws) != tt.wantRaws {
				t.Errorf("raws = %d, want %d", len(raws), tt.wantRaws)
			}
			if bad != tt.wantBad {
				t.Errorf("bad = %d, want %d", bad, tt.wantBad)
			}
		})
	}
}

// FuzzSplitJSONArrayOrLines holds the shared reader panic-free over
// arbitrary bytes: audit-log files are untrusted input, and the reader
// is the first thing every file-based ingester runs on them.
func FuzzSplitJSONArrayOrLines(f *testing.F) {
	f.Add(`[{"a":1}]`)
	f.Add("{\"a\":1}\n{\"b\":2}")
	f.Add(`[`)
	f.Add("\x00\x00")
	f.Add(strings.Repeat("[", 100))
	f.Fuzz(func(t *testing.T, data string) {
		raws, bad, err := SplitJSONArrayOrLines(strings.NewReader(data))
		if err != nil {
			return
		}
		if bad < 0 {
			t.Fatalf("negative bad count %d", bad)
		}
		_ = raws // must not panic; shape is the ingesters' concern
	})
}
