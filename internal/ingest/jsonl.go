// Package ingest holds the helpers that are byte-identical across the
// record-stream ingesters under internal/ingest/*. It deliberately holds
// only what is genuinely the same for every stream; per-stream logic —
// identity conventions, session windowing, the event schemas — stays in
// each ingester, because that is where the streams actually differ.
package ingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// SplitJSONArrayOrLines reads audit entries in either shape a log export
// ships in: a single JSON array (the `gcloud … --format=json` /
// `az … -o json` / GitHub-API shape) or newline-delimited JSON (the
// streaming-sink shape). It returns each entry's exact raw bytes — what a
// provenance digest must cover — plus a count of non-empty lines that
// were not valid JSON (skipped, not fatal: a corrupt line shouldn't lose
// the rest of the log). Malformed array JSON does error, since there is
// no entry boundary to resync on.
func SplitJSONArrayOrLines(r io.Reader) (raws []json.RawMessage, bad int, err error) {
	br := bufio.NewReader(r)
	lead, err := br.Peek(1)
	for err == nil && len(lead) == 1 && (lead[0] == ' ' || lead[0] == '\n' || lead[0] == '\t' || lead[0] == '\r') {
		_, _ = br.ReadByte()
		lead, err = br.Peek(1)
	}
	if err == io.EOF {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read audit log: %w", err)
	}

	if lead[0] == '[' {
		if err := json.NewDecoder(br).Decode(&raws); err != nil {
			return nil, 0, fmt.Errorf("failed to parse audit array: %w", err)
		}
		return raws, 0, nil
	}

	for {
		line, err := br.ReadBytes('\n')
		atEOF := err == io.EOF
		if err != nil && !atEOF {
			return nil, bad, fmt.Errorf("failed to read audit line: %w", err)
		}
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			if json.Valid(line) {
				raws = append(raws, json.RawMessage(line))
			} else {
				bad++
			}
		}
		if atEOF {
			return raws, bad, nil
		}
	}
}
