package corroborate

import (
	"crypto/sha256"
	"encoding/hex"
)

// DigestHex returns the lowercase hex SHA-256 of b — the canonical
// Provenance.Digest over a raw stream entry as ingested. Every ingester
// computes provenance the same way so a finding's input is re-fetchable
// and tamper-evident; centralizing the hash keeps that guarantee
// byte-identical across all record streams.
func DigestHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
