#!/usr/bin/env bash
# Regenerate the CycloneDX SBOM from the shipped binary's build graph, enriched
# with the (uniform, verified) Apache-2.0 license for the AWS SDK / smithy-go
# tree. Requires cyclonedx-gomod:
#   go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=docs/security/sbom.cdx.json
GOBIN="$(go env GOPATH)/bin"

"$GOBIN/cyclonedx-gomod" app -json -licenses -main cmd/crossbearing -output "$OUT" .

# cyclonedx-gomod doesn't resolve module licenses from the cache; the whole tree
# is AWS SDK for Go v2 + smithy-go, both Apache-2.0. Enrich, and fail loudly if a
# non-AWS component ever appears (the lean-tree invariant).
python3 - "$OUT" <<'PY'
import json, sys
p = sys.argv[1]
s = json.load(open(p))
bad = [c["purl"] for c in s.get("components", [])
       if not (c["purl"].startswith("pkg:golang/github.com/aws/aws-sdk-go-v2")
               or c["purl"].startswith("pkg:golang/github.com/aws/smithy-go"))]
if bad:
    sys.exit("SBOM: non-AWS/smithy component(s) present — review license before enriching:\n  " + "\n  ".join(bad))
for c in s.get("components", []):
    c["licenses"] = [{"license": {"id": "Apache-2.0"}}]
mc = s.get("metadata", {}).get("component")
if mc:
    mc["licenses"] = [{"license": {"name": "FSL-1.1-ALv2"}}]
json.dump(s, open(p, "w"), indent=2)
open(p, "a").write("\n")
print(f"SBOM: {len(s['components'])} components, all Apache-2.0 → {p}")
PY
