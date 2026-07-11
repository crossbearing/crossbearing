#!/usr/bin/env bash
# crossbearing demo — the fab / Bedrock dress rehearsal, fully offline.
#
# A synthetic but realistic run of agents on the nanohype/fab substrate:
# Claude agents on Bedrock, doing infra work through the Bash tool (kubectl,
# aws) and the GitHub MCP server. The claim side is a Bedrock model-invocation
# log; the record side is K8s audit, CloudTrail, and GitHub audit. This is the
# exact pipeline the live EKS run will use — only the fixtures get swapped for
# real exports.
#
# Add --format html for the print-to-PDF Agent Attribution Audit:
#   ./demo/fab/run.sh --format html > audit.html
set -euo pipefail
cd "$(dirname "$0")/../.."

go run ./cmd/crossbearing report \
  --bedrock-audit    demo/fab/bedrock-invocations.jsonl \
  --k8s-audit        demo/fab/k8s-audit.jsonl   --k8s-cluster prod-eks \
  --aws-cloudtrail   demo/fab/aws-cloudtrail.json \
  --github-audit     demo/fab/github-audit.jsonl --github-org acme \
  --production-match prod \
  "$@"
