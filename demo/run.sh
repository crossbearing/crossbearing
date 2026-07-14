#!/usr/bin/env bash
# crossbearing demo — the divergence report, fully offline, in one command.
# No AWS/GCP/Azure credentials needed: the audit logs here are captured
# samples in the real schemas the engine validated against live.
set -euo pipefail
cd "$(dirname "$0")/.."

go run ./cmd/crossbearing report \
  --transcript        demo/transcript.jsonl \
  --aws-cloudtrail    demo/aws-cloudtrail.json \
  --k8s-audit         demo/k8s-audit.jsonl     --k8s-cluster prod-east \
  --github-audit      demo/github-audit.jsonl  --github-org  acme \
  --principal         deploy-bot,agent-deployer \
  --production-match  prod-
