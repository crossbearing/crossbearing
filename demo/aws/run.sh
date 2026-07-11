#!/usr/bin/env bash
# crossbearing AWS demo — the main bearing (CloudTrail), every finding case in
# one offline run. No AWS credentials, no real account, no secrets: the
# transcript and CloudTrail capture here are synthetic samples in the real
# schemas the engine validated against live.
#
# One agent session claims a few read-only AWS calls; CloudTrail tells the
# fuller story — a write where it claimed a read (mismatch), a production bucket
# it never mentioned, bound to no human (unattributed → agent-suspect), an
# access-key listing it didn't claim (unclaimed), and a describe it claimed but
# nothing recorded (unrecorded) — plus the calls that line up (corroborated).
set -euo pipefail
cd "$(dirname "$0")/../.."

go run ./cmd/crossbearing report \
  --transcript        demo/aws/transcript.jsonl \
  --aws-cloudtrail    demo/aws/aws-cloudtrail.json \
  --production-match  prod-
