#!/usr/bin/env bash
set -euo pipefail

docker build \
  -t glassbox-audit:latest \
  -f docker/audit-image.Dockerfile \
  .
