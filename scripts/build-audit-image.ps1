$ErrorActionPreference = "Stop"

docker build `
  -t glassbox-audit:latest `
  -f docker/audit-image.Dockerfile `
  .
