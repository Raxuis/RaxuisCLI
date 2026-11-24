#!/bin/sh
# Local protocol fixtures only; no credentials, containers or privileged ports.
set -eu
lab_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$lab_root"
exec go test -race -count=1 -timeout=2m \
  ./internal/web/http \
  ./internal/shared/httpclient \
  ./internal/network/dns \
  ./internal/audit/dns \
  ./internal/crypto/tlsscan \
  ./internal/tools/ports \
  ./internal/network/scan \
  ./internal/network/recon \
  ./internal/container/k8s \
  ./internal/redteam/ldap \
  ./internal/redteam/smb
