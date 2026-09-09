#!/usr/bin/env bash
# Autoresearch harness: SPHINCS- (C13) docs correctness + IPFS deployability.
#
# Workload (deterministic, offline):
#   1. Rebuild the static UI bundle (ui/dist) with relative base — the artifact
#      that gets pinned to IPFS.
#   2. Run the IPFS publisher in --dry-run: lists the files that would be
#      uploaded, no network, no JWT.
#   3. Run js-client/scripts/check-sphincs-docs.ts: verifies every SPHINCS- C13
#      claim in the docs against the code, the compiled contracts, the
#      vendored verifier and the deterministic fixture, including an
#      independent keccak WOTS+C/FORS+C verification of the fixture signatures
#      (positive and negative).
#
# Primary metric: sphincs_docs_passed = number of passing gates (all must pass).
# Secondary:    sphincs_docs_failed, ui_dist_total_bytes.

set -uo pipefail
cd "$(dirname "$0")"

if ! command -v bun >/dev/null 2>&1; then
  echo "autoresearch.sh: bun not on PATH (this workstation runs the JS workloads under bun)" >&2
  exit 2
fi

# 1. Static bundle: byte-identical given identical sources (Vite build).
( cd ui && bun run --silent node_modules/vite/bin/vite.js build ) || {
  echo "vite build failed"; exit 1; }

DIST_BYTES=$(find ui/dist -type f -exec stat -c %s {} + | awk '{s+=$1} END {print s}')

# 2. IPFS dry-run: prove the pinning path resolves the bundle with no network.
if ! ( cd ui && PINATA_JWT= bun run --silent scripts/deploy-ipfs.mjs --dry-run >/dev/null ); then
  echo "deploy-ipfs --dry-run failed"; exit 1; fi

# 3. SPHINCS-/docs conformance gates.
OUT=$(bun js-client/scripts/check-sphincs-docs.ts) && STATUS=0 || STATUS=$?
echo "$OUT"
[ $STATUS -eq 0 ] || exit "$STATUS"

PASSED=$(echo "$OUT" | grep -c '^PASS ')
FAILED=$(echo "$OUT" | grep -c '^FAIL ')

echo "METRIC sphincs_docs_passed=$PASSED"
echo "METRIC sphincs_docs_failed=$FAILED"
echo "METRIC ui_dist_total_bytes=$DIST_BYTES"
