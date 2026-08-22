#!/usr/bin/env bash
# End-to-end (v,r,s)-as-pointers demo on a local anvil node.
# Usage: cd ETHDILITHIUM && script/demo_anvil.sh
set -euo pipefail
cd "$(dirname "$0")/.."

RPC=http://127.0.0.1:8545
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil #0
export RECIPIENT=0x000000000000000000000000000000000000bEEF

[ -x pythonref/myenv/bin/python ] || { echo "missing pythonref/myenv (see docs/pointer-signatures-poc.md)"; exit 1; }

anvil --silent --gas-limit 60000000 --code-size-limit 100000 &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null' EXIT
for _ in $(seq 1 50); do cast chain-id --rpc-url $RPC >/dev/null 2>&1 && break; sleep 0.2; done

forge script script/PointerSigDemo.s.sol --rpc-url $RPC --broadcast --ffi --slow -vv \
  | grep -E "verifier|registry|vault|pqOwner|keyIdx|sigIdx|recipient|Paid|gas" | sed 's/^ *//'

RUN=broadcast/PointerSigDemo.s.sol/31337/run-latest.json
REGISTRY=$(jq -r '.transactions[] | select(.transactionType=="CREATE" and .contractName=="PointerSigRegistry") | .contractAddress' $RUN)
VAULT=$(jq -r '.transactions[] | select(.transactionType=="CREATE" and .contractName=="PointerSigVault") | .contractAddress' $RUN)

echo
echo "== on-chain state (cast) =="
echo "keyCount        : $(cast call $REGISTRY 'keyCount()(uint256)' --rpc-url $RPC)"
echo "signatureCount  : $(cast call $REGISTRY 'signatureCount()(uint256)' --rpc-url $RPC)"
echo "recipient.balance: $(cast balance $RECIPIENT --rpc-url $RPC --ether) ETH  (expect 0.35)"
echo
echo "== per-tx gas =="
paste <(jq -r '.transactions[] | "\(.contractName).\(.function // "constructor")"' $RUN) \
      <(jq -r '.receipts[].gasUsed' $RUN | while read g; do cast to-dec $g; done) | column -t
