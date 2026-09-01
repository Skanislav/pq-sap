#!/usr/bin/env bash
# Build the Yul-only contracts (forge cannot parse .yul under src/): yul/FrameTxContext.yul
# -> out/FrameTxContext.yul/FrameTxContext.json, forge-artifact shaped
# ({ bytecode: { object } }) so deploy scripts read it like any other artifact.
#
# Needs the same solc forge uses (foundry.toml solc_version) on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=yul/FrameTxContext.yul
OUT=out/FrameTxContext.yul
mkdir -p "$OUT"

BIN=$(solc --strict-assembly --optimize --evm-version prague --bin "$SRC" \
  | awk '/Binary representation/{getline; print; exit}')
[ -n "$BIN" ] || { echo "build-yul: no bytecode produced" >&2; exit 1; }

node -e '
const [bin, out, src] = process.argv.slice(1)
require("fs").writeFileSync(out, JSON.stringify({
  contractName: "FrameTxContext", sourcePath: src,
  bytecode: { object: "0x" + bin },
}, null, 2) + "\n")
' "$BIN" "$OUT/FrameTxContext.json" "$SRC"
echo "built $OUT/FrameTxContext.json ($(( ${#BIN} / 2 )) bytes)"
