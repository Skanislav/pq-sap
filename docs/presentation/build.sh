#!/usr/bin/env bash
# Build the EPF presentation from Markdown.
#
#   ./build.sh          render SUMMARY.md -> SUMMARY.html
#   ./build.sh watch    rebuild HTML on every save (refresh browser to see it)
#   ./build.sh pdf      render SUMMARY.md -> SUMMARY.pdf (embeds local images)
#
# Needs Node >= 20 for the Marp CLI; picks it up via nvm if the default is older.
set -euo pipefail
cd "$(dirname "$0")"

if ! node -e 'process.exit(+process.versions.node.split(".")[0] >= 20 ? 0 : 1)' 2>/dev/null; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck disable=SC1091
  source "$NVM_DIR/nvm.sh"
  nvm use 26 >/dev/null
fi

case "${1:-html}" in
  html)  npx -y @marp-team/marp-cli SUMMARY.md -o SUMMARY.html ;;
  watch) npx -y @marp-team/marp-cli --watch SUMMARY.md -o SUMMARY.html ;;
  pdf)   npx -y @marp-team/marp-cli SUMMARY.md -o SUMMARY.pdf --allow-local-files ;;
  *)     echo "usage: $0 [html|watch|pdf]" >&2; exit 2 ;;
esac
