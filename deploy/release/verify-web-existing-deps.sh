#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_directory=$(cd -- "${script_directory}/../.." && pwd -P)
web_directory=${source_directory}/web
node_binary=${NODE:-node}

for path in \
  "${web_directory}/pnpm-lock.yaml" \
  "${web_directory}/node_modules/.pnpm/lock.yaml" \
  "${web_directory}/node_modules/.bin/tsc" \
  "${web_directory}/node_modules/.bin/eslint" \
  "${web_directory}/node_modules/.bin/vinext"; do
  if [[ ! -f "$path" ]]; then
    printf 'Lock-matched dashboard dependency is missing: %s\n' "$path" >&2
    exit 2
  fi
done
if ! command -v "$node_binary" >/dev/null 2>&1; then
  printf 'Node.js is unavailable: %s\n' "$node_binary" >&2
  exit 2
fi
if ! cmp -s "${web_directory}/pnpm-lock.yaml" "${web_directory}/node_modules/.pnpm/lock.yaml"; then
  echo 'Installed dashboard dependencies do not exactly match pnpm-lock.yaml.' >&2
  exit 1
fi

export PATH="$(dirname -- "$(command -v "$node_binary")"):${web_directory}/node_modules/.bin:${PATH}"
cd -- "$web_directory"
tsc -p tsconfig.typecheck.json --noEmit
eslint . --ignore-pattern dist --ignore-pattern .next
vinext build
"$node_binary" scripts/complete-standalone.mjs
echo 'web_existing_dependencies_verification=pass'
