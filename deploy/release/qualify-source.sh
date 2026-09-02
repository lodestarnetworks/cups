#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_directory=$(cd -- "${script_directory}/../.." && pwd -P)
go_binary=${GO:-go}
pnpm_binary=${PNPM:-pnpm}
release_version=${1:-${RELEASE_VERSION:-}}

if [[ -z "$release_version" ]]; then
  echo 'Usage: qualify-source.sh RELEASE_VERSION' >&2
  exit 2
fi
cd -- "$source_directory"

"${script_directory}/verify-public-tree.sh"

"$go_binary" vet ./...
"$go_binary" test -count=1 ./...
"$go_binary" test -race -count=1 ./...
"$go_binary" run ./cmd/sgw-c --config configs/sgw-c.lab.yaml --check-config
"$go_binary" run ./cmd/sgw-u --config configs/sgw-u.lab.yaml --check-config
"$go_binary" run ./cmd/pgw-c --config configs/pgw-c.lab.yaml --check-config
"$go_binary" run ./cmd/pgw-u --config configs/pgw-u.lab.yaml --check-config
"$go_binary" run ./cmd/sgw-c --config deploy/benchmark/sgw-c.vps-netns.yaml --check-config
"$go_binary" run ./cmd/sgw-u --config deploy/benchmark/sgw-u.vps-netns.yaml --check-config
"$go_binary" run ./cmd/sgw-u --config deploy/benchmark/sgw-u.tcx-smoke.yaml --check-config
"$go_binary" run ./cmd/lodestar-alert-check --rules deploy/prometheus/lodestar-cups-alerts.yaml
PROMTOOL=${PROMTOOL:-promtool} deploy/prometheus/test-alert-rules.sh

if command -v "$pnpm_binary" >/dev/null 2>&1; then
	(
		cd web
		"$pnpm_binary" typecheck
		"$pnpm_binary" lint
		"$pnpm_binary" build
	)
elif [[ -f web/node_modules/.pnpm/lock.yaml ]]; then
  NODE=${NODE:-node} "${script_directory}/verify-web-existing-deps.sh"
else
  echo 'PNPM is unavailable and no exact lock-matched installed dashboard dependency tree exists.' >&2
  exit 1
fi

while IFS= read -r -d '' script; do
  bash -n "$script"
done < <(find deploy -type f -name '*.sh' -print0)

"${script_directory}/build-release.sh" "$release_version"
echo 'source_qualification=pass'
