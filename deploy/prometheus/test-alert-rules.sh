#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
promtool_binary=${PROMTOOL:-promtool}

if ! command -v "$promtool_binary" >/dev/null 2>&1; then
  printf 'Prometheus promtool is required to validate alert semantics: %s\n' "$promtool_binary" >&2
  exit 2
fi

"$promtool_binary" check rules "${script_directory}/lodestar-cups-alerts.yaml"
"$promtool_binary" test rules "${script_directory}/lodestar-cups-alerts.test.yaml"
echo 'prometheus_alert_tests=pass'
