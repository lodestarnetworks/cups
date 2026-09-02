#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_directory=$(cd -- "${script_directory}/../.." && pwd -P)
cd -- "$source_directory"

if ! command -v git >/dev/null 2>&1; then
  echo 'git is required to verify the publishable source boundary' >&2
  exit 2
fi

file_list=$(mktemp)
cleanup() {
  if [[ -f "$file_list" ]]; then
    rm -- "$file_list"
  fi
}
trap cleanup EXIT INT TERM

git ls-files -z --cached --others --exclude-standard >"$file_list"

forbidden_path=0
while IFS= read -r -d '' path; do
  case "$path" in
    benchmarks/results/*|configs/*-canary/*|configs/*-live-canary/*|deploy/*-canary/*|deploy/*-live-canary/*|docs/benchmarks/*|docs/20??-??-??-*|internal/config/*_live_deployment_test.go)
      printf 'private deployment path entered the publishable tree: %s\n' "$path" >&2
      forbidden_path=1
      ;;
    *.pcap|*.pcapng|*.prof|*.test|*.tsbuildinfo|.env|.env.*)
      if [[ "$path" != *.env.example ]]; then
        printf 'generated or sensitive file entered the publishable tree: %s\n' "$path" >&2
        forbidden_path=1
      fi
      ;;
  esac
done <"$file_list"
if [[ "$forbidden_path" != 0 ]]; then
  exit 1
fi

if xargs -0 grep -IEl -- \
  'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}' \
  <"$file_list" >/dev/null 2>&1; then
  echo 'a private key or credential-shaped value exists in the publishable tree' >&2
  exit 1
fi

echo 'public_tree_boundary=pass'
