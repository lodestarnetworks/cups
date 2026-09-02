#!/usr/bin/env bash
set -euo pipefail

release_directory=${1:-}
public_key=${VERIFY_PUBLIC_KEY:-}
archive=${VERIFY_ARCHIVE:-}
require_signature=${REQUIRE_SIGNATURE:-0}

if [[ -z "$release_directory" || ! -d "$release_directory" || -L "$release_directory" ]]; then
  echo 'Usage: verify-release.sh /absolute/path/to/extracted-release' >&2
  exit 2
fi
release_directory=$(cd -- "$release_directory" && pwd -P)
for command_name in jq sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Required verification command is missing: %s\n' "$command_name" >&2
    exit 2
  }
done

for component in sgw-c sgw-u pgw-c pgw-u; do
  binary=${release_directory}/bin/${component}
  if [[ ! -f "$binary" || -L "$binary" || ! -x "$binary" ]]; then
    printf 'Invalid release binary: %s\n' "$binary" >&2
    exit 1
  fi
  "$binary" --version >/dev/null
done
(
  cd -- "$release_directory"
  sha256sum -c SHA256SUMS
)
jq -e \
  '.bomFormat == "CycloneDX" and .specVersion == "1.6" and
   (.components | map(select(.type == "application")) | length) >= 4 and
   (.dependencies | length) > 4' \
  "${release_directory}/SBOM.cdx.json" >/dev/null
jq -e \
  '.schema == 1 and .target.os == "linux" and .target.architecture == "amd64" and
   .target.cgo == false and (.sourceSha256 | length) == 64 and
   (.dependencyManifests.goModSha256 | length) == 64 and
   (.dependencyManifests.goSumSha256 | length) == 64' \
  "${release_directory}/BUILD-PROVENANCE.json" >/dev/null
test "$(sha256sum "${release_directory}/go.mod" | awk '{print $1}')" = \
  "$(jq -r '.dependencyManifests.goModSha256' "${release_directory}/BUILD-PROVENANCE.json")"
test "$(sha256sum "${release_directory}/go.sum" | awk '{print $1}')" = \
  "$(jq -r '.dependencyManifests.goSumSha256' "${release_directory}/BUILD-PROVENANCE.json")"

if find "$release_directory" -type f -perm /002 -print -quit | grep -q .; then
  echo 'Release contains a world-writable file.' >&2
  exit 1
fi
if find "$release_directory" -type f \( -perm /4000 -o -perm /2000 \) -print -quit | grep -q .; then
  echo 'Release contains a setuid or setgid file.' >&2
  exit 1
fi
if find "$release_directory" -type l -print -quit | grep -q .; then
  echo 'Release contains a symbolic link.' >&2
  exit 1
fi

if [[ -n "$public_key" || "$require_signature" == 1 ]]; then
  if [[ -z "$public_key" || -z "$archive" || ! -f "${archive}.sig" ]]; then
    echo 'Signature verification requires VERIFY_PUBLIC_KEY, VERIFY_ARCHIVE, and the matching .sig file.' >&2
    exit 1
  fi
  openssl pkeyutl -verify -pubin -rawin -inkey "$public_key" -in "$archive" -sigfile "${archive}.sig"
fi
echo 'release_verification=pass'
