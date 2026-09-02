#!/usr/bin/env bash
set -euo pipefail

umask 022
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source_directory=$(cd -- "${script_directory}/../.." && pwd -P)
release_version=${1:-${RELEASE_VERSION:-}}
output_directory=${OUTPUT_DIRECTORY:-${source_directory}/dist/releases}
go_binary=${GO:-go}
source_date_epoch=${SOURCE_DATE_EPOCH:-0}
require_signature=${REQUIRE_SIGNATURE:-0}
signing_key=${SIGNING_KEY:-}

if ! [[ "$release_version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  echo 'Release version must be 1..64 alphanumeric, dot, underscore, or hyphen characters.' >&2
  exit 2
fi
if ! [[ "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo 'SOURCE_DATE_EPOCH must be a non-negative Unix timestamp.' >&2
  exit 2
fi
if [[ "$require_signature" != 0 && "$require_signature" != 1 ]]; then
  echo 'REQUIRE_SIGNATURE must be 0 or 1.' >&2
  exit 2
fi
for command_name in "$go_binary" awk cp find install jq mktemp mv openssl rm sha256sum sort stat tar xargs; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required release command is missing: %s\n' "$command_name" >&2
    exit 2
  fi
done

install -d -m 0755 "$output_directory"
work_directory=$(mktemp -d "${output_directory}/.lodestar-release.XXXXXX")
cleanup() {
  if [[ -d "$work_directory" && "$work_directory" == "${output_directory}/.lodestar-release."* ]]; then
    rm -r -- "$work_directory"
  fi
}
trap cleanup EXIT INT TERM

first_build=${work_directory}/build-a
second_build=${work_directory}/build-b
release_name=lodestar-cups-${release_version}-linux-amd64
release_directory=${work_directory}/${release_name}
install -d -m 0755 "$first_build" "$second_build" "$release_directory/bin"

ldflags="-s -w -buildid= -X main.version=${release_version}"
components=(sgw-c sgw-u pgw-c pgw-u)
build_component() {
  local destination=$1
  local component=$2
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_binary" build \
    -buildvcs=false -trimpath -ldflags "$ldflags" \
    -o "${destination}/${component}" "./cmd/${component}"
}

cd -- "$source_directory"
for component in "${components[@]}"; do
  build_component "$first_build" "$component"
  build_component "$second_build" "$component"
  first_digest=$(sha256sum "${first_build}/${component}" | awk '{print $1}')
  second_digest=$(sha256sum "${second_build}/${component}" | awk '{print $1}')
  if [[ "$first_digest" != "$second_digest" ]]; then
    printf 'Reproducible-build gate failed for %s: %s != %s\n' "$component" "$first_digest" "$second_digest" >&2
    exit 1
  fi
  install -m 0755 "${first_build}/${component}" "${release_directory}/bin/${component}"
done

for path in LICENSE README.md SECURITY.md go.mod go.sum; do
  install -m 0644 "$path" "${release_directory}/${path}"
done
install -d -m 0755 "${release_directory}/configs" "${release_directory}/deploy" "${release_directory}/docs"
# Release artifacts contain reusable examples only. Operator overlays are kept
# in ignored subdirectories and must never be copied into a distributable.
find configs -maxdepth 1 -type f -exec cp -a -- {} "${release_directory}/configs/" \;
cp -a deploy/systemd deploy/sysctl deploy/prometheus "${release_directory}/deploy/"
# Ship reusable operator and architecture documentation. Dated site
# qualification reports remain source evidence and are not release payloads.
find docs -maxdepth 1 -type f ! -name '20??-??-??-*' -exec cp -a -- {} "${release_directory}/docs/" \;
find "${release_directory}" -type d -exec chmod 0755 {} +
find "${release_directory}" -type f ! -path '*/bin/*' -exec chmod 0644 {} +

source_digest=$(
  {
    printf '%s\0' go.mod go.sum LICENSE README.md SECURITY.md
    find cmd internal pkg -type f ! -path 'internal/config/*_live_deployment_test.go' -print0
    find configs -maxdepth 1 -type f -print0
    find deploy/benchmark deploy/prometheus deploy/release deploy/sysctl deploy/systemd -type f -print0
    find docs web/app web/public -type f -print0
  } | sort -z | xargs -0 sha256sum -z | sha256sum | awk '{print $1}'
)
go_mod_digest=$(sha256sum go.mod | awk '{print $1}')
go_sum_digest=$(sha256sum go.sum | awk '{print $1}')
printf '%s\n' "$source_digest" >"${release_directory}/SOURCE_SHA256"

"$go_binary" run ./cmd/lodestar-sbom \
  --name lodestar-cups --version "$release_version" \
  --output "${release_directory}/SBOM.cdx.json" \
  "${release_directory}/bin/pgw-c" "${release_directory}/bin/pgw-u" \
  "${release_directory}/bin/sgw-c" "${release_directory}/bin/sgw-u"

go_version=$($go_binary version)
jq -n --sort-keys \
  --arg name lodestar-cups \
  --arg version "$release_version" \
  --arg sourceSha256 "$source_digest" \
  --arg goModSha256 "$go_mod_digest" \
  --arg goSumSha256 "$go_sum_digest" \
  --arg goVersion "$go_version" \
  --argjson sourceDateEpoch "$source_date_epoch" \
  '{schema: 1, name: $name, version: $version, sourceSha256: $sourceSha256,
    dependencyManifests: {goModSha256: $goModSha256, goSumSha256: $goSumSha256},
    sourceDateEpoch: $sourceDateEpoch, builder: $goVersion,
    target: {os: "linux", architecture: "amd64", cgo: false},
    buildFlags: ["-buildvcs=false", "-trimpath", "-ldflags=-s -w -buildid="]}' \
  >"${release_directory}/BUILD-PROVENANCE.json"

(
  cd -- "$release_directory"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)

final_directory=${output_directory}/${release_name}
archive=${output_directory}/${release_name}.tar.gz
temporary_archive=${work_directory}/${release_name}.tar.gz
if [[ -e "$final_directory" || -e "$archive" || -e "${archive}.sha256" || -e "${archive}.sig" || -e "${archive}.UNSIGNED" ]]; then
  printf 'Refusing to overwrite an existing release: %s\n' "$release_name" >&2
  exit 2
fi
tar --sort=name --mtime="@${source_date_epoch}" --owner=0 --group=0 --numeric-owner \
  -C "$work_directory" -czf "$temporary_archive" "$release_name"
archive_digest=$(sha256sum "$temporary_archive" | awk '{print $1}')
printf '%s  %s\n' "$archive_digest" "${release_name}.tar.gz" >"${temporary_archive}.sha256"

if [[ -n "$signing_key" ]]; then
  if [[ ! -f "$signing_key" || -L "$signing_key" ]]; then
    echo 'SIGNING_KEY must name a regular non-symlink file.' >&2
    exit 2
  fi
  key_mode=$(stat -c '%a' "$signing_key")
  if ! [[ "$key_mode" =~ ^[46]00$ ]]; then
    echo 'SIGNING_KEY must have mode 0400 or 0600.' >&2
    exit 2
  fi
  openssl pkeyutl -sign -rawin -inkey "$signing_key" -in "$temporary_archive" -out "${temporary_archive}.sig"
elif [[ "$require_signature" == 1 ]]; then
  echo 'Release signing is required but SIGNING_KEY is not configured.' >&2
  exit 1
else
  printf '%s\n' 'UNSIGNED RELEASE CANDIDATE — not approved for production publication' >"${temporary_archive}.UNSIGNED"
fi

mv "$release_directory" "$final_directory"
mv "$temporary_archive" "$archive"
mv "${temporary_archive}.sha256" "${archive}.sha256"
if [[ -f "${temporary_archive}.sig" ]]; then
  mv "${temporary_archive}.sig" "${archive}.sig"
fi
if [[ -f "${temporary_archive}.UNSIGNED" ]]; then
  mv "${temporary_archive}.UNSIGNED" "${archive}.UNSIGNED"
fi

printf 'release_directory=%s\n' "$final_directory"
printf 'release_archive=%s\n' "$archive"
printf 'source_sha256=%s\n' "$source_digest"
printf 'reproducible_build=yes\n'
if [[ -f "${archive}.sig" ]]; then
  printf 'signature=%s\n' "${archive}.sig"
else
  printf 'signature=missing\n'
fi
