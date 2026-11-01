#!/usr/bin/env bash
set -euo pipefail

registry="ghcr.io"
image_name="coilyco/node-stats-mcp"

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "GITHUB_TOKEN is required for the trusted image-publish lane." >&2
  exit 1
fi

sha="${GITHUB_SHA:-$(git rev-parse HEAD)}"
case "${sha}" in
  *[!0-9a-f]*|"")
    echo "node-stats-mcp source sha is not a lowercase hexadecimal commit id." >&2
    exit 1
    ;;
esac
if [ "${#sha}" -ne 40 ]; then
  echo "node-stats-mcp source sha must be a full 40-character commit id." >&2
  exit 1
fi

image="${registry}/${image_name}:${sha}"
docker_config="$(mktemp -d)"
trap 'rm -rf "${docker_config}"' EXIT
chmod 700 "${docker_config}"
export DOCKER_CONFIG="${docker_config}"

printf '%s' "${GITHUB_TOKEN}" \
  | docker login "${registry}" --username "${GITHUB_ACTOR:-coilyco-ops}" --password-stdin

echo "==> building ${image}"
docker build --pull \
  --label "org.opencontainers.image.source=https://github.com/coilyco/node-stats-mcp" \
  -t "${image}" .

echo "==> smoke-testing ${image}"
docker run --rm --entrypoint python "${image}" -c "import node_stats_mcp.server"

echo "==> publishing ${image}"
docker push "${image}"

docker manifest inspect "${image}" >/dev/null
echo "verified immutable manifest ${image}"
