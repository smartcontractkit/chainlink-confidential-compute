#!/usr/bin/env bash
#
# Pushes a set of per-architecture image tarballs to a registry and assembles a
# multi-arch manifest list for each requested tag.
#
# For every tag in TAGS this pushes one arch-suffixed image per architecture
# (e.g. host-sha-abc123-amd64, host-sha-abc123-arm64) and then creates the
# plain tag (host-sha-abc123) as a manifest list pointing at both, so consumers
# can pull a single tag and get the right architecture.
#
# Environment:
#   LOCAL_IMAGE   repo:tag of the image inside each tarball (e.g. enclave-host:latest)
#   TARBALL_FMT   path to each tarball, with the literal token {arch} as a placeholder
#   TAGS          newline-separated list of fully-qualified target tags
#   ARCHES        space-separated architectures (default: "amd64 arm64")

set -euo pipefail

LOCAL_IMAGE="${LOCAL_IMAGE:?LOCAL_IMAGE is required}"
TARBALL_FMT="${TARBALL_FMT:?TARBALL_FMT is required}"
TAGS="${TAGS:?TAGS is required}"
ARCHES="${ARCHES:-amd64 arm64}"

for arch in $ARCHES; do
  tarball="${TARBALL_FMT//\{arch\}/$arch}"

  echo "==> Loading $tarball"
  docker load --input "$tarball"

  # Guard against a stale LOCAL_IMAGE tag being pushed under the wrong arch
  # suffix, which would produce a manifest list that lies about its contents.
  actual=$(docker image inspect --format '{{.Architecture}}' "$LOCAL_IMAGE")
  if [ "$actual" != "$arch" ]; then
    echo "::error::$tarball contains a $actual image but was expected to be $arch"
    exit 1
  fi

  while read -r tag; do
    [ -n "$tag" ] || continue
    echo "==> Pushing ${tag}-${arch}"
    docker tag "$LOCAL_IMAGE" "${tag}-${arch}"
    docker push "${tag}-${arch}"
  done <<< "$TAGS"
done

while read -r tag; do
  [ -n "$tag" ] || continue
  sources=()
  for arch in $ARCHES; do
    sources+=("${tag}-${arch}")
  done
  echo "==> Creating manifest list $tag -> ${sources[*]}"
  docker buildx imagetools create --tag "$tag" "${sources[@]}"
done <<< "$TAGS"
