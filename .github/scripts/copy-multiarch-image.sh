#!/usr/bin/env bash
#
# Copies already-published image tags from one registry to another without
# rebuilding.
#
# Each tag is copied with `imagetools create`, which re-points the destination
# tag at the source's existing manifests, so child digests are preserved and
# the copy is identical to what the original build published. This matters for
# the nitro images: a rebuild is not guaranteed bit-identical and would not
# match the PCR measurements already published for the tag.
#
# Arch-suffixed tags are copied alongside the manifest list, matching the tag
# layout that push-multiarch-image.sh produces.
#
# Environment:
#   SOURCE_REGISTRY  registry hostname holding the images
#   TARGET_REGISTRY  registry hostname to copy into
#   REPOSITORY       repository path, shared by both (e.g. containers/enclave)
#   TAGS             whitespace-separated tags to copy
#   ARCHES           space-separated architectures (default: "amd64 arm64")

set -euo pipefail

SOURCE_REGISTRY="${SOURCE_REGISTRY:?SOURCE_REGISTRY is required}"
TARGET_REGISTRY="${TARGET_REGISTRY:?TARGET_REGISTRY is required}"
REPOSITORY="${REPOSITORY:?REPOSITORY is required}"
TAGS="${TAGS:?TAGS is required}"
ARCHES="${ARCHES:-amd64 arm64}"

if [ "$SOURCE_REGISTRY" = "$TARGET_REGISTRY" ]; then
  echo "==> Source and target registry are both $SOURCE_REGISTRY, nothing to do"
  exit 0
fi

copied=0
missing=()
for tag in $TAGS; do
  # A missing arch tag is normal; a missing plain tag means the caller asked for
  # something the source does not have, usually a typo.
  if ! docker buildx imagetools inspect "${SOURCE_REGISTRY}/${REPOSITORY}:${tag}" >/dev/null 2>&1; then
    echo "==> Skipping $tag, not present in $SOURCE_REGISTRY"
    missing+=("$tag")
    continue
  fi

  # Arch tags first so the manifest list's children are already present.
  refs=()
  for arch in $ARCHES; do
    refs+=("${tag}-${arch}")
  done
  refs+=("$tag")

  for ref in "${refs[@]}"; do
    src="${SOURCE_REGISTRY}/${REPOSITORY}:${ref}"
    dst="${TARGET_REGISTRY}/${REPOSITORY}:${ref}"

    if ! docker buildx imagetools inspect "$src" >/dev/null 2>&1; then
      echo "==> Skipping $ref, not present in $SOURCE_REGISTRY"
      continue
    fi

    echo "==> Copying $src -> $dst"
    docker buildx imagetools create --tag "$dst" "$src"
    copied=$((copied + 1))
  done
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "::error::Not found in $SOURCE_REGISTRY: ${missing[*]}"
  exit 1
fi

echo "==> Copied $copied tag(s) to $TARGET_REGISTRY"
