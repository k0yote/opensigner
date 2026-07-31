#!/bin/sh
# Installs the d2 diagram compiler from a pinned release, verified by checksum.
# The single source of the pinned version and checksums; CI and the docs image
# both run this script. Fetching an install script and piping it to a shell
# would let whoever controls that endpoint run arbitrary code in the build, and
# would pick up a different compiler version on every deploy.
#
# POSIX sh, not bash: the docs image build runs it on Alpine.
set -eu

D2_VERSION="${D2_VERSION:-0.7.1}"
D2_SHA256_ARM64="ce3a0b985a8f91335a826c254b3a88736fd81afcdd08b58f6c749d2add6864b0"
D2_SHA256_AMD64="eb172adf59f38d1e5a70ab177591356754ffaf9bebb84e0ca8b767dfb421dad7"

if command -v d2 >/dev/null 2>&1 && d2 --version 2>/dev/null | grep -q "$D2_VERSION"; then
  echo "install-d2: d2 $D2_VERSION already present"
  exit 0
fi

# Only Linux tarballs are pinned here. On macOS, install d2 with
# `brew install d2` (or from https://d2lang.com) rather than letting this
# script fetch a Linux binary that passes its checksum and then cannot run.
if [ "$(uname -s)" != "Linux" ]; then
  echo "install-d2: this script only installs on Linux; on $(uname -s) install d2 $D2_VERSION manually (e.g. brew install d2)" >&2
  exit 1
fi

case "$(uname -m)" in
  aarch64 | arm64) arch=arm64; expected="$D2_SHA256_ARM64" ;;
  x86_64 | amd64) arch=amd64; expected="$D2_SHA256_AMD64" ;;
  *)
    echo "install-d2: unsupported architecture $(uname -m)" >&2
    exit 1
    ;;
esac

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

tarball="d2-v${D2_VERSION}-linux-${arch}.tar.gz"
url="https://github.com/terrastruct/d2/releases/download/v${D2_VERSION}/${tarball}"

echo "install-d2: fetching $tarball"
curl -fsSL "$url" -o "${workdir}/${tarball}"

echo "${expected}  ${workdir}/${tarball}" | sha256sum -c -

tar -xzf "${workdir}/${tarball}" -C "$workdir"
PREFIX="${PREFIX:-$HOME/.local}" make -C "${workdir}/d2-v${D2_VERSION}" install

echo "install-d2: installed d2 $D2_VERSION"
