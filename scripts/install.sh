#!/bin/sh
# RaxuisCLI installer — downloads the latest release binary for your platform.
#
#   curl -sSL https://raw.githubusercontent.com/Raxuis/RaxuisCLI/main/scripts/install.sh | sh
#
# Env overrides:
#   RAXUIS_VERSION   pin a version (e.g. v1.2.3); default: latest release
#   RAXUIS_BIN_DIR   install directory; default: /usr/local/bin (or ~/.local/bin without write access)
set -eu

REPO="Raxuis/RaxuisCLI"
BIN="raxuiscli"

err() { printf 'error: %s\n' "$1" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || err "missing required command: $1"; }
need uname
need tar

if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsSL "$1" -o "$2"; }
  fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO "$2" "$1"; }
  fetch() { wget -qO- "$1"; }
else
  err "need curl or wget"
fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux | darwin) ;;
  *) err "unsupported OS: $os (use the Windows zip from the releases page)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) err "unsupported architecture: $arch" ;;
esac

version="${RAXUIS_VERSION:-}"
if [ -z "$version" ]; then
  version=$(fetch "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name":' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [ -n "$version" ] || err "could not resolve latest version"
fi

# Archive names carry the version without the leading "v".
num="${version#v}"
archive="${BIN}_${num}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${version}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

printf 'Downloading %s (%s)...\n' "$BIN" "$version"
dl "${base}/${archive}" "${tmp}/${archive}" || err "download failed: ${base}/${archive}"

# Verify checksum when the checksums file is available.
if dl "${base}/checksums.txt" "${tmp}/checksums.txt" 2>/dev/null; then
  expected=$(grep " ${archive}\$" "${tmp}/checksums.txt" | awk '{print $1}')
  if [ -n "$expected" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      actual=$(sha256sum "${tmp}/${archive}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
      actual=$(shasum -a 256 "${tmp}/${archive}" | awk '{print $1}')
    fi
    [ -z "${actual:-}" ] || [ "$actual" = "$expected" ] || err "checksum mismatch for ${archive}"
  fi
fi

tar -xzf "${tmp}/${archive}" -C "$tmp"
[ -f "${tmp}/${BIN}" ] || err "binary not found in archive"

dir="${RAXUIS_BIN_DIR:-/usr/local/bin}"
if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
  dir="${HOME}/.local/bin"
  mkdir -p "$dir"
fi

install -m 0755 "${tmp}/${BIN}" "${dir}/${BIN}"
printf 'Installed %s to %s/%s\n' "$BIN" "$dir" "$BIN"

case ":${PATH}:" in
  *":${dir}:"*) ;;
  *) printf 'note: %s is not in your PATH — add it to use %s directly.\n' "$dir" "$BIN" ;;
esac
