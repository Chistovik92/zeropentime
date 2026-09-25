#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Скачивает официальный Wintun в third_party/wintun и проверяет SHA-256.
# Вызывается goreleaser перед сборкой: wintun.dll кладётся в архивы для Windows.
# Лицензия Wintun (Prebuilt Binaries License) разрешает распространять DLL
# вместе с программой, использующей её API; текст лицензии кладётся рядом.
set -euo pipefail

version="0.14.1"
sha256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
dest="third_party/wintun"

if [ -f "$dest/.version" ] && [ "$(cat "$dest/.version")" = "$version" ]; then
  exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/wintun.zip" "https://www.wintun.net/builds/wintun-$version.zip"
got=$(sha256sum "$tmp/wintun.zip" | cut -d' ' -f1)
if [ "$got" != "$sha256" ]; then
  echo "wintun-$version.zip: SHA-256 $got, ожидалось $sha256" >&2
  exit 1
fi
rm -rf "$dest"
mkdir -p "$dest"
unzip -q "$tmp/wintun.zip" -d "$tmp"
cp -r "$tmp/wintun/bin" "$dest/"
cp "$tmp/wintun/LICENSE.txt" "$dest/LICENSE.txt"
echo "$version" > "$dest/.version"
