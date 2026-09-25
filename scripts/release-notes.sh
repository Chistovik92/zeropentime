#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Печатает раздел CHANGELOG.md для версии: scripts/release-notes.sh 0.1.0
# Завершается с ошибкой, если раздела нет — релиз без заметок не выпускается.
set -euo pipefail

version="${1:?использование: $0 ВЕРСИЯ (например 0.1.0)}"
changelog="${2:-CHANGELOG.md}"

notes=$(awk -v v="$version" '
  $0 ~ "^## \\[" v "\\]" { found = 1; next }
  found && /^## \[/ { exit }
  found { print }
' "$changelog")

if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "в $changelog нет раздела «## [$version]» — добавьте заметки к релизу" >&2
  exit 1
fi
printf '%s\n' "$notes"
