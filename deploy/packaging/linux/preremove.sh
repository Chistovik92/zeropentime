#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Перед удалением пакета служба останавливается. При обновлении (deb: "upgrade",
# rpm: $1 = 1) — не трогаем: postinstall новой версии её перезапустит.
case "$1" in
  upgrade|1) exit 0 ;;
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl disable --now zpt.service || true
fi
exit 0
