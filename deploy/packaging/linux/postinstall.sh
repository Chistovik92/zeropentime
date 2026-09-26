#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# После установки пакета: служба включается и запускается, ссылки zpt://
# открываются командой "zpt open".
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl enable zpt.service || true
  systemctl restart zpt.service || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
exit 0
