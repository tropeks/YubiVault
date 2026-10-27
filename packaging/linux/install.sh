#!/bin/sh
# Installs YubiVault for the current user only (no root): the app and CLI in
# ~/.local/bin, a menu entry, the icon and the .yvault file type.
# Run it again to update, or with --uninstall to remove everything it added.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
data=${XDG_DATA_HOME:-$HOME/.local/share}
bin=$HOME/.local/bin

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$bin/yubivault" "$bin/yubivault-cli" \
          "$data/applications/yubivault.desktop" \
          "$data/icons/hicolor/512x512/apps/yubivault.png"
    rm -f "$data/mime/packages/yubivault-mime.xml"
else
    install -Dm755 "$here/YubiVault" "$bin/yubivault"
    install -Dm755 "$here/yubivault-cli" "$bin/yubivault-cli"
    install -Dm644 "$here/share/yubivault.desktop" "$data/applications/yubivault.desktop"
    install -Dm644 "$here/share/yubivault.png" "$data/icons/hicolor/512x512/apps/yubivault.png"
    install -Dm644 "$here/share/yubivault-mime.xml" "$data/mime/packages/yubivault-mime.xml"
    # Menus may not search ~/.local/bin, so point the entry at the full path.
    sed -i "s|^Exec=yubivault |Exec=\"$bin/yubivault\" |" "$data/applications/yubivault.desktop"
fi

command -v update-mime-database >/dev/null && update-mime-database "$data/mime" || true
command -v update-desktop-database >/dev/null && update-desktop-database "$data/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$data/icons/hicolor" || true

if [ "${1:-}" = "--uninstall" ]; then
    echo "YubiVault removed."
else
    echo "YubiVault installed in $bin. It is in your applications menu, and .yvault files open with it."
fi
