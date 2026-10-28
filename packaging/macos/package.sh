#!/bin/sh
# Builds YubiVault-<version>-<rid>.zip holding YubiVault.app and yubivault-cli.
# Runs on macOS (needs sips, iconutil and codesign).
# Usage: packaging/macos/package.sh <version> <rid> <app publish dir> <cli publish dir>
set -eu

version=$1 rid=$2 app=$3 cli=$4
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
name=YubiVault-$version-$rid
stage=$(mktemp -d)/$name
bundle=$stage/YubiVault.app

mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
install -m755 "$app/YubiVault" "$bundle/Contents/MacOS/YubiVault"
sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$bundle/Contents/Info.plist"
plutil -lint "$bundle/Contents/Info.plist"

# Each .icns is built from a 512 px PNG at every size macOS asks for: the app icon, and the
# folder-with-key icon that Finder shows on .yvault files.
make_icns() {
    iconset=$(mktemp -d)/icon.iconset
    mkdir -p "$iconset"
    for size in 16 32 128 256 512; do
        sips -z $size $size "$1" --out "$iconset/icon_${size}x${size}.png" >/dev/null
        double=$((size * 2))
        if [ $double -le 512 ]; then
            sips -z $double $double "$1" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
        fi
    done
    iconutil -c icns "$iconset" -o "$2"
}
make_icns "$root/assets/yubivault.png" "$bundle/Contents/Resources/yubivault.icns"
make_icns "$root/assets/yubivault-file.png" "$bundle/Contents/Resources/yubivault-file.icns"

install -m755 "$cli/yubivault-cli" "$stage/yubivault-cli"
install -m644 "$root/LICENSE" "$here/README.txt" "$stage/"

# Not notarized: an ad-hoc signature is what Apple Silicon needs to run it at all.
codesign --force --deep --sign - "$bundle"
codesign --force --sign - "$stage/yubivault-cli"

ditto -c -k --keepParent "$stage" "$name.zip"
echo "$name.zip"
