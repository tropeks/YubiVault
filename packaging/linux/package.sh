#!/bin/sh
# Builds YubiVault-<version>-<rid>.tar.gz from published single-file binaries.
# Usage: packaging/linux/package.sh <version> <rid> <app publish dir> <cli publish dir>
set -eu

version=$1 rid=$2 app=$3 cli=$4
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
name=YubiVault-$version-$rid
stage=$(mktemp -d)/$name

mkdir -p "$stage/share"
install -m755 "$app/YubiVault" "$cli/yubivault-cli" "$here/install.sh" "$stage/"
install -m644 "$here/yubivault.desktop" "$here/yubivault-mime.xml" "$here/70-yubivault-fido.rules" "$stage/share/"
install -m644 "$root/assets/yubivault.png" "$stage/share/yubivault.png"
install -m644 "$root/LICENSE" "$stage/"
install -m644 "$here/README.txt" "$stage/"

tar -C "$(dirname "$stage")" --owner=0 --group=0 -czf "$name.tar.gz" "$name"
echo "$name.tar.gz"
