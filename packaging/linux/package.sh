#!/bin/sh
# Builds YubiVault-<version>-<rid>.tar.gz and, when nfpm is on the PATH, the
# matching .deb and .rpm, from published single-file binaries.
# Usage: packaging/linux/package.sh <version> <rid> <app publish dir> <cli publish dir>
set -eu

version=$1 rid=$2 app=$3 cli=$4
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
name=YubiVault-$version-$rid
work=$(mktemp -d)
stage=$work/$name

mkdir -p "$stage/share"
install -m755 "$app/YubiVault" "$cli/yubivault-cli" "$here/install.sh" "$stage/"
install -m644 "$here/yubivault.desktop" "$here/yubivault-mime.xml" "$here/70-yubivault-fido.rules" "$stage/share/"
install -m644 "$root/assets/yubivault.png" "$stage/share/yubivault.png"
install -m644 "$root/assets/yubivault-file.png" "$stage/share/application-x-yubivault.png"
install -m644 "$root/LICENSE" "$here/README.txt" "$stage/"

tar -C "$work" --owner=0 --group=0 -czf "$name.tar.gz" "$name"
echo "$name.tar.gz"

command -v nfpm >/dev/null || exit 0

case "$rid" in
    linux-x64) arch=amd64 ;;
    linux-arm64) arch=arm64 ;;
    *) echo "No .deb/.rpm architecture for $rid" >&2; exit 1 ;;
esac
mkdir "$work/pkgroot"
cp "$stage/YubiVault" "$stage/yubivault-cli" "$stage/share/yubivault.desktop" \
   "$stage/share/yubivault.png" "$stage/share/application-x-yubivault.png" "$stage/share/yubivault-mime.xml" "$stage/LICENSE" "$work/pkgroot/"
cp "$here/nfpm.yaml" "$work/"
out=$(pwd)
for packager in deb rpm; do
    (cd "$work" && VERSION=$version ARCH=$arch nfpm package -f nfpm.yaml -p $packager -t "$out/")
done
