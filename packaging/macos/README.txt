YubiVault for macOS
===================

Drag YubiVault.app to Applications (or keep it on a USB stick) and open it.
yubivault-cli is the command-line version: ./yubivault-cli help

First launch
------------
YubiVault is free and not notarized by Apple, so macOS blocks it the first time.
Open it with right-click (or Control-click) > Open > Open, or in Terminal:
    xattr -dr com.apple.quarantine YubiVault.app yubivault-cli

Your security key needs no drivers or setup. Requires macOS 14 or later.

Full documentation: https://github.com/tropeks/YubiVault
