YubiVault for Linux
===================

Run it from here:   ./YubiVault          (command line: ./yubivault-cli help)

Or install it for your user (menu entry, icon, .yvault file type, no root):
    ./install.sh                 ./install.sh --uninstall   to remove it

Security key access
-------------------
YubiVault talks to your FIDO2 key through /dev/hidraw*. On distributions with
systemd 244 or later (Ubuntu 20.04+, Debian 11+, Fedora 32+ and most others)
the logged-in user already has access, so there is nothing to do.

If YubiVault says it cannot find your key, install the udev rule in share/:
    sudo cp share/70-yubivault-fido.rules /etc/udev/rules.d/
    sudo udevadm control --reload && sudo udevadm trigger
then unplug and plug the key back in.

Full documentation: https://github.com/tropeks/YubiVault
