#!/bin/sh

echo "[*] Downloading OpenSSL..."
git submodule init
git submodule update

echo "[*] Building OpenSSL..."
cd openssl
./config --prefix=$(pwd)/local enable-ssl2 enable-ssl3 enable-ssl3-method enable-des enable-rc4 enable-weak-ssl-ciphers no-shared
make
make install_sw
cd ..

echo "[*] Building hostapd-mana..."
cd hostapd
make
cd ..

echo "[+] Done!"
