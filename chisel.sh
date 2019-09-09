#!/usr/bin/bash

echo "[!] Deleting previous chisel folder and binaries..."
/usr/bin/rm -rf /opt/chisel
/usr/bin/cd /opt
echo "[!] Creating fresh chisel clone in '/opt'..."
git clone https://github.com/jpillora/chisel.git
/usr/bin/cd chisel
echo "[!] Building new chisel Go binary without debug information..."
/usr/local/go/bin/go build -ldflags="-s -w"
echo "[!] Packing with upx..."
/usr/bin/upx brute chisel
