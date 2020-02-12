#!/bin/bash
set -e
N_CPU=$(grep ^processor /proc/cpuinfo | wc -l)

mkdir -p opt
INSTALL_DIR=$(cd opt && pwd)

(
	rm -rf vendor
	mkdir -p vendor
	cd vendor
	git clone https://github.com/openssl/openssl.git
	cd openssl
	./Configure enable-weak-ssl-ciphers enable-deprecated enable-rc4 no-shared --prefix="$INSTALL_DIR" linux-x86_64
	make -j $N_CPU
	make install
	make clean
)
