#!/bin/bash
set -e
#git submodule update --init --recursive --remote

N_CPU=$(grep ^processor /proc/cpuinfo | wc -l)

mkdir -p opt
INSTALL_DIR=$(cd opt && pwd)

(
	#export CC="$CC -DSSL_DEBUG=1";
	mkdir -p vendor
	cd vendor
	#git clone https://github.com/openssl/openssl.git
	cd openssl
#	./Configure $openssl_cflags \
#	enable-ssl2 enable-weak-ssl-ciphers --debug --prefix="$INSTALL_DIR" &&
	./Configure enable-weak-ssl-ciphers enable-deprecated enable-rc4 no-shared --prefix="$INSTALL_DIR" linux-x86_64
	make -j $N_CPU
	make install
	make clean
)
