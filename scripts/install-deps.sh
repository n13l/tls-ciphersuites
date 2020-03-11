#!/bin/bash
set -e
N_CPU=$(grep ^processor /proc/cpuinfo | wc -l)

mkdir -p opt
mkdir -p vendor

INSTALL_DIR=$(cd opt && pwd)

(
	cd vendor
	git clone https://github.com/openssl/openssl.git
	cd openssl
	./Configure enable-weak-ssl-ciphers enable-deprecated \
                enable-ssl2 enable-ssl3 \
		enable-rc2 enable-rc4 enable-rc5 \
		enable-rmd160 enable-md2 enable-md4 enable-mdc2 \
		enable-gost enable-idea enable-blake2 enable-aria enable-idea \
		enable-whirlpool enable-des enable-dsa enable-ripemd enable-seed \
		enable-sm2 enable-sm3 enable-sm4 enable-cast \
		no-shared --prefix="$INSTALL_DIR" linux-x86_64
	make -j $N_CPU
	make install
	make clean
)

#(
#	git clone https://github.com/open-quantum-safe/liboqs.git
#	cd libogs
#	autoreconf -i
#	./configure --prefix="$INSTALL_DIR"
#	make -j $N_CPU
#	make install
#	make clean
#	cd ..
#	git clone https://github.com/open-quantum-safe/openssl.git
#	./Configure enable-weak-ssl-ciphers enable-deprecated enable-rc4 no-shared --prefix="$INSTALL_DIR/ogs" linux-x86_64
#	make -j $N_CPU
#	make install
#	make clean
#)

#(
#	git clone https://github.com/gnutls/gnutls.git
#	cd gnutls
#	autoreconf -i
#	./configure --prefix="$INSTALL_DIR"
#	make -j $N_CPU
#	make install
#	make clean
#)
