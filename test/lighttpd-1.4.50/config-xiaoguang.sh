#! /bin/sh
CC=/usr/local/musl/bin/musl-gcc ./configure --prefix=/opt/lighttpd --disable-FEATURE --enable-static --disable-lfs --disable-ipv6 --without-PACKAGE --without-valgrind --without-openssl --without-kerberos5 --without-pcre --without-zlib --without-bzip2 --without-lua
