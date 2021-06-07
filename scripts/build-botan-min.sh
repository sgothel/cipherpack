#! /bin/sh

sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`

cd $rootdir/botan

MOD_HW_COMMON=simd,chacha_simd32,chacha_avx2,simd_avx2

#MOD_HW_AMD64=aes_ni,sha1_sse2,sha1_x86,sha2_32_x86,$MOD_HW_COMMON
MOD_HW_AMD64=sha1_sse2,sha1_x86,sha2_32_x86,$MOD_HW_COMMON
#MOD_HW_ARM64=aes_armv8,pmull,sha1_armv8,sha2_32_armv8,$MOD_HW_COMMON
MOD_HW_ARM64=pmull,sha1_armv8,sha2_32_armv8,$MOD_HW_COMMON

USE_CPU=x86_64
MOD_HW_THIS=$MOD_HW_AMD64

MOD_RNG=system_rng

MOD_HASH=sha1,sha2_32
#MOD_CIPHER=aes,gcm,chacha,chacha20poly1305,aead,stream
MOD_CIPHER=chacha,chacha20poly1305,aead,stream
# MOD_COMPRESSION=lzma,bzip2
#MOD_BASIC=base,cryptobox,pubkey,rsa,x509,eme_oaep,eme_raw
MOD_BASIC=base,pubkey,rsa,x509,eme_oaep,eme_raw,emsa1

# CXX_FLAGS="-fno-rtti"
# LD_FLAGS="-fno-rtti"
CXX_FLAGS=
LD_FLAGS=

rm -rf dist-amd64-min
mkdir -p dist-amd64-min

./configure.py --cpu=$USE_CPU --prefix=`pwd`/dist-amd64-min --minimized-build \
    --enable-modules=$MOD_BASIC,$MOD_CIPHER,$MOD_HASH,$MOD_RNG,$MOD_HW_THIS \
    --cxxflags=$CXX_FLAGS \
    --ldflags=$LD_FLAGS \
    --amalgamation \
    --with-doxygen \

#    --with-lzma --with-bzip2 \

cp -a botan_all.cpp botan_all.h dist-amd64-min/

cd $rootdir
