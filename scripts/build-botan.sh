#! /bin/sh

sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $sdir/setup-machine-arch.sh

logfile=$rootdir/$bname-$archabi.log
rm -f $logfile

MOD_HW_COMMON=simd,chacha_simd32,chacha_avx2,simd_avx2

# Since Intel Haswell or AMD Excavator: sha2_32_bmi2,sha2_64_bmi2
#MOD_HW_AMD64=aes_ni,sha2_32_x86,$MOD_HW_COMMON
MOD_HW_AMD64=sha2_32_x86,$MOD_HW_COMMON
CFG_OPTIONS_AMD64=

#MOD_HW_ARM64=aes_armv8,sha2_32_armv8,$MOD_HW_COMMON
MOD_HW_ARM64=sha2_32_armv8,$MOD_HW_COMMON
CFG_OPTIONS_ARM64=

MOD_HW_ARM32=$MOD_HW_COMMON
CFG_OPTIONS_ARM32="--disable-neon"

MOD_RNG=system_rng

MOD_HASH=sha2_32,sha2_64,blake2,blake2mac
#MOD_CIPHER=aes,gcm,chacha,chacha20poly1305,aead,stream
MOD_CIPHER=chacha,chacha20poly1305,aead,stream
# MOD_COMPRESSION=lzma,bzip2
#MOD_BASIC=base,cryptobox,pubkey,rsa,x509,eme_oaep,eme_raw,emsa1,emsa_raw,pbes2,eme_pkcs1,emsa_pkcs1
MOD_BASIC=base,pubkey,rsa,x509,eme_oaep,eme_raw,emsa1,emsa_raw,pbes2,eme_pkcs1,emsa_pkcs1

case "$archabi" in
    "armhf") 
        USE_CPU=armhf
        MOD_HW_THIS=$MOD_HW_ARM32
        CFG_OPTIONS_THIS=$CFG_OPTIONS_ARM32
    ;;
    "arm64")
        USE_CPU=aarch64
        MOD_HW_THIS=$MOD_HW_ARM64
        CFG_OPTIONS_THIS=$CFG_OPTIONS_ARM64
    ;;
    "amd64")
        USE_CPU=x86_64
        MOD_HW_THIS=$MOD_HW_AMD64
        CFG_OPTIONS_THIS=$CFG_OPTIONS_AMD64
    ;;
    *) 
        echo "Unsupported archabi $archabi"
        exit 1
    ;;
esac

# CXX_FLAGS="-fno-rtti"
# LD_FLAGS="-fno-rtti"
CXX_FLAGS=
LD_FLAGS=

buildit() {
    echo rootdir $rootdir
    echo logfile $logfile
    echo CPU $USE_CPU
    echo CFG_OPTIONS_THIS $CFG_OPTIONS_THIS
    echo MOD_BASIC $MOD_BASIC
    echo MOD_CIPHER $MOD_CIPHER
    echo MOD_HASH $MOD_HASH
    echo MOD_RNG $MOD_RNG
    echo MOD_HW_THIS $MOD_HW_THIS

    mkdir -p $rootdir/include/amalgamation-$archabi
    rm -f $rootdir/include/amalgamation-$archabi/botan_all.h
    rm -f $rootdir/include/amalgamation-$archabi/botan_all.cpp

    cd $rootdir/botan

    ./configure.py --cpu=$USE_CPU $CFG_OPTIONS_THIS \
        --prefix=`pwd`/dist-$archabi-min \
        --minimized-build \
        --enable-modules=$MOD_BASIC,$MOD_CIPHER,$MOD_HASH,$MOD_RNG,$MOD_HW_THIS \
        --cxxflags=$CXX_FLAGS \
        --ldflags=$LD_FLAGS \
        --amalgamation \
        --with-doxygen \

    #    --with-lzma --with-bzip2 \

    mv botan_all.cpp botan_all.h $rootdir/include/amalgamation-$archabi/
    cd $rootdir
}

buildit 2>&1 | tee $logfile
cp -av $logfile $rootdir/include/amalgamation-$archabi/

