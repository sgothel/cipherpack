#!/bin/sh

if [ ! -e bin/cipherpack -o ! -e lib/libelevator.so ] ; then
    echo run from dist directory
    exit 1
fi

for i in ../test_data/data-64kB.bin ../test_data/data-382MB.mkv ../test_data/data-1GB.mkv ; do
    ../scripts/run_cipherpack.sh pack -epk ../keys/terminal_rsa1.pub.pem -epk ../keys/terminal_rsa2.pub.pem -epk ../keys/terminal_rsa3.pub.pem \
                                      -ssk ../keys/host_rsa1 -in $i -target_path $i -version 201 -version_parent 200 -out $i.enc
done

