#!/bin/sh

if [ ! -e bin/cipherpack -o ! -e lib/libelevator.so ] ; then
    echo run from dist directory
    exit 1
fi

../scripts/run_cipherpack.sh pack -epk ../keys/terminal_rsa1.pub.pem -epk ../keys/terminal_rsa2.pub.pem -epk ../keys/terminal_rsa3.pub.pem -ssk ../keys/host_rsa -in ../test_data/data-64kB.bin -filename data-64kB.bin -version 101 -version_parent 100 -out ../test_data/data-64kB.bin.enc

../scripts/run_cipherpack.sh pack -epk ../keys/terminal_rsa1.pub.pem -epk ../keys/terminal_rsa2.pub.pem -epk ../keys/terminal_rsa3.pub.pem -ssk ../keys/host_rsa -in ../test_data/data-382MB.mkv -filename data-382MB.mkv -version 101 -version_parent 100 -out ../test_data/data-382MB.mkv.enc

../scripts/run_cipherpack.sh pack -epk ../keys/terminal_rsa1.pub.pem -epk ../keys/terminal_rsa2.pub.pem -epk ../keys/terminal_rsa3.pub.pem -ssk ../keys/host_rsa -in ../test_data/data-1GB.mkv -filename data-1GB.mkv -version 101 -version_parent 100 -out ../test_data/data-1GB.mkv.enc

