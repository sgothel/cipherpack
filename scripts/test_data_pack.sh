#!/bin/sh

script_args="$@"
sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $sdir/setup-machine-arch.sh

dist_dir=${rootdir}/dist-${archabi}
if [ ! -e ${dist_dir} ] ; then
    echo build first
    exit 1
fi
cd ${dist_dir}

if [ ! -e bin/cipherpack -o ! -e lib/libelevator.so ] ; then
    echo build incomplete
    exit 1
fi

#for i in ../test_data/data-10kiB.bin ../test_data/data-64kB.bin ../test_data/data-382MB.mkv ../test_data/data-1GB.mkv ; do

for i in ../test_data/data-10kiB.bin ../test_data/data-64kB.bin ; do
    ../scripts/run_cipherpack.sh pack -epk ../test_keys/terminal_rsa1.pub.pem -epk ../test_keys/terminal_rsa2.pub.pem -epk ../test_keys/terminal_rsa3.pub.pem \
                                      -ssk ../test_keys/host_rsa1 -in $i -target_path $i -version 201 -version_parent 200 -out $i.enc
done

