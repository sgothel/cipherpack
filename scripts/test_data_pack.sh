#!/bin/sh

# export cipherpack_debug=true
export cipherpack_verbose=true

script_args="$@"
sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $sdir/setup-machine-arch.sh

logfile=~/${bname}-${archabi}.log
rm -f $logfile

dist_dir=${rootdir}/dist-${archabi}
if [ ! -e ${dist_dir} ] ; then
    echo build first
    exit 1
fi
cd ${dist_dir}

if [ ! -e bin/cipherpack -o ! -e lib/libcipherpack.so ] ; then
    echo build incomplete
    exit 1
fi
ulimit -c unlimited

# run as root 'dpkg-reconfigure locales' enable 'en_US.UTF-8'
# perhaps run as root 'update-locale LC_MEASUREMENT=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8'
export LC_MEASUREMENT=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

do_test() {
    echo logfile $logfile
    echo COMMANDLINE $0 $*
    echo cipherpack_debug $cipherpack_debug
    echo cipherpack_verbose $cipherpack_verbose

    #for i in ../test_data_local/data-10kiB.bin ../test_data_local/data-64kB.bin ../test_data_local/data-382MB.mkv ../test_data_local/data-1GB.mkv ; do
    for i in ../test_data_local/*.bin ; do
        LD_LIBRARY_PATH=`pwd`/lib bin/cipherpack pack \
                                          -epk ../test_keys/terminal_rsa1.pub.pem -epk ../test_keys/terminal_rsa2.pub.pem -epk ../test_keys/terminal_rsa3.pub.pem \
                                          -ssk ../test_keys/host_rsa1 -in $i -target_path $i -version 201 -version_parent 200 -out $i.enc
    done
}

do_test 2>&1 | tee $logfile

