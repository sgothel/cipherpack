#!/bin/sh

# export cipherpack_debug=true
export cipherpack_verbose=true

USE_HTTPD=1
#USE_HTTPD=0

script_args="$@"
sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $sdir/setup-machine-arch.sh

logfile=~/${bname}-${archabi}.log
rm -f $logfile
logfile_httpd=~/${bname}-${archabi}-httpd.log
rm -f $logfile_httpd

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

killall mini_httpd
killall mini_httpd
if [ $USE_HTTPD -eq 1 ] ; then
    /usr/sbin/mini_httpd -d ${rootdir} -p 8080 -l $logfile_httpd
fi

# run as root 'dpkg-reconfigure locales' enable 'en_US.UTF-8'
# perhaps run as root 'update-locale LC_MEASUREMENT=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8'
export LC_MEASUREMENT=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

ulimit -c unlimited

do_test() {
    echo logfile $logfile
    echo logfile $logfile_httpd
    echo cipherpack_debug $cipherpack_debug
    echo cipherpack_verbose $cipherpack_verbose

    #for i in ../test_data_local/data-10kiB.bin ../test_data_local/data-64kB.bin ../test_data_local/data-382MB.mkv ../test_data_local/data-1GB.mkv ; do
    #for i in ../test_data_local/data-10kiB.bin.enc ; do
    #for i in ../test_data_local/data-1GB.bin.enc ../test_data_local/data-2GB.bin.enc ; do
    #for i in ../test_data_local/*.bin.enc ; do
    for i in ../test_data_local/data-2GB.bin.enc ; do
        bname_file=`basename $i`
        if [ $USE_HTTPD -eq 1 ] ; then
            in_name="http://localhost:8080/test_data_local/${bname_file}"
        else
            in_name=${i}
        fi
        LD_LIBRARY_PATH=`pwd`/lib bin/cipherpack unpack \
                                            -spk ../test_keys/host_rsa1.pub.pem -spk ../test_keys/host_rsa2.pub.pem \
                                            -dsk ../test_keys/terminal_rsa1 \
                                            -in ${in_name} \
                                            -out $i.dec
    done
}

do_test 2>&1 | tee $logfile

