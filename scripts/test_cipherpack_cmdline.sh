#!/bin/bash

data_dir_in=../cipherpack_test_data_local

sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $rootdir/jaulib/scripts/setup-machine-arch.sh "-quiet"

mkdir -p $rootdir/doc/test
logfile=$rootdir/doc/test/$bname-$os_name-$archabi.log
rm -f $logfile

build_dir=$rootdir/"build-$os_name-$archabi"
data_dir_out=${build_dir}/test_cipherpack_out
rm -rf ${data_dir_out}
mkdir -p ${data_dir_out}

cmp_hash_value() {
    hash1=`awk ' { print $1 } ' $1`
    hash2=`awk ' { print $1 } ' $2`
    if [ "$hash1" != "$hash2" ] ; then
        echo "Hash mismatch $1 $2"
        return 1
    fi
    return 0
}

run_test_file01() {
    #scripts/cipherpack hash -out ${data_dir_out}/test_data_local.phash ${data_dir_in}
    #if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi

    scripts/cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 -hashout ${data_dir_out}/t1.orig.phash -out ${data_dir_out}/t1.enc ${data_dir_in}/data-10kiB.bin
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    scripts/cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 -hashout ${data_dir_out}/t1.dec.phash -out ${data_dir_out}/t1.dec ${data_dir_out}/t1.enc
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp ${data_dir_out}/t1.dec ${data_dir_in}/data-10kiB.bin
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t1.orig.phash ${data_dir_out}/t1.dec.phash
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi

    scripts/cipherpack hash -out ${data_dir_out}/t1.dec2.phash ${data_dir_out}/t1.dec
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t1.dec.phash ${data_dir_out}/t1.dec2.phash
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
}

run_test_pipe01() {
    cat ${data_dir_in}/data-10kiB.bin | scripts/cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 -hashout ${data_dir_out}/t2.orig.phash > ${data_dir_out}/t2.enc
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cat ${data_dir_out}/t2.enc | scripts/cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 -hashout ${data_dir_out}/t2.dec.phash > ${data_dir_out}/t2.dec
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp ${data_dir_out}/t2.dec ${data_dir_in}/data-10kiB.bin
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t2.orig.phash ${data_dir_out}/t2.dec.phash
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi

    scripts/cipherpack hash -out ${data_dir_out}/t2.dec2.phash ${data_dir_out}/t2.dec
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t2.dec.phash ${data_dir_out}/t2.dec2.phash
}

run_test_pipe02() {
    cat ${data_dir_in}/data-10kiB.bin | scripts/cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 -hashout ${data_dir_out}/t3.orig.phash | scripts/cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 -hashout ${data_dir_out}/t3.dec.phash > ${data_dir_out}/t3.dec
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp ${data_dir_out}/t3.dec ${data_dir_in}/data-10kiB.bin
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t3.orig.phash ${data_dir_out}/t3.dec.phash
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
}

run_test_file01 2>&1 | tee $logfile
run_test_pipe01 2>&1 | tee $logfile
run_test_pipe02 2>&1 | tee $logfile
