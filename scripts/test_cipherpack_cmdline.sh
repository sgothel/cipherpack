#!/bin/bash

# export cipherpack_debug=true
# export cipherpack_verbose=true

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
    hash1_algo=`awk '  { print $1 } ' $1`
    hash1_value=`awk ' { print $2 } ' $1`
    hash2_algo=`awk '  { print $1 } ' $2`
    hash2_value=`awk ' { print $2 } ' $2`
    if [ "$hash1_algo" != "$hash2_algo" ] ; then
        echo "Hash algo mismatch"
        echo "- 1: algo $hash1_algo in $1"
        echo "- 2: algo $hash2_algo in $2"
        return 1
    fi
    if [ "$hash1_value" != "$hash2_value" ] ; then
        echo "Hash value mismatch"
        echo "- 1: value $hash1_value in $1"
        echo "- 2: value $hash2_value in $2"
        return 1
    fi
    return 0
}

run_test_file01() {
    infile=$1
    #scripts/cipherpack hash -out ${data_dir_out}/test_data_local.phash ${data_dir_in}
    #if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi

    scripts/cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 -hashout ${data_dir_out}/t1.orig.phash -out ${data_dir_out}/t1.enc ${infile}
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    scripts/cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 -hashout ${data_dir_out}/t1.dec.phash -out ${data_dir_out}/t1.dec ${data_dir_out}/t1.enc
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp ${data_dir_out}/t1.dec ${infile}
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t1.orig.phash ${data_dir_out}/t1.dec.phash
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi

    scripts/cipherpack hash -out ${data_dir_out}/t1.dec2.phash ${data_dir_out}/t1.dec
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t1.dec.phash ${data_dir_out}/t1.dec2.phash
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
}

run_test_pipe01() {
    infile=$1
    cat ${infile} | scripts/cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 -hashout ${data_dir_out}/t2.orig.phash > ${data_dir_out}/t2.enc
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cat ${data_dir_out}/t2.enc | scripts/cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 -hashout ${data_dir_out}/t2.dec.phash > ${data_dir_out}/t2.dec
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp ${data_dir_out}/t2.dec ${infile}
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t2.orig.phash ${data_dir_out}/t2.dec.phash
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi

    scripts/cipherpack hash -out ${data_dir_out}/t2.dec2.phash ${data_dir_out}/t2.dec
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t2.dec.phash ${data_dir_out}/t2.dec2.phash
}

run_test_pipe02() {
    infile=$1
    cat ${infile} | scripts/cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 -hashout ${data_dir_out}/t3.orig.phash | scripts/cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 -hashout ${data_dir_out}/t3.dec.phash > ${data_dir_out}/t3.dec
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp ${data_dir_out}/t3.dec ${infile}
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
    cmp_hash_value ${data_dir_out}/t3.orig.phash ${data_dir_out}/t3.dec.phash
    if [ $? -ne 0 ] ; then echo "ERROR test $LINENO"; return 1; fi
}

#${data_dir_in}/data-10kiB.bin
#${data_dir_in}/data-32752B.bin
#=${data_dir_in}/data-32768B.bin
#infile=${data_dir_in}/deploy.sqfs
#infile=${data_dir_in}/data-382MB.bin

for i in ${data_dir_in}/data-10kiB.bin ${data_dir_in}/data-32752B.bin ${data_dir_in}/data-32768B.bin ${data_dir_in}/deploy.sqfs ; do
    run_test_file01 $i 2>&1 | tee $logfile
    run_test_pipe01 $i 2>&1 | tee $logfile
    run_test_pipe02 $i 2>&1 | tee $logfile
done

