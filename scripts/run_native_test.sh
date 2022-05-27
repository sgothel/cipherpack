#!/bin/bash

export elevator_debug=true
export elevator_verbose=true

script_args="$@"
sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $sdir/setup-machine-arch.sh

build_dir=${rootdir}/build-${archabi}

if [ "$1" = "-log" ] ; then
    logfile=$2
    shift 2
else
    logfile=
fi

test_exe=${build_dir}/test/elevator/test_01_cipherpack
if [ ! -z "$1" ] ; then
    test_exe=$1
    shift 1
fi
test_basename=`basename ${test_exe}`

if [ -z "${logfile}" ] ; then
    logfile=~/${bname}-${test_basename}-${archabi}.log
fi
rm -f $logfile
logbasename=`basename ${logfile} .log`

# run as root 'dpkg-reconfigure locales' enable 'en_US.UTF-8'
# perhaps run as root 'update-locale LC_MEASUREMENT=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8'
export LC_MEASUREMENT=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

do_test() {
    echo "script invocation: $0 ${script_args}"
    echo elevator_debug $elevator_debug
    echo elevator_verbose $elevator_verbose
    echo logfile $logfile

    cd `dirname $test_exe`

    ulimit -c unlimited
    $EXE_WRAPPER ${test_exe} ${*@Q}
    exit $?
}

do_test "$@" 2>&1 | tee $logfile

