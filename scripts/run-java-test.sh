#!/bin/bash

#export cipherpack_debug=true
#export cipherpack_verbose=true

#
# JAVA_PROPS="-Dorg.cipherpack.debug=true -Dorg.cipherpack.verbose=true"
#

script_args="$@"
sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $sdir/setup-machine-arch.sh

build_dir=${rootdir}/build-${archabi}

if [ -e /usr/lib/jvm/java-17-openjdk-$archabi ] ; then
    export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-$archabi
elif [ -e /usr/lib/jvm/java-11-openjdk-$archabi ] ; then
    export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-$archabi
fi
if [ ! -e $JAVA_HOME ] ; then
    echo $JAVA_HOME does not exist
    exit 1
fi
JAVA_EXE=${JAVA_HOME}/bin/java
# JAVA_EXE=`readlink -f $(which java)`
# JAVA_CMD="${JAVA_EXE} -Xcheck:jni -verbose:jni"
JAVA_CMD="${JAVA_EXE}"

if [ "$1" = "-log" ] ; then
    logfile=$2
    shift 2
else
    logfile=
fi

test_class=test.org.cipherpack.Test01Cipherpack
if [ ! -z "$1" ] ; then
    test_class=$1
    shift 1
fi
test_basename=`echo ${test_class} | sed 's/.*\.//g'`

if [ -z "${logfile}" ] ; then
    logfile=~/${bname}-${test_basename}-${archabi}.log
fi
rm -f $logfile
logbasename=`basename ${logfile} .log`

valgrindlogfile=$logbasename-valgrind.log
rm -f $valgrindlogfile

callgrindoutfile=$logbasename-callgrind.out
rm -f $callgrindoutfile

echo 'core_%e.%p' | sudo tee /proc/sys/kernel/core_pattern
ulimit -c unlimited

# run as root 'dpkg-reconfigure locales' enable 'en_US.UTF-8'
# perhaps run as root 'update-locale LC_MEASUREMENT=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8'
export LC_MEASUREMENT=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

# export JAVA_PROPS="-Xint"
# export EXE_WRAPPER="valgrind --tool=memcheck --leak-check=full --show-reachable=no  --track-origins=yes --num-callers=24 --malloc-fill=0xff --free-fill=0xfe --error-limit=no --default-suppressions=yes --suppressions=$sdir/valgrind.supp --suppressions=$sdir/valgrind-jvm.supp --gen-suppressions=all -s --log-file=$valgrindlogfile"
# export EXE_WRAPPER="valgrind --tool=helgrind --track-lockorders=yes --num-callers=24 --ignore-thread-creation=yes --default-suppressions=yes --suppressions=$sdir/valgrind.supp --suppressions=$sdir/valgrind-jvm.supp --gen-suppressions=all -s --log-file=$valgrindlogfile"
# export EXE_WRAPPER="valgrind --tool=drd --segment-merging=no --ignore-thread-creation=yes --trace-barrier=no --trace-cond=no --trace-fork-join=no --trace-mutex=no --trace-rwlock=no --trace-semaphore=no --default-suppressions=yes --suppressions=$sdir/valgrind.supp --suppressions=$sdir/valgrind-jvm.supp --gen-suppressions=all -s --log-file=$valgrindlogfile"
# export EXE_WRAPPER="valgrind --tool=callgrind --instr-atstart=yes --collect-atstart=yes --collect-systime=yes --combine-dumps=yes --separate-threads=no --callgrind-out-file=$callgrindoutfile --log-file=$valgrindlogfile"

test_classpath=/usr/share/java/junit4.jar:${build_dir}/java/cipherpack.jar:${build_dir}/jaulib/java_base/jaulib_base.jar:${build_dir}/jaulib/test/java/jaulib-test.jar:${build_dir}/test/java/cipherpack-test.jar

do_test() {
    echo "script invocation: $0 ${script_args}"
    echo cipherpack_debug $cipherpack_debug
    echo cipherpack_verbose $cipherpack_verbose
    echo logfile $logfile
    echo test_class ${test_class}

    test_dir="${build_dir}/test/java/"
    echo "cd ${test_dir}"
    cd ${test_dir}
    pwd

    echo "$EXE_WRAPPER ${JAVA_CMD} ${JAVA_PROPS} -cp ${test_classpath} -Djava.library.path=${rootdir}/dist-${archabi}/lib org.junit.runner.JUnitCore ${test_class} ${*@Q}"

    ulimit -c unlimited
    $EXE_WRAPPER ${JAVA_CMD} ${JAVA_PROPS} -cp ${test_classpath} -Djava.library.path=${rootdir}/dist-${archabi}/lib org.junit.runner.JUnitCore ${test_class} ${*@Q}
    exit $?
}

do_test "$@" 2>&1 | tee $logfile

