#!/bin/bash

# export cipherpack_debug=true
# export cipherpack_verbose=true
unset cipherpack_debug
unset cipherpack_verbose

#
# JAVA_PROPS="-Dorg.cipherpack.debug=true -Dorg.cipherpack.verbose=true"
#

script_args="$@"
sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $rootdir/jaulib/scripts/setup-machine-arch.sh "-quiet"

dist_dir=$rootdir/"dist-$os_name-$archabi"
build_dir=$rootdir/"build-$os_name-$archabi"
echo dist_dir $dist_dir
echo build_dir $build_dir

if [ ! -e $dist_dir/lib/java/jaulib-test.jar ] ; then
    echo "test exe $dist_dir/lib/java/jaulib-test.jar not existing"
    exit 1
fi

if [ -z "$JAVA_HOME" -o ! -e "$JAVA_HOME" ] ; then
    echo "ERROR: JAVA_HOME $JAVA_HOME does not exist"
    exit 1
else
    echo JAVA_HOME $JAVA_HOME
fi
if [ -z "$JUNIT_CP" ] ; then
    echo "ERROR: JUNIT_CP $JUNIT_CP does not exist"
    exit 1
else
    echo JUNIT_CP $JUNIT_CP
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
    mkdir -p $rootdir/doc/test
    logfile=$rootdir/doc/test/${bname}-${test_basename}-${os_name}-${archabi}.log
fi
rm -f $logfile
logbasename=`basename ${logfile} .log`

valgrindlogfile=$rootdir/doc/test/$logbasename.valgrind.0.log
rm -f $valgrindlogfile

callgrindoutfile=$rootdir/doc/test/$logbasename.callgrind.0.out
rm -f $callgrindoutfile

ulimit -c unlimited

# run as root 'dpkg-reconfigure locales' enable 'en_US.UTF-8'
# perhaps run as root 'update-locale LC_MEASUREMENT=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8'
export LC_MEASUREMENT=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

# export JAVA_PROPS="-Xint"
# export EXE_WRAPPER="nice -20"
# export JAVA_PROPS="-Djau.debug=true -Djau.verbose=true"

# export JAVA_PROPS="-Xint -Xcheck:jni"
# export JAVA_PROPS="-Xcheck:jni -verbose:jni"
#export EXE_WRAPPER="LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/10/libasan.so"
# export EXE_WRAPPER="valgrind --tool=memcheck --leak-check=full --show-reachable=no  --track-origins=yes --num-callers=24 --malloc-fill=0xff --free-fill=0xfe --error-limit=no --default-suppressions=yes --suppressions=$sdir/valgrind.supp --suppressions=$sdir/valgrind-jvm.supp --gen-suppressions=all -s --log-file=$valgrindlogfile"
# export EXE_WRAPPER="valgrind --tool=helgrind --track-lockorders=yes --num-callers=24 --ignore-thread-creation=yes --default-suppressions=yes --suppressions=$sdir/valgrind.supp --suppressions=$sdir/valgrind-jvm.supp --gen-suppressions=all -s --log-file=$valgrindlogfile"
# export EXE_WRAPPER="valgrind --tool=drd --segment-merging=no --ignore-thread-creation=yes --trace-barrier=no --trace-cond=no --trace-fork-join=no --trace-mutex=no --trace-rwlock=no --trace-semaphore=no --default-suppressions=yes --suppressions=$sdir/valgrind.supp --suppressions=$sdir/valgrind-jvm.supp --gen-suppressions=all -s --log-file=$valgrindlogfile"
# export EXE_WRAPPER="valgrind --tool=callgrind --instr-atstart=yes --collect-atstart=yes --collect-systime=yes --combine-dumps=yes --separate-threads=no --callgrind-out-file=$callgrindoutfile --log-file=$valgrindlogfile"


test_classpath=$JUNIT_CP:${dist_dir}/lib/java/cipherpack.jar:${build_dir}/jaulib/java_base/jaulib_base.jar:${build_dir}/jaulib/test/java/jaulib-test.jar:${build_dir}/test/java/cipherpack-test.jar
#test_classpath=$JUNIT_CP:${dist_dir}/lib/java/cipherpack-fat.jar:${build_dir}/jaulib/java_base/jaulib_base.jar:${build_dir}/jaulib/test/java/jaulib-test.jar:${build_dir}/test/java/cipherpack-test.jar

do_test() {
    echo "script invocation: $0 ${script_args}"
    echo EXE_WRAPPER $EXE_WRAPPER
    echo cipherpack_debug $cipherpack_debug
    echo cipherpack_verbose $cipherpack_verbose
    echo logbasename $logbasename
    echo logfile $logfile
    echo test_class ${test_class}

    test_dir="${build_dir}/test/java/"
    echo "cd ${test_dir}"
    cd ${test_dir}
    pwd

    echo "$EXE_WRAPPER ${JAVA_CMD} ${JAVA_PROPS} -cp ${test_classpath} -Djava.library.path=${dist_dir}/lib org.junit.runner.JUnitCore ${test_class} ${*@Q}"

    ulimit -c unlimited
    # export ASAN_OPTIONS="debug=true:strict_string_checks=true:detect_odr_violation=2:halt_on_error=false:verbosity=2"
    # LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/10/libasan.so \

    # $EXE_WRAPPER ${JAVA_CMD} ${JAVA_PROPS} -cp ${test_classpath} -Djava.library.path=${dist_dir}/lib org.junit.runner.JUnitCore ${test_class} ${*@Q}

    $EXE_WRAPPER ${JAVA_CMD} ${JAVA_PROPS} -cp ${test_classpath} -Djava.library.path=${dist_dir}/lib ${test_class} $*

    # $EXE_WRAPPER ${JAVA_CMD} ${JAVA_PROPS} -cp ${test_classpath} org.junit.runner.JUnitCore ${test_class} ${*@Q}
    exit $?
}

do_test $* 2>&1 | tee $logfile

