#!/bin/sh

export elevator_debug=true
export elevator_verbose=true
#
# ../scripts/run-cipherpack.sh some_plaintext_file.bin 
#

if [ ! -e bin/cipherpack -o ! -e lib/libelevator.so ] ; then
    echo run from dist directory
    exit 1
fi
ulimit -c unlimited

# run as root 'dpkg-reconfigure locales' enable 'en_US.UTF-8'
# perhaps run as root 'update-locale LC_MEASUREMENT=en_US.UTF-8 LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8'
export LC_MEASUREMENT=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

echo COMMANDLINE $0 $*
echo elevator_debug $elevator_debug
echo elevator_verbose $elevator_verbose

#LD_LIBRARY_PATH=`pwd`/lib strace bin/cipherpack $*
LD_LIBRARY_PATH=`pwd`/lib bin/cipherpack $*
