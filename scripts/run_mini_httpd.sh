#!/bin/sh

sdir=`dirname $(readlink -f $0)`
rootdir=`dirname $sdir`
bname=`basename $0 .sh`

. $sdir/setup-machine-arch.sh

echo killall minihttpd
killall mini_httpd
echo killall minihttpd
killall mini_httpd
echo launch minihttpd
cd $rootdir
/usr/sbin/mini_httpd -p 8080 -l $rootdir/mini_httpd-$archabi.log

