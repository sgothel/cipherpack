prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${exec_prefix}/lib@LIB_SUFFIX@
includedir=${prefix}/include/elevator

Name: elevator
Description: An Upgrade Process Library
Version: @elevator_VERSION_STRING@

Libs: -L${libdir} -lelevator
Cflags: -I${includedir}
