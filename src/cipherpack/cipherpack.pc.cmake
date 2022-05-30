prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${exec_prefix}/lib@LIB_SUFFIX@
includedir=${prefix}/include/cipherpack

Name: cipherpack
Description: Cipherpack library
Version: @cipherpack_VERSION_STRING@

Libs: -L${libdir} -lcipherpack
Cflags: -I${includedir}
