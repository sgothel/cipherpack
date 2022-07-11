# java/CMakeLists.txt

#                    COMMAND ${CMAKE_COMMAND} 
#                            -DOS_AND_ARCH=${OS_AND_ARCH}
#                            -Dos_and_arch_slash=${os_and_arch_slash}
#                            -Dos_and_arch_dot=${os_and_arch_dot}
#                            -D_jarfile=${CMAKE_CURRENT_BINARY_DIR}/jaulib_jni-natives-${OS_AND_ARCH}.jar
#                            -D_workdir=${CMAKE_CURRENT_BINARY_DIR}
#                            -D_module=jni
#                            -P ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/modules/MakeNativeJar.cmake

# set(cipherpack_jar_file ${CMAKE_CURRENT_BINARY_DIR}/cipherpack.jar CACHE FILEPATH "cipherpack jar file" FORCE)
set(cipherpack_fat_jar_file ${CMAKE_CURRENT_BINARY_DIR}/cipherpack-fat.jar CACHE FILEPATH "cipherpack fat jar file" FORCE)
set(cipherpack_java_src_file ${CMAKE_CURRENT_BINARY_DIR}/cipherpack-java-src.zip CACHE FILEPATH "cipherpack java source file" FORCE)

add_custom_command (OUTPUT ${cipherpack_fat_jar_file} ${cipherpack_java_src_file}
                    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                    COMMAND ${CMAKE_COMMAND}
                            -D_srcdir=${CMAKE_CURRENT_BINARY_DIR}/../src/cipherpack
                            -D_dstdir=${CMAKE_CURRENT_BINARY_DIR}/natives/${OS_AND_ARCH}
                            -D_srcbasename=${CMAKE_SHARED_LIBRARY_PREFIX}cipherpack${CMAKE_SHARED_LIBRARY_SUFFIX}.${cipherpack_VERSION_SHORT}
                            -D_dstbasename=${CMAKE_SHARED_LIBRARY_PREFIX}cipherpack${CMAKE_SHARED_LIBRARY_SUFFIX}
                            -P ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/modules/FileCopyS2D.cmake
                    COMMAND ${CMAKE_COMMAND}
                            -D_srcdir=${CMAKE_CURRENT_BINARY_DIR}/../java/jni/cipherpack
                            -D_dstdir=${CMAKE_CURRENT_BINARY_DIR}/natives/${OS_AND_ARCH}
                            -D_srcbasename=${CMAKE_SHARED_LIBRARY_PREFIX}javacipherpack${CMAKE_SHARED_LIBRARY_SUFFIX}.${cipherpack_VERSION_SHORT}
                            -D_dstbasename=${CMAKE_SHARED_LIBRARY_PREFIX}javacipherpack${CMAKE_SHARED_LIBRARY_SUFFIX}
                            -P ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/modules/FileCopyS2D.cmake
                    COMMAND ${CMAKE_COMMAND}
                            -D _dstdir:PATH='${CMAKE_CURRENT_BINARY_DIR}/temp'
                            -D _archives:FILEPATH="${jaulib_fat_jar_file}"
                            -P ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/modules/ExtractArchiveList.cmake

                    COMMAND ${CMAKE_COMMAND}
                            -D_srcdir=${CMAKE_CURRENT_BINARY_DIR}/../java/${CMAKE_FILES_DIRECTORY}/cipherpack_jar.dir/org
                            -D_dstdir=${CMAKE_CURRENT_BINARY_DIR}/temp
                            -P ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/modules/DirCopy.cmake

                    COMMAND ${JAR}
                       --create --file ${cipherpack_fat_jar_file}
                       --manifest ${CMAKE_CURRENT_BINARY_DIR}/manifest-fat.txt
                       -C ${CMAKE_CURRENT_BINARY_DIR}/temp/ jau
                       -C ${CMAKE_CURRENT_BINARY_DIR}/temp/ org
                       -C ${CMAKE_CURRENT_BINARY_DIR}/temp/ natives
                       -C ${CMAKE_CURRENT_BINARY_DIR}/ natives

                    COMMAND ${JAR}
                       --create --file ${cipherpack_java_src_file}
                       --no-manifest
                       -C ${PROJECT_SOURCE_DIR}/java org
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_base org/jau/util/BasicTypes.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/sys/Clock.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/io/PrintUtil.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/io/MemUtil.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/io/ByteInStream.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/io/ByteInStream_File.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/io/ByteInStream_URL.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/io/ByteInStream_Feed.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/io/ByteInStreamUtil.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/io/UriTk.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/fs/CopyOptions.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/fs/DirItem.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/fs/FileStats.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/fs/FileUtil.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/fs/FMode.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/fs/TraverseEvent.java
                       -C ${PROJECT_SOURCE_DIR}/jaulib/java_jni org/jau/fs/TraverseOptions.java
                    DEPENDS jaulib_fat_jar cipherpack cipherpack_jar javacipherpack
                    COMMENT "producing cipherpack [fat] jar files and its java source zip"
                    VERBATIM
                   )

add_custom_target (cipherpack_fat_jar ALL 
                   DEPENDS ${cipherpack_fat_jar_file} ${cipherpack_java_src_file}
                  )

add_dependencies(cipherpack_fat_jar jaulib_fat_jar cipherpack cipherpack_jar javacipherpack)

install (FILES ${cipherpack_fat_jar_file} ${cipherpack_java_src_file} DESTINATION ${CMAKE_INSTALL_LIBDIR}/../lib/java)


