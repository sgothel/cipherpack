# java/CMakeLists.txt

set(cipherpack_jar_file ${CMAKE_CURRENT_BINARY_DIR}/cipherpack.jar CACHE FILEPATH "cipherpack jar file" FORCE)

set(CMAKE_JNI_TARGET TRUE)
file(GLOB_RECURSE JAVA_SOURCES "*.java")

set(CMAKE_JAVA_COMPILE_FLAGS ${cipherpack_JAVA_COMPILE_FLAGS})
add_jar(cipherpack_jar 
        ${JAVA_SOURCES}
        ${PROJECT_SOURCE_DIR}/jaulib/java_base/org/jau/util/BasicTypes.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_base/org/jau/util/BaseCodec.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/sys/Clock.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/PrintUtil.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/MemUtil.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/IOStateFunc.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/ByteInStream.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/ByteInStream_File.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/ByteInStream_URL.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/ByteInStream_Feed.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/ByteInStreamUtil.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/ByteOutStream.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/ByteOutStream_File.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/io/UriTk.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/CopyOptions.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/DirItem.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/FileStats.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/FileUtil.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/FMode.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/MountFlags.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/TraverseEvent.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/TraverseOptions.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/UnmountFlags.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/linux/MountFlags.java
        ${PROJECT_SOURCE_DIR}/jaulib/java_jni/org/jau/fs/linux/UnmountFlags.java
        INCLUDE_JARS ${jaulib_fat_jar_file}
        MANIFEST ${CMAKE_CURRENT_BINARY_DIR}/manifest.txt
        OUTPUT_NAME cipherpack
        GENERATE_NATIVE_HEADERS javacipherpack_javah
            DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/cipherpack_jar.dir/jni"
)
add_dependencies(cipherpack_jar jaulib_fat_jar)

# JNI header generation is satisfied by above 'add_jar(.. GENERATE_NATIVE_HEADERS <target> DESTINATION <dir>)',
# note that its GENERATE_NATIVE_HEADERS target is a dummy target, since jni/cipherpack defines target javacipherpack.
# Weakness of not directly checking build dependency of javacipherpack against generated headers exists,
# however, it is unrealistic to assume that the transient generated JNI header will be edited manually
# within the process.
# Therefor we can use the dummy target javacipherpack_javah and JNI header generation will only
# occur when java sources have been modified, i.e. the jar file being actually build.
#
#add_custom_command (TARGET cipherpack_jar
#  POST_BUILD
#  COMMAND ${CMAKE_COMMAND} -E echo "Generating JNI headers.."
#  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/cipherpack_jar.dir"
#  COMMAND ${JAVAC} -h jni/ ${JAVA_SOURCES}
#)

set(JNI_HEADER_PATH "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/cipherpack_jar.dir/jni")
install (FILES ${cipherpack_jar_file} DESTINATION ${CMAKE_INSTALL_LIBDIR}/../lib/java)

add_subdirectory (jni/cipherpack)

