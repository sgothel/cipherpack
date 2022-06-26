find_package(JNI REQUIRED)

if (JNI_FOUND)
    message (STATUS "JNI_INCLUDE_DIRS=${JNI_INCLUDE_DIRS}")
    message (STATUS "JNI_LIBRARIES=${JNI_LIBRARIES}")
endif (JNI_FOUND)

set (cipherpack_LIB_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/jaulib/include
    ${AMALGAMATION_ARCH_INC}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/cipherpack
    ${PROJECT_SOURCE_DIR}/java/jni
)

include_directories(
    ${JNI_INCLUDE_DIRS}
    ${cipherpack_LIB_INCLUDE_DIRS}
    ${JNI_HEADER_PATH}
)

set (cipherpack_JNI_SRCS
  ${PROJECT_SOURCE_DIR}/jaulib/java_jni/jni/jni_mem.cxx
  ${PROJECT_SOURCE_DIR}/jaulib/java_jni/jni/helper_jni.cxx
  ${PROJECT_SOURCE_DIR}/jaulib/java_jni/jni/jau/ByteInStream_File.cxx
  ${PROJECT_SOURCE_DIR}/jaulib/java_jni/jni/jau/ByteInStream_URL.cxx
  ${PROJECT_SOURCE_DIR}/jaulib/java_jni/jni/jau/ByteInStream_Feed.cxx
  ${PROJECT_SOURCE_DIR}/jaulib/java_jni/jni/jau/jau_nio_uri.cxx
  ${PROJECT_SOURCE_DIR}/java/jni/helper_base.cxx
  ${PROJECT_SOURCE_DIR}/java/jni/cipherpack/Cipherpack.cxx        
  ${PROJECT_SOURCE_DIR}/java/jni/cipherpack/CipherpackListener.cxx
  ${PROJECT_SOURCE_DIR}/java/jni/cipherpack/CPFactory.cxx
  ${PROJECT_SOURCE_DIR}/java/jni/cipherpack/CPNativeDownlink.cxx   
  ${PROJECT_SOURCE_DIR}/java/jni/cipherpack/CPUtils.cxx
  ${PROJECT_SOURCE_DIR}/java/jni/cipherpack/CipherpackHelper.cxx
)

set (CMAKE_SHARED_LINKER_FLAGS "-Wl,--as-needed")

add_library (javacipherpack SHARED ${cipherpack_JNI_SRCS})
target_link_libraries(javacipherpack ${JNI_LIBRARIES} cipherpack)

if(USE_STRIP)
add_custom_command(TARGET javacipherpack POST_BUILD
                   COMMAND ${STRIP} ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}javacipherpack${CMAKE_SHARED_LIBRARY_SUFFIX}.${cipherpack_VERSION_SHORT}
                   COMMENT "stripping javacipherpack"
                   VERBATIM
                   )
endif(USE_STRIP)

set_target_properties(
    javacipherpack
    PROPERTIES
    SOVERSION ${cipherpack_VERSION_MAJOR}
    VERSION ${cipherpack_VERSION_SHORT}
)

install(TARGETS javacipherpack LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

add_dependencies(javacipherpack cipherpack cipherpack_jar)

