cmake_minimum_required (VERSION 3.13.0 FATAL_ERROR)
set(USE_LIBCURL ON CACHE BOOL "" FORCE)
include(jaulib/JaulibSetup.cmake)
JaulibPreset()

project (cipherpack LANGUAGES C CXX)

set (THREADS_PREFER_PTHREAD_FLAG ON)
find_package (Threads REQUIRED)

# set(CMAKE_MESSAGE_LOG_LEVEL DEBUG)


if(NOT DEFINED DONT_USE_RTTI)
    set(DONT_USE_RTTI OFF)
    message(STATUS "${PROJECT_NAME} DONT_USE_RTTI ${DONT_USE_RTTI} (cipherpack default)")
else()
    message(STATUS "${PROJECT_NAME} DONT_USE_RTTI ${DONT_USE_RTTI} (user)")
endif()

JaulibSetup()

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.clangd)
# Fixup clangd w/ absolute path
set (cipherpack_clangd_source_args "-isystem, ${CMAKE_CURRENT_SOURCE_DIR}/jaulib/include, -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/jaulib/src, -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/jaulib/java_jni/jni, -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/jaulib/java_jni/jni/jau, -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/jaulib/test")
set (cipherpack_clangd_source_args "${cipherpack_clangd_source_args} -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/include, -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/src/cipherpack, -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/java/jni, -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/java/jni/cipherpack, -isystem, ${CMAKE_CURRENT_SOURCE_DIR}/test/cipherpack")
configure_file (${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/clangd.in
                ${CMAKE_CURRENT_SOURCE_DIR}/.clangd)
endif()

# Determine amalgamation platform include director, depnding on OS_NAME and OS_ARCH
set(AMALGAMATION_ARCH_INC "${PROJECT_SOURCE_DIR}/include/amalgamation-${OS_NAME}-${OS_ARCH}")

# this is the library version, derived from git tag and revision
set (cipherpack_VERSION_MAJOR      ${VERSION_MAJOR})
set (cipherpack_VERSION_MINOR      ${VERSION_MINOR})
set (cipherpack_VERSION_PATCH      ${VERSION_PATCH})
set (cipherpack_VERSION_COMMITS    ${VERSION_COMMITS})
set (cipherpack_VERSION_SHA1       ${VERSION_SHA1})
set (cipherpack_VERSION_SHA1_SHORT ${VERSION_SHA1_SHORT})
set (cipherpack_GIT_DIRTY          ${GIT_WORKDIR_DIRTY})
set (cipherpack_VERSION_LONG       ${VERSION_LONG})
set (cipherpack_VERSION_SHORT      ${VERSION_SHORT})
set (cipherpack_VERSION_API        ${VERSION_API})

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/version.cpp.in
                ${CMAKE_CURRENT_BINARY_DIR}/src/version.cpp)

set (CMAKE_SWIG_FLAGS "")

set (cipherpack_DOCS_DIR documentation)

find_path (SYSTEM_USR_DIR "stdlib.h")
include_directories (${SYSTEM_USR_DIR})

add_subdirectory (jaulib)

add_subdirectory (src/cipherpack)

option (BUILDJAVA "Build Java API." OFF)

IF(BUILDJAVA)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/java/manifest.txt.in ${CMAKE_CURRENT_BINARY_DIR}/java/manifest.txt)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/java_fat/manifest-fat.txt.in ${CMAKE_CURRENT_BINARY_DIR}/java_fat/manifest-fat.txt)
    add_subdirectory (java)
    add_subdirectory (java_fat)
ENDIF(BUILDJAVA)

# add a target to generate API documentation with Doxygen
find_package (Doxygen)
if (DOXYGEN_FOUND)
  configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.cpp.out @ONLY)
  if (BUILDJAVA)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.java.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.java.out @ONLY)
    add_custom_command (OUTPUT ${cipherpack_DOCS_DIR}/cpp ${cipherpack_DOCS_DIR}/java
      COMMAND ${CMAKE_COMMAND} -E make_directory ${cipherpack_DOCS_DIR}
      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.cpp.out
      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.java.out
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/ ${CMAKE_CURRENT_SOURCE_DIR}/java/org/cipherpack/*.java
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
    add_custom_target(doc
      DEPENDS ${cipherpack_DOCS_DIR}/cpp ${cipherpack_DOCS_DIR}/java)
  else ()
    add_custom_command (OUTPUT ${cipherpack_DOCS_DIR}/cpp
      COMMAND ${CMAKE_COMMAND} -E make_directory ${cipherpack_DOCS_DIR}
      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.cpp.out
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
    add_custom_target(doc
      DEPENDS ${cipherpack_DOCS_DIR}/cpp)
  endif ()
endif (DOXYGEN_FOUND)

if (BUILDEXAMPLES)
  add_subdirectory (examples)
  if (BUILDJAVA)
      add_subdirectory (examples/java)
  endif(BUILDJAVA)
endif (BUILDEXAMPLES)

if (BUILD_TESTING)
  enable_testing ()
  add_subdirectory (test/cipherpack)
  if (BUILDJAVA)
      configure_file (${CMAKE_CURRENT_SOURCE_DIR}/test/java/manifest.txt.in ${CMAKE_CURRENT_BINARY_DIR}/test/java/manifest.txt)
      add_subdirectory (test/java)
  endif(BUILDJAVA)
endif(BUILD_TESTING)


