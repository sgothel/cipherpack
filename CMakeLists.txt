cmake_minimum_required (VERSION 3.13.0 FATAL_ERROR)
project (elevator LANGUAGES C CXX)

if(${CMAKE_VERSION} VERSION_LESS "3.18.0")
    message(STATUS "CMake ${CMAKE_VERSION}, please consider to switch to CMake 3.18.0 or later")
else()
    message(STATUS "CMake ${CMAKE_VERSION} >= 3.18.0, good.")
endif()

FIND_PACKAGE (Threads REQUIRED)

if(NOT DEFINED DONT_USE_RTTI)
    set(DONT_USE_RTTI OFF)
    message(STATUS "${PROJECT_NAME} DONT_USE_RTTI ${DONT_USE_RTTI} (elevator default)")
else()
    message(STATUS "${PROJECT_NAME} DONT_USE_RTTI ${DONT_USE_RTTI} (user)")
endif()

include(jaulib/JaulibSetup.cmake)
JaulibSetup()

# Determine amalgamation platform include director, depnding on OS_ARCH
set(AMALGAMATION_ARCH_INC "${PROJECT_SOURCE_DIR}/include/amalgamation-${OS_ARCH}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -frtti")
set(CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} -frtti")
set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -frtti")

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/version.cpp.in
                ${CMAKE_CURRENT_BINARY_DIR}/src/version.cpp)

# this is the library version, independant of git revision
set (elevator_VERSION_MAJOR ${VERSION_MAJOR})
set (elevator_VERSION_MINOR ${VERSION_MINOR})
set (elevator_VERSION_PATCH ${VERSION_PATCH})
set (elevator_VERSION_STRING "${elevator_VERSION_MAJOR}.${elevator_VERSION_MINOR}.${elevator_VERSION_PATCH}")

set (CMAKE_SWIG_FLAGS "")

set (elevator_DOCS_DIR documentation)

find_path (SYSTEM_USR_DIR "stdlib.h")
include_directories (${SYSTEM_USR_DIR})

add_subdirectory (jaulib)

add_subdirectory (src/elevator)

option (BUILDJAVA "Build Java API." OFF)

IF(BUILDJAVA)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/java/manifest.txt.in ${CMAKE_CURRENT_BINARY_DIR}/java/manifest.txt)
    add_subdirectory (java)
ENDIF(BUILDJAVA)

# add a target to generate API documentation with Doxygen
find_package (Doxygen)
if (DOXYGEN_FOUND)
  configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.cpp.out @ONLY)
  if (BUILDJAVA)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.java.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.java.out @ONLY)
    add_custom_command (OUTPUT ${elevator_DOCS_DIR}/cpp ${elevator_DOCS_DIR}/java
      COMMAND ${CMAKE_COMMAND} -E make_directory ${elevator_DOCS_DIR}
      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.cpp.out
      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.java.out
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/api/tinyb/*.hpp ${CMAKE_CURRENT_SOURCE_DIR}/api/elevator/*.hpp ${CMAKE_CURRENT_SOURCE_DIR}/java/org/elevator/*.java ${CMAKE_CURRENT_SOURCE_DIR}/java/tinyb/dbus/*java ${CMAKE_CURRENT_SOURCE_DIR}/java/jau/elevator/*java
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
    add_custom_target(doc
      DEPENDS ${elevator_DOCS_DIR}/cpp ${elevator_DOCS_DIR}/java)
  else ()
    add_custom_command (OUTPUT ${elevator_DOCS_DIR}/cpp
      COMMAND ${CMAKE_COMMAND} -E make_directory ${elevator_DOCS_DIR}
      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.cpp.out
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/api/
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
    add_custom_target(doc
      DEPENDS ${elevator_DOCS_DIR}/cpp)
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
  add_subdirectory (test/elevator)
  if (BUILDJAVA)
      configure_file (${CMAKE_CURRENT_SOURCE_DIR}/test/java/manifest.txt.in ${CMAKE_CURRENT_BINARY_DIR}/test/java/manifest.txt)
      add_subdirectory (test/java)
  endif(BUILDJAVA)
endif(BUILD_TESTING)


