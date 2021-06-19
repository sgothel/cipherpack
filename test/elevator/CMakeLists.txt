include_directories(
  ${PROJECT_SOURCE_DIR}/jaulib/include
  ${AMALGAMATION_ARCH_INC}
  ${PROJECT_SOURCE_DIR}/include
)

set (catch2l_LIB_SRCS
  ${PROJECT_SOURCE_DIR}/jaulib/include/catch2/catch_amalgamated.cpp
)

add_library (catch2l STATIC ${catch2l_LIB_SRCS})

if(CMAKE_COMPILER_IS_GNUCC)
target_compile_options(catch2l PUBLIC "-Wno-error=format-overflow")
endif(CMAKE_COMPILER_IS_GNUCC)

# These examples use the standard separate compilation
set( SOURCES_IDIOMATIC_EXAMPLES
    test_01.cpp
    test_01_cipherpack.cpp
    test_02_iostream.cpp
)

string( REPLACE ".cpp" "" BASENAMES_IDIOMATIC_EXAMPLES "${SOURCES_IDIOMATIC_EXAMPLES}" )
set( TARGETS_IDIOMATIC_EXAMPLES ${BASENAMES_IDIOMATIC_EXAMPLES} )

foreach( name ${TARGETS_IDIOMATIC_EXAMPLES} )
    add_executable(${name} ${name}.cpp test_data.cpp)
    target_link_libraries(${name} elevator catch2l)
    add_dependencies(${name} elevator catch2l)
    add_test (NAME ${name} COMMAND ${name})
endforeach()

