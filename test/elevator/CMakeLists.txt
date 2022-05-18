include_directories(
  ${PROJECT_SOURCE_DIR}/jaulib/include
  ${AMALGAMATION_ARCH_INC}
  ${PROJECT_SOURCE_DIR}/include
)

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
    target_link_libraries(${name} elevator catch2)
    add_dependencies(${name} elevator catch2)
    add_test (NAME ${name} COMMAND ${name})
endforeach()

