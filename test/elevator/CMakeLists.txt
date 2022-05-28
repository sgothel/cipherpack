include_directories(
  ${PROJECT_SOURCE_DIR}/jaulib/include
  ${AMALGAMATION_ARCH_INC}
  ${PROJECT_SOURCE_DIR}/include
)

# These examples use the standard separate compilation
file(GLOB_RECURSE SOURCES_IDIOMATIC_EXAMPLES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "test_*.cpp")

string( REPLACE ".cpp" "" BASENAMES_IDIOMATIC_EXAMPLES "${SOURCES_IDIOMATIC_EXAMPLES}" )
set( TARGETS_IDIOMATIC_EXAMPLES ${BASENAMES_IDIOMATIC_EXAMPLES} )

foreach( name ${TARGETS_IDIOMATIC_EXAMPLES} )
    add_executable(${name} ${name}.cpp data_test.cpp)
    target_link_libraries(${name} elevator catch2)
    add_dependencies(${name} elevator catch2)
    add_test (NAME ${name} COMMAND ${name})
endforeach()

