include_directories(
  ${PROJECT_SOURCE_DIR}/jaulib/include
  ${PROJECT_SOURCE_DIR}/jaulib/include/catch2_jau
  ${AMALGAMATION_ARCH_INC}
  ${PROJECT_SOURCE_DIR}/include
)

# These examples use the standard separate compilation
file(GLOB_RECURSE SOURCES_IDIOMATIC_EXAMPLES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "test_*.cpp")

string( REPLACE ".cpp" "" BASENAMES_IDIOMATIC_EXAMPLES "${SOURCES_IDIOMATIC_EXAMPLES}" )
set( TARGETS_IDIOMATIC_EXAMPLES ${BASENAMES_IDIOMATIC_EXAMPLES} )

foreach( name ${TARGETS_IDIOMATIC_EXAMPLES} )
    add_executable(${name} ${name}.cpp data_test.cpp)
    target_compile_options(${name} PUBLIC ${cipherpack_CXX_FLAGS})
    target_link_options(${name} PUBLIC ${cipherpack_EXE_LINKER_FLAGS})
    target_link_libraries(${name} cipherpack catch2)
    add_dependencies(${name} cipherpack catch2)
    add_test (NAME ${name} COMMAND ${name})
    if(DEFINED CMAKE_CXX_CLANG_TIDY)
        set_target_properties(${name} PROPERTIES CXX_CLANG_TIDY "${CMAKE_CXX_CLANG_TIDY};--checks;-bugprone-chained-comparison")
    endif()
endforeach()

