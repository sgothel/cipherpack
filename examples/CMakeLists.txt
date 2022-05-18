include_directories(
  ${PROJECT_SOURCE_DIR}/jaulib/include
  ${AMALGAMATION_ARCH_INC}
  ${PROJECT_SOURCE_DIR}/include
)

add_executable (cipherpack cipherpack/cipherpack.cpp)
target_link_libraries (cipherpack elevator)
add_dependencies(cipherpack elevator)

install(TARGETS cipherpack RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

