include_directories(
  ${PROJECT_SOURCE_DIR}/jaulib/include
  ${PROJECT_SOURCE_DIR}/botan/dist-amd64-min
#  ${PROJECT_SOURCE_DIR}/botan/dist-amd64-min/include/botan-3
  ${PROJECT_SOURCE_DIR}/include
)

# add_executable (pack pack/pack.cpp)
# target_link_libraries (pack elevator)
# add_dependencies(pack elevator)

add_executable (cipherpack cipherpack/cipherpack.cpp)
target_link_libraries (cipherpack elevator)
add_dependencies(cipherpack elevator)

install(TARGETS cipherpack RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

