include_directories(
  ${PROJECT_SOURCE_DIR}/jaulib/include
  ${AMALGAMATION_ARCH_INC}
  ${PROJECT_SOURCE_DIR}/include
)

add_executable (cipherpack_exe cipherpack/commandline.cpp)
target_compile_options(cipherpack_exe PUBLIC ${cipherpack_CXX_FLAGS})
target_link_options(cipherpack_exe PUBLIC ${cipherpack_EXE_LINKER_FLAGS})
target_link_libraries (cipherpack_exe cipherpack)
set_target_properties(cipherpack_exe PROPERTIES OUTPUT_NAME cipherpack)
add_dependencies(cipherpack_exe cipherpack)

install(TARGETS cipherpack_exe RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

