# examples/java/CMakeLists.txt
find_package(Java REQUIRED)
include(UseJava)

# These examples use the standard separate compilation
set( SOURCES_IDIOMATIC_EXAMPLES
    Cipherpack.java
)

string( REPLACE ".java" "" BASENAMES_IDIOMATIC_EXAMPLES "${SOURCES_IDIOMATIC_EXAMPLES}" )
set( TARGETS_IDIOMATIC_EXAMPLES ${BASENAMES_IDIOMATIC_EXAMPLES} )

string( REPLACE ".java" ".jar" BASENAMES_IDIOMATIC_EXAMPLE_JARS "${SOURCES_IDIOMATIC_EXAMPLES}" )
set( TARGETS_IDIOMATIC_EXAMPLE_JARS ${BASENAMES_IDIOMATIC_EXAMPLE_JARS} )

foreach( name ${TARGETS_IDIOMATIC_EXAMPLES} )
    set(CMAKE_JAVA_COMPILE_FLAGS ${cipherpack_JAVA_COMPILE_FLAGS})
    add_jar(${name} SOURCES ${name}.java INCLUDE_JARS cipherpack_jar ENTRY_POINT Notification)
    add_custom_command(TARGET ${name}
            POST_BUILD
            COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_FILES_DIRECTORY}/${name}.dir/${name}.class" "${CMAKE_CURRENT_BINARY_DIR}"
    )
    add_dependencies(${name} cipherpack_jar)
    install_jar(${name} DESTINATION ${CMAKE_INSTALL_BINDIR}/java)
endforeach()

