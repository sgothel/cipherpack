# java/CMakeLists.txt

find_jar(JUNIT_JAR
  NAMES junit4 junit
  PATHS "/usr/share/java" "/usr/local/share/java/classes" )

find_jar(HAMCREST_JAR
  NAMES hamcrest-all hamcrest
  PATHS "/usr/share/java" "/usr/local/share/java/classes" )


set(cipherpack_test_jar_file ${CMAKE_CURRENT_BINARY_DIR}/cipherpack-test.jar CACHE FILEPATH "cipherpack test jar file" FORCE)

file(GLOB_RECURSE TEST_JAVA_SOURCES "*.java")

file(GLOB_RECURSE TEST_JAVA_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "Test*.java")

set(CMAKE_JAVA_COMPILE_FLAGS ${cipherpack_JAVA_COMPILE_FLAGS})
add_jar(cipherpack_test
        ${TEST_JAVA_SOURCES}
        INCLUDE_JARS ${jaulib_fat_jar_file} ${cipherpack_fat_jar_file} ${jaulib_test_jar_file} ${JUNIT_JAR} ${HAMCREST_JAR}
        MANIFEST ${CMAKE_CURRENT_BINARY_DIR}/manifest.txt
        OUTPUT_NAME cipherpack-test
)
add_dependencies(cipherpack_test cipherpack_fat_jar jaulib_test)

install (FILES ${cipherpack_test_jar_file} DESTINATION ${CMAKE_INSTALL_LIBDIR}/../lib/java)

string( REPLACE ".java" "" TEST_JAVA_FILES2 "${TEST_JAVA_FILES}" )
string( REPLACE "/" "." BASENAMES_IDIOMATIC_EXAMPLES "${TEST_JAVA_FILES2}" )
set( TARGETS_IDIOMATIC_EXAMPLES ${BASENAMES_IDIOMATIC_EXAMPLES} )

foreach(name ${TARGETS_IDIOMATIC_EXAMPLES})
    add_test (NAME ${name} COMMAND ${JAVA_RUNTIME} 
                           -cp ${JUNIT_JAR}:${HAMCREST_JAR}:${cipherpack_fat_jar_file}:${jaulib_test_jar_file}:${cipherpack_test_jar_file}
                           org.junit.runner.JUnitCore ${name})
endforeach()

