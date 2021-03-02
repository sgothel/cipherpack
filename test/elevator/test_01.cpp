#include <iostream>
#include <cassert>
#include <cinttypes>
#include <cstring>

#define CATCH_CONFIG_RUNNER
// #define CATCH_CONFIG_MAIN
#include <catch2/catch_amalgamated.hpp>
#include <jau/test/catch2_ext.hpp>

#include <elevator/elevator.hpp>

using namespace elevator;

TEST_CASE( "Elevator Test 01", "[nop][none]" ) {
    std::cout << "Hello COUT" << std::endl;
    std::cerr << "Hello CERR" << std::endl;
}
