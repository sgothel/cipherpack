/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#include <iostream>
#include <cassert>
#include <cinttypes>
#include <cstring>

#include <fstream>
#include <iostream>

// #define CATCH_CONFIG_RUNNER
#define CATCH_CONFIG_MAIN
#include <catch2/catch_amalgamated.hpp>
#include <jau/test/catch2_ext.hpp>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

extern "C" {
    #include <unistd.h>
}

using namespace elevator;

TEST_CASE( "Elevator Test 01 IOStream", "[io][stream]" ) {

    // const std::string url_input("http://jordan/deployment/data-382MB.mkv.enc");
    const std::string url_input("http://jordan/deployment/data-64kB.bin.enc");

    Botan::secure_vector<uint8_t> buffer(4096);
    ssize_t calls0 = 0;
    ssize_t total0 = 0;
    auto consume = [&](Botan::secure_vector<uint8_t>& data, bool is_final) noexcept {
        calls0++;
        total0 += data.size();
        jau::PLAIN_PRINT("test", "#% " PRIi64 ": consumed size % " PRIu64 ", total %" PRIi64 ", capacity %" PRIu64 ", final %d",
                calls0, data.size(), total0, data.capacity(), is_final );
    };
    ssize_t total1 = IOUtil::read_http_get(url_input, buffer, consume);

    REQUIRE( total0 == total1 );
}
