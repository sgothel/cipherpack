/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#include <iostream>
#include <cassert>
#include <cinttypes>
#include <cstring>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

extern "C" {
    #include <unistd.h>
}

using namespace elevator;

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "Elevate ...\n");

#if 0
    const bool overwrite = true;
    const bool verbose = true;
    const std::string fname_payload("payload_101.bin");
    const std::string fname_package("package_101.bin");
    const uint32_t pversion(101);
    const uint32_t pversion_parent(0);
    const std::string fname_payload_copy("payload_101_copy.bin");

    Package pack_out = Package::pack(fname_payload, pversion, pversion_parent, fname_package, overwrite, verbose);
    jau::fprintf_td(stderr, "Pack result: Output package file %s: %s\n", fname_package.c_str(), pack_out.toString().c_str());

    if( pack_out.isValid() ) {
        Package pack_in = Package::unpack(fname_package, fname_payload_copy, overwrite, verbose);
        jau::fprintf_td(stderr, "Unpack result: Output payload file %s: %s\n", fname_payload_copy.c_str(), pack_in.toString().c_str());
    }
#else
    const bool overwrite = true;
    const std::string fname_pubkey("dummy_rsa.pub.pem");
    const std::string fname_payload("payload_102.bin");
    const std::string fname_encder("payload_102.enc");

    bool res = Cipherpack::encrypt_RSA(fname_pubkey, fname_payload, fname_encder, overwrite);
    jau::fprintf_td(stderr, "Encrypt result: Output encder file %s: Result %d\n", fname_encder.c_str(), res);

#endif
    return 0;
}
