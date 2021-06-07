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

TEST_CASE( "Elevator Test 01 CipherPack", "[pack][cipher]" ) {

    const bool overwrite = true;
    const std::string enc_pub_key_fname("../../../keys/terminal_rsa.pub.pem");
    const std::string dec_sec_key_fname("../../../keys/terminal_rsa");
    const std::string dec_sec_key_passphrase("");
    const std::string sign_pub_key_fname("../../../keys/host_rsa.pub.pem");
    const std::string sign_sec_key_fname("../../../keys/host_rsa");
    const std::string sign_sec_key_passphrase("");
    const std::string fname_payload("payload_test01.bin");
    const std::string fname_encrypted(fname_payload+".enc");
    const std::string fname_decrypted(fname_encrypted+".dec");

    // produce fresh demo data
    IOUtil::remove(fname_payload);
    {
        std::string one_line = "Hello World, this is a test and I like it. Exactly 100 characters long. 0123456780 abcdefghjklmnop. ";
        std::ofstream ofs(fname_payload, std::ios::out | std::ios::binary);

        REQUIRE( ofs.good() == true );
        REQUIRE( ofs.is_open() == true );

        for(int i=0; i < 3*4096; i+=one_line.size()) {
            ofs.write(reinterpret_cast<char*>(one_line.data()), one_line.size());
        }
    }

    bool res_enc = Cipherpack::encryptThenSign_RSA1(enc_pub_key_fname, sign_sec_key_fname, sign_sec_key_passphrase, fname_payload, fname_encrypted, overwrite);
    jau::fprintf_td(stderr, "Encrypt1 result: Output encrypted file %s: Result %d\n", fname_encrypted.c_str(), res_enc);
    REQUIRE( res_enc == true );

    bool res_dec = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_key_fname, dec_sec_key_fname, dec_sec_key_passphrase, fname_encrypted, fname_decrypted, overwrite);
    jau::fprintf_td(stderr, "Decrypted1 result: Output decrypted file %s: Result %d\n", fname_decrypted.c_str(), res_dec);
    REQUIRE( res_dec == true );
}
