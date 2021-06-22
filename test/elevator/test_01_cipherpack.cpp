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

#include "test_data.hpp"

#include <jau/debug.hpp>

extern "C" {
    #include <unistd.h>
}

using namespace elevator;

class Test01Cipherpack : public TestData {
    public:
        static void test01() {
            // produce fresh demo data
            const std::string fname_payload = "test01cipher01.bin";
            const std::string fname_encrypted = fname_payload+".enc";
            const std::string fname_decrypted = fname_encrypted+".dec";

            IOUtil::remove(fname_payload);
            {
                std::string one_line = "Hello World, this is a test and I like it. Exactly 100 characters long. 0123456780 abcdefghjklmnop. ";
                std::ofstream ofs(fname_payload, std::ios::out | std::ios::binary);

                REQUIRE( ofs.good() == true );
                REQUIRE( ofs.is_open() == true );

                for(int i=0; i < 1024*1000/100; i+=one_line.size()) { // 1MiB
                    ofs.write(reinterpret_cast<char*>(one_line.data()), one_line.size());
                }
            }

            Cipherpack::PackInfo pinfo1 = Cipherpack::encryptThenSign_RSA1(enc_pub_key_fname, sign_sec_key_fname, sign_sec_key_passphrase,
                                                                           fname_payload, fname_payload, 1, 0,
                                                                           fname_encrypted, overwrite);
            jau::PLAIN_PRINT(true, "test01cipher01: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
            jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo1.toString().c_str());
            REQUIRE( pinfo1.isValid() == true );

            Botan::DataSource_Stream enc_stream(fname_encrypted, true /* use_binary */);
            Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_key_fname, dec_sec_key_fname, dec_sec_key_passphrase,
                                                                                enc_stream, fname_decrypted, overwrite);
            jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
            jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
            REQUIRE( pinfo2.isValid() == true );
        }

        static void test02() {
            const std::string uri_encrypted = url_input_root + basename_64kB + ".enc";
            const std::string file_decrypted = basename_64kB+".enc.dec";

            DataSource_URL enc_stream(uri_encrypted);
            Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_key_fname, dec_sec_key_fname, dec_sec_key_passphrase,
                                                                                enc_stream, file_decrypted, overwrite);
            jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
            jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
            REQUIRE( pinfo2.isValid() == true );
        }
};

METHOD_AS_TEST_CASE( Test01Cipherpack::test01, "Elevator Test 01 CipherPack 01");
METHOD_AS_TEST_CASE( Test01Cipherpack::test02, "Elevator Test 01 CipherPack 02");

