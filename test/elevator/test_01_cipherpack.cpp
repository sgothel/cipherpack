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

                for(int i=0; i < 3*4096; i+=one_line.size()) {
                    ofs.write(reinterpret_cast<char*>(one_line.data()), one_line.size());
                }
            }

            bool res_enc = Cipherpack::encryptThenSign_RSA1(enc_pub_key_fname, sign_sec_key_fname, sign_sec_key_passphrase, fname_payload, fname_encrypted, overwrite);
            jau::PLAIN_PRINT(true, "test01cipher01 Encrypt1 result: Output encrypted file %s: Result %d\n", fname_encrypted.c_str(), res_enc);
            REQUIRE( res_enc == true );

            Botan::DataSource_Stream enc_stream(fname_encrypted, true /* use_binary */);
            bool res_dec = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_key_fname, dec_sec_key_fname, dec_sec_key_passphrase, enc_stream, fname_decrypted, overwrite);
            jau::PLAIN_PRINT(true, "test01cipher01 Decrypted1 result: Output decrypted file %s: Result %d\n", fname_decrypted.c_str(), res_dec);
            REQUIRE( res_dec == true );
        }

        static void test02() {
            // produce fresh demo data
            const std::string fname_payload = "test01cipher02.bin";
            const std::string fname_encrypted = fname_payload+".enc";
            const std::string fname_decrypted = fname_encrypted+".dec";

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
            jau::PLAIN_PRINT(true, "test01cipher02 Encrypt1 result: Output encrypted file %s: Result %d\n", fname_encrypted.c_str(), res_enc);
            REQUIRE( res_enc == true );

            Botan::DataSource_Stream enc_stream(fname_encrypted, true /* use_binary */);
            bool res_dec = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_key_fname, dec_sec_key_fname, dec_sec_key_passphrase, enc_stream, fname_decrypted, overwrite);
            jau::PLAIN_PRINT(true, "test01cipher02 Decrypted1 result: Output decrypted file %s: Result %d\n", fname_decrypted.c_str(), res_dec);
            REQUIRE( res_dec == true );
        }
};

METHOD_AS_TEST_CASE( Test01Cipherpack::test01, "Elevator Test 01 CipherPack 01");
METHOD_AS_TEST_CASE( Test01Cipherpack::test02, "Elevator Test 01 CipherPack 02");

