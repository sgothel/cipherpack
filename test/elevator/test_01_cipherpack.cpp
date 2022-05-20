/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2021 Gothel Software e.K.
 * Copyright (c) 2021 ZAFENA AB
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <iostream>
#include <cassert>
#include <cinttypes>
#include <cstring>

#include <fstream>
#include <iostream>

#define CATCH_CONFIG_RUNNER
// #define CATCH_CONFIG_MAIN
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
    private:
        const std::string fname_payload = "test_cipher01.bin";
        const std::string fname_encrypted = fname_payload+".enc";
        const std::string fname_decrypted = fname_encrypted+".dec";

    public:
        Test01Cipherpack() {
            // produce fresh demo data

            IOUtil::remove(fname_payload);
            IOUtil::remove(fname_encrypted);
            IOUtil::remove(fname_decrypted);
            {
                std::string one_line = "Hello World, this is a test and I like it. Exactly 100 characters long. 0123456780 abcdefghjklmnop..";
                std::ofstream ofs(fname_payload, std::ios::out | std::ios::binary);

                REQUIRE( ofs.good() == true );
                REQUIRE( ofs.is_open() == true );

                for(int i=0; i < 1024*1000/100; i+=one_line.size()) { // 1MiB
                    ofs.write(reinterpret_cast<char*>(one_line.data()), one_line.size());
                }
            }
        }

        void test01_enc_dec_file_ok() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                Cipherpack::PackInfo pinfo1 = Cipherpack::encryptThenSign_RSA1(enc_pub_keys,
                                                                               sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                               fname_payload, fname_payload, "test_case", 1, 0,
                                                                               fname_encrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo1.toString().c_str());
                REQUIRE( pinfo1.isValid() == true );

                Botan::DataSource_Stream enc_stream(fname_encrypted, true /* use_binary */);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
            {
                Cipherpack::PackInfo pinfo1 = Cipherpack::encryptThenSign_RSA1(enc_pub_keys,
                                                                               sign_sec_key2_fname, sign_sec_key_passphrase,
                                                                               fname_payload, fname_payload, "test_case", 1, 0,
                                                                               fname_encrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo1.toString().c_str());
                REQUIRE( pinfo1.isValid() == true );

                Botan::DataSource_Stream enc_stream(fname_encrypted, true /* use_binary */);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
            {
                Cipherpack::PackInfo pinfo1 = Cipherpack::encryptThenSign_RSA1(enc_pub_keys,
                                                                               sign_sec_key3_fname, sign_sec_key_passphrase,
                                                                               fname_payload, fname_payload, "test_case", 1, 0,
                                                                               fname_encrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo1.toString().c_str());
                REQUIRE( pinfo1.isValid() == true );

                Botan::DataSource_Stream enc_stream(fname_encrypted, true /* use_binary */);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
        }

        void test02_enc_dec_file_error() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            Cipherpack::PackInfo pinfo1 = Cipherpack::encryptThenSign_RSA1(enc_pub_keys,
                                                                           sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                           fname_payload, fname_payload, "test_case", 1, 0,
                                                                           fname_encrypted, overwrite);
            jau::PLAIN_PRINT(true, "test01cipher01: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
            jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo1.toString().c_str());
            REQUIRE( pinfo1.isValid() == true );

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                // Error: Not encrypted for terminal key 4
                Botan::DataSource_Stream enc_stream(fname_encrypted, true /* use_binary */);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == false );
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                Botan::DataSource_Stream enc_stream(fname_encrypted, true /* use_binary */);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys_nope, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == false );
            }
        }

        void test11_dec_http_ok() {
            const std::string uri_encrypted = url_input_root + basename_64kB + ".enc";
            const std::string file_decrypted = basename_64kB+".enc.dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                DataSource_URL enc_stream(uri_encrypted);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
            {
                DataSource_URL enc_stream(uri_encrypted);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
            {
                DataSource_URL enc_stream(uri_encrypted);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
        }

        void test12_dec_http_error() {
            const std::string uri_encrypted = url_input_root + basename_64kB + ".enc";
            const std::string file_decrypted = basename_64kB+".enc.dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                // Error: Not encrypted for terminal key 4
                DataSource_URL enc_stream(uri_encrypted);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == false );
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                DataSource_URL enc_stream(uri_encrypted);
                Cipherpack::PackInfo pinfo2 = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys_nope, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01cipher01: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01cipher01: %s\n", pinfo2.toString().c_str());
                REQUIRE( pinfo2.isValid() == false );
            }
        }
};

METHOD_AS_TEST_CASE( Test01Cipherpack::test01_enc_dec_file_ok,    "Elevator CipherPack 01 test01_enc_dec_file_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test02_enc_dec_file_error, "Elevator CipherPack 01 test02_enc_dec_file_error");

METHOD_AS_TEST_CASE( Test01Cipherpack::test11_dec_http_ok,        "Elevator CipherPack 02 test11_dec_http_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test12_dec_http_error,     "Elevator CipherPack 02 test11_dec_http_error");


