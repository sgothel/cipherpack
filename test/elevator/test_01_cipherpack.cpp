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
#include <jau/file_util.hpp>

extern "C" {
    #include <unistd.h>
}

using namespace elevator;
using namespace jau::fractions_i64_literals;

class Test01Cipherpack : public TestData {
    private:
        const std::string fname_payload = "test_cipher01.bin";
        const std::string fname_encrypted = fname_payload+".enc";
        const std::string fname_decrypted = fname_encrypted+".dec";

    public:
        Test01Cipherpack() {
            // produce fresh demo data

            jau::fs::remove(fname_payload, false /* recursive */);
            jau::fs::remove(fname_encrypted, false /* recursive */);
            jau::fs::remove(fname_decrypted, false /* recursive */);
            {
                std::string one_line = "Hello World, this is a test and I like it. Exactly 100 characters long. 0123456780 abcdefghjklmnop..";
                std::ofstream ofs(fname_payload, std::ios::out | std::ios::binary);

                REQUIRE( ofs.good() == true );
                REQUIRE( ofs.is_open() == true );

                for(int i=0; i < 1024*10; i+=one_line.size()) { // 10kiB
                    ofs.write(reinterpret_cast<char*>(one_line.data()), one_line.size());
                }
            }
        }

        void test01_enc_dec_file_ok() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                cipherpack::PackInfo pinfo1 = cipherpack::encryptThenSign_RSA1(cipherpack::CryptoConfig::getDefault(),
                                                                               enc_pub_keys,
                                                                               sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                               fname_payload, fname_payload, "test_case", 1, 0,
                                                                               fname_encrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", pinfo1.toString(true, true).c_str());
                REQUIRE( pinfo1.isValid() == true );

                io::ByteStream_File enc_stream(fname_encrypted, true /* use_binary */);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
            {
                cipherpack::PackInfo pinfo1 = cipherpack::encryptThenSign_RSA1(cipherpack::CryptoConfig::getDefault(),
                                                                               enc_pub_keys,
                                                                               sign_sec_key2_fname, sign_sec_key_passphrase,
                                                                               fname_payload, fname_payload, "test_case", 1, 0,
                                                                               fname_encrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", pinfo1.toString(true, true).c_str());
                REQUIRE( pinfo1.isValid() == true );

                io::ByteStream_File enc_stream(fname_encrypted, true /* use_binary */);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
            {
                cipherpack::PackInfo pinfo1 = cipherpack::encryptThenSign_RSA1(cipherpack::CryptoConfig::getDefault(),
                                                                               enc_pub_keys,
                                                                               sign_sec_key3_fname, sign_sec_key_passphrase,
                                                                               fname_payload, fname_payload, "test_case", 1, 0,
                                                                               fname_encrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", pinfo1.toString(true, true).c_str());
                REQUIRE( pinfo1.isValid() == true );

                io::ByteStream_File enc_stream(fname_encrypted, true /* use_binary */);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
        }

        void test02_enc_dec_file_error() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            cipherpack::PackInfo pinfo1 = cipherpack::encryptThenSign_RSA1(cipherpack::CryptoConfig::getDefault(),
                                                                           enc_pub_keys,
                                                                           sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                           fname_payload, fname_payload, "test_case", 1, 0,
                                                                           fname_encrypted, overwrite);
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", pinfo1.toString(true, true).c_str());
            REQUIRE( pinfo1.isValid() == true );

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                // Error: Not encrypted for terminal key 4
                io::ByteStream_File enc_stream(fname_encrypted, true /* use_binary */);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == false );
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                io::ByteStream_File enc_stream(fname_encrypted, true /* use_binary */);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys_nope, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, fname_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == false );
            }
        }

        void test11_dec_http_ok() {
            const std::string uri_encrypted = url_input_root + basename_10kiB + ".enc";
            const std::string file_decrypted = basename_64kB+".enc.dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                io::ByteStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
            {
                io::ByteStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
            {
                io::ByteStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == true );
            }
        }

        void test12_dec_http_error() {
            const std::string uri_encrypted = url_input_root + basename_10kiB + ".enc";
            const std::string file_decrypted = basename_64kB+".enc.dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                // Error: Not encrypted for terminal key 4
                io::ByteStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test12_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test12_dec_http_error: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == false );
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                io::ByteStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys_nope, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                                    enc_stream, file_decrypted, overwrite);
                jau::PLAIN_PRINT(true, "test12_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test12_dec_http_error: %s\n", pinfo2.toString(true, true).c_str());
                REQUIRE( pinfo2.isValid() == false );
            }
        }

        // throttled, no content size
        static void feed_source_00(io::ByteStream_Feed * enc_feed) {
            uint64_t xfer_total = 0;
            io::ByteStream_File enc_stream(enc_feed->id(), true /* use_binary */);
            while( !enc_stream.end_of_data() ) {
                uint8_t buffer[1024]; // 1k
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                    jau::sleep_for( 100_ms );
                }
            }
            // probably set after decryption due to above sleep, which also ends when total size has been reached.
            enc_feed->set_eof( io::result_t::SUCCESS );
        }

        // full speed, with content size
        static void feed_source_01(io::ByteStream_Feed * enc_feed) {
            jau::fs::file_stats fs_feed(enc_feed->id());
            const uint64_t file_size = fs_feed.size();
            enc_feed->set_content_size( file_size );

            uint64_t xfer_total = 0;
            io::ByteStream_File enc_stream(enc_feed->id(), true /* use_binary */);
            while( !enc_stream.end_of_data() && xfer_total < file_size ) {
                uint8_t buffer[1024]; // 1k
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    // jau::sleep_for( 100_ms );
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                }
            }
            enc_feed->set_eof( xfer_total == file_size ? io::result_t::SUCCESS : io::result_t::FAILED );
        }

        void test21_enc_dec_fed_ok() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                cipherpack::PackInfo pinfo1 = cipherpack::encryptThenSign_RSA1(cipherpack::CryptoConfig::getDefault(),
                                                                               enc_pub_keys,
                                                                               sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                               fname_payload, fname_payload, "test_case", 1, 0,
                                                                               fname_encrypted, overwrite);
                jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Encrypted %s to %s\n", fname_payload.c_str(), fname_encrypted.c_str());
                jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", pinfo1.toString(true, true).c_str());
                REQUIRE( pinfo1.isValid() == true );

                {
                    // throttled, no content size
                    io::ByteStream_Feed enc_feed(fname_encrypted, io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_00, &enc_feed);

                    cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                        enc_feed, fname_decrypted, overwrite);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", pinfo2.toString(true, true).c_str());
                    REQUIRE( pinfo2.isValid() == true );
                }
                {
                    // full speed, with content size
                    io::ByteStream_Feed enc_feed(fname_encrypted, io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_01, &enc_feed);

                    cipherpack::PackInfo pinfo2 = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                        enc_feed, fname_decrypted, overwrite);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted.c_str(), fname_decrypted.c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", pinfo2.toString(true, true).c_str());
                    REQUIRE( pinfo2.isValid() == true );
                }
            }
        }

};

METHOD_AS_TEST_CASE( Test01Cipherpack::test01_enc_dec_file_ok,    "Elevator CipherPack 01 test01_enc_dec_file_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test02_enc_dec_file_error, "Elevator CipherPack 01 test02_enc_dec_file_error");

METHOD_AS_TEST_CASE( Test01Cipherpack::test11_dec_http_ok,        "Elevator CipherPack 02 test11_dec_http_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test12_dec_http_error,     "Elevator CipherPack 02 test11_dec_http_error");

METHOD_AS_TEST_CASE( Test01Cipherpack::test21_enc_dec_fed_ok,     "Elevator CipherPack 03 test21_enc_dec_fed_ok");


