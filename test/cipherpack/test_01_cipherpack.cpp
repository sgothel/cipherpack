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

#include <cipherpack/cipherpack.hpp>

#include "data_test.hpp"

#include <jau/debug.hpp>
#include <jau/file_util.hpp>

extern "C" {
    #include <unistd.h>
}

using namespace jau::fractions_i64_literals;

class Test01Cipherpack : public TestData {
    private:
        const std::string payload_version = "0";
        const std::string payload_version_parent = "0";

        const size_t IDX_11kiB = 0;
        const size_t IDX_65MiB = 1;
        static std::vector<std::string> fname_payload_lst;
        static std::vector<std::string> fname_payload_encrypted_lst;
        static std::vector<std::string> fname_payload_decrypted_lst;

        class data {
            private:
                static void add_test_file(const std::string name, const size_t size) {
                    jau::fs::remove(name);
                    jau::fs::remove(name+".enc");
                    jau::fs::remove(name+".enc.dec");
                    {
                        static const std::string one_line = "Hello World, this is a test and I like it. Exactly 100 characters long. 0123456780 abcdefghjklmnop..";
                        std::ofstream ofs(name, std::ios::out | std::ios::binary);

                        REQUIRE( ofs.good() == true );
                        REQUIRE( ofs.is_open() == true );

                        for(size_t i=0; i < size; i+=one_line.size()) {
                            ofs.write(reinterpret_cast<const char*>(one_line.data()), one_line.size());
                        }
                        ofs.write("X", 1); // make it odd
                    }
                    fname_payload_lst.push_back(name);
                    fname_payload_encrypted_lst.push_back(name+".enc");
                    fname_payload_decrypted_lst.push_back(name+".enc.dec");
                }
                data() {
                    // setenv("cipherpack.debug", "true", 1 /* overwrite */);
                    setenv("cipherpack.verbose", "true", 1 /* overwrite */);

                    add_test_file("test_cipher_01_11kiB.bin", 1024*11);
                    add_test_file("test_cipher_02_65MiB.bin", 1024*1024*65);
                }
            public:
                static const data& get() {
                    static data instance;
                    return instance;
                }
        };

        cipherpack::CipherpackListenerRef silentListener = std::make_shared<cipherpack::CipherpackListener>();

    public:
        Test01Cipherpack() {
            // produce fresh demo data once per whole test class
            const data& d = data::get();
            (void)d;
        }

        ~Test01Cipherpack() {
            std::system("killall mini_httpd");
        }

        static void httpd_start() {
            std::system("killall mini_httpd");
            const std::string cwd = jau::fs::get_cwd();
            const std::string cmd = "/usr/sbin/mini_httpd -p 8080 -l "+cwd+"/mini_httpd.log";
            jau::PLAIN_PRINT(true, "%s", cmd.c_str());
            std::system(cmd.c_str());
        }

        void test01_enc_dec_file_ok() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                const size_t file_idx = IDX_11kiB;
                jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                         silentListener, fname_payload_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true).c_str());
                REQUIRE( ph1.isValid() == true );

                jau::io::ByteInStream_File enc_stream(fname_payload_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, fname_payload_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
            {
                const size_t file_idx = IDX_65MiB;
                jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key2_fname, sign_sec_key_passphrase,
                                                                         source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                         silentListener, fname_payload_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true).c_str());
                REQUIRE( ph1.isValid() == true );

                jau::io::ByteInStream_File enc_stream(fname_payload_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, fname_payload_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
            {
                const size_t file_idx = IDX_11kiB;
                jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key3_fname, sign_sec_key_passphrase,
                                                                         source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                         silentListener, fname_payload_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true).c_str());
                REQUIRE( ph1.isValid() == true );

                jau::io::ByteInStream_File enc_stream(fname_payload_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                               enc_stream,
                                                                               silentListener, fname_payload_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
        }

        void test02_enc_dec_file_error() {
            const size_t file_idx = IDX_11kiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                     silentListener, fname_payload_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph1.toString(true, true).c_str());
            REQUIRE( ph1.isValid() == true );

            {
                // Error: Not encrypted for terminal key 4
                const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
                jau::io::ByteInStream_File enc_stream(fname_payload_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, fname_payload_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                jau::io::ByteInStream_File enc_stream(fname_payload_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, fname_payload_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
        }

        void test11_dec_http_ok() {
            httpd_start();

            const size_t file_idx = IDX_11kiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                     silentListener, fname_payload_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph1.toString(true, true).c_str());
            REQUIRE( ph1.isValid() == true );

            const std::string uri_encrypted = url_input_root + fname_payload_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_payload_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
            {
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
            {
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
        }

        void test12_dec_http_ok() {
            httpd_start();

            const size_t file_idx = IDX_65MiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                     silentListener, fname_payload_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph1.toString(true, true).c_str());
            REQUIRE( ph1.isValid() == true );

            const std::string uri_encrypted = url_input_root + fname_payload_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_payload_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
        }

        void test13_dec_http_error() {
            httpd_start();

            const size_t file_idx = IDX_11kiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                     silentListener, fname_payload_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph1.toString(true, true).c_str());
            REQUIRE( ph1.isValid() == true );

            const std::string uri_encrypted = url_input_root + fname_payload_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_payload_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                // Error: Not encrypted for terminal key 4
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, file_decrypted);
                jau::PLAIN_PRINT(true, "test12_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test12_dec_http_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, file_decrypted);
                jau::PLAIN_PRINT(true, "test12_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test12_dec_http_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
            {
                // Error: URL file doesn't exist
                const std::string uri_encrypted_err = url_input_root + "doesnt_exists.enc";
                jau::io::ByteInStream_URL enc_stream(uri_encrypted_err, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, file_decrypted);
                jau::PLAIN_PRINT(true, "test12_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test12_dec_http_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
        }

        // throttled, no content size, interruptReader() via set_eof() will avoid timeout
        static void feed_source_00(jau::io::ByteInStream_Feed * enc_feed) {
            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id(), true /* use_binary */);
            while( !enc_stream.end_of_data() ) {
                uint8_t buffer[1024]; // 1k
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                    jau::sleep_for( 16_ms );
                }
            }
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed->set_eof( jau::io::async_io_result_t::SUCCESS );
        }

        // throttled, with content size
        static void feed_source_01(jau::io::ByteInStream_Feed * enc_feed) {
            jau::fs::file_stats fs_feed(enc_feed->id());
            const uint64_t file_size = fs_feed.size();
            enc_feed->set_content_size( file_size );

            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id(), true /* use_binary */);
            while( !enc_stream.end_of_data() && xfer_total < file_size ) {
                uint8_t buffer[1024]; // 1k
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                    jau::sleep_for( 16_ms );
                }
            }
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed->set_eof( xfer_total == file_size ? jau::io::async_io_result_t::SUCCESS : jau::io::async_io_result_t::FAILED );
        }

        // full speed, with content size
        static void feed_source_10(jau::io::ByteInStream_Feed * enc_feed) {
            jau::fs::file_stats fs_feed(enc_feed->id());
            const uint64_t file_size = fs_feed.size();
            enc_feed->set_content_size( file_size );

            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id(), true /* use_binary */);
            while( !enc_stream.end_of_data() && xfer_total < file_size ) {
                uint8_t buffer[1024]; // 1k
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                }
            }
            enc_feed->set_eof( xfer_total == file_size ? jau::io::async_io_result_t::SUCCESS : jau::io::async_io_result_t::FAILED );
        }

        // full speed, no content size, interrupting @ 1024 bytes within our header
        static void feed_source_20(jau::io::ByteInStream_Feed * enc_feed) {
            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id(), true /* use_binary */);
            while( !enc_stream.end_of_data() ) {
                uint8_t buffer[1024]; // 1k
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                    if( xfer_total >= 1024 ) {
                        enc_feed->set_eof( jau::io::async_io_result_t::FAILED ); // calls data_feed->interruptReader();
                        return;
                    }
                }
            }
        }

        // full speed, with content size, interrupting 1/4 way
        static void feed_source_21(jau::io::ByteInStream_Feed * enc_feed) {
            jau::fs::file_stats fs_feed(enc_feed->id());
            const uint64_t file_size = fs_feed.size();
            enc_feed->set_content_size( file_size );

            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id(), true /* use_binary */);
            while( !enc_stream.end_of_data() ) {
                uint8_t buffer[1024]; // 1k
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                    if( xfer_total >= file_size/4 ) {
                        enc_feed->set_eof( jau::io::async_io_result_t::FAILED ); // calls data_feed->interruptReader();
                        return;
                    }
                }
            }
        }

        void test21_enc_dec_fed_ok() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                const size_t file_idx = IDX_11kiB;
                {
                    jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
                    cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                             enc_pub_keys,
                                                                             sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                             source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                             silentListener, fname_payload_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph1.toString(true, true).c_str());
                    REQUIRE( ph1.isValid() == true );
                }
                {
                    // throttled, no content size, interruptReader() via set_eof() will avoid timeout
                    jau::io::ByteInStream_Feed enc_feed(fname_payload_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_00, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, fname_payload_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                }
                {
                    // throttled, with content size
                    jau::io::ByteInStream_Feed enc_feed(fname_payload_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_01, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, fname_payload_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                }
            }
            {
                const size_t file_idx = IDX_65MiB;
                {
                    jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
                    cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                             enc_pub_keys,
                                                                             sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                             source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                             silentListener, fname_payload_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph1.toString(true, true).c_str());
                    REQUIRE( ph1.isValid() == true );
                }
                {
                    // full speed, with content size
                    jau::io::ByteInStream_Feed enc_feed(fname_payload_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_10, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, fname_payload_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                }
            }
        }

        void test22_enc_dec_fed_irq() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                const size_t file_idx = IDX_65MiB;
                {
                    jau::io::ByteInStream_File source(fname_payload_lst[file_idx]);
                    cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                             enc_pub_keys,
                                                                             sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                             source, fname_payload_lst[file_idx], "test_case", payload_version, payload_version_parent,
                                                                             silentListener, fname_payload_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: Encrypted %s to %s\n", fname_payload_lst[file_idx].c_str(), fname_payload_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: %s\n", ph1.toString(true, true).c_str());
                    REQUIRE( ph1.isValid() == true );
                }
                {
                    // full speed, no content size, interrupting @ 1024 bytes within our header
                    jau::io::ByteInStream_Feed enc_feed(fname_payload_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_20, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, fname_payload_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                }
                {
                    // full speed, with content size, interrupting 1/4 way
                    jau::io::ByteInStream_Feed enc_feed(fname_payload_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_21, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, fname_payload_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: Decypted %s to %s\n", fname_payload_encrypted_lst[file_idx].c_str(), fname_payload_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                }
            }
        }

};

std::vector<std::string> Test01Cipherpack::fname_payload_lst;
std::vector<std::string> Test01Cipherpack::fname_payload_encrypted_lst;
std::vector<std::string> Test01Cipherpack::fname_payload_decrypted_lst;

METHOD_AS_TEST_CASE( Test01Cipherpack::test01_enc_dec_file_ok,    "Elevator CipherPack 01 test01_enc_dec_file_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test02_enc_dec_file_error, "Elevator CipherPack 01 test02_enc_dec_file_error");

METHOD_AS_TEST_CASE( Test01Cipherpack::test11_dec_http_ok,        "Elevator CipherPack 02 test11_dec_http_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test12_dec_http_ok,        "Elevator CipherPack 02 test12_dec_http_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test13_dec_http_error,     "Elevator CipherPack 02 test13_dec_http_error");

METHOD_AS_TEST_CASE( Test01Cipherpack::test21_enc_dec_fed_ok,     "Elevator CipherPack 03 test21_enc_dec_fed_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test22_enc_dec_fed_irq,    "Elevator CipherPack 03 test22_enc_dec_fed_irq");


