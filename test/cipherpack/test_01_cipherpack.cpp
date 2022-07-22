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
        const std::string plaintext_version = "0";
        const std::string plaintext_version_parent = "0";

        const size_t IDX_11kiB = 0;
        const size_t IDX_65MiB = 1;
        static std::vector<std::string> fname_plaintext_lst;
        static std::vector<std::string> fname_encrypted_lst;
        static std::vector<std::string> fname_decrypted_lst;

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
                    fname_plaintext_lst.push_back(name);
                    fname_encrypted_lst.push_back(name+".enc");
                    fname_decrypted_lst.push_back(name+".enc.dec");
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
            if( jau::io::uri_tk::protocol_supported("http:") ) {
                int res = std::system("killall mini_httpd");
                (void)res;
            }
        }

        static void httpd_start() {
            if( jau::io::uri_tk::protocol_supported("http:") ) {
                int res = std::system("killall mini_httpd");
                const std::string cwd = jau::fs::get_cwd();
                const std::string cmd = "/usr/sbin/mini_httpd -p 8080 -l "+cwd+"/mini_httpd.log";
                jau::PLAIN_PRINT(true, "%s", cmd.c_str());
                res = std::system(cmd.c_str());
                (void)res;
            }
        }

        void test01_enc_dec_file_ok() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                const size_t file_idx = IDX_11kiB;
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                         silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true).c_str());
                REQUIRE( ph1.isValid() == true );

                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
            {
                const size_t file_idx = IDX_11kiB;
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key2_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                         silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true).c_str());
                REQUIRE( ph1.isValid() == true );

                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
            {
                const size_t file_idx = IDX_65MiB;
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key3_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                         silentListener, "", fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true).c_str());
                REQUIRE( ph1.isValid() == true );

                {
                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx], true /* use_binary */);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                   enc_stream,
                                                                                   silentListener, "", fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    jau::PLAIN_PRINT(true, "");
                }
                {
                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx], true /* use_binary */);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                   enc_stream,
                                                                                   silentListener, "SHA-256", fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    hash_retest(fname_plaintext_lst[file_idx], fname_decrypted_lst[file_idx],
                                ph2.getPlaintextHashAlgo(), ph2.getPlaintextHash());
                }
                {
                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx], true /* use_binary */);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                   enc_stream,
                                                                                   silentListener, "SHA-512", fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    hash_retest(fname_plaintext_lst[file_idx], fname_decrypted_lst[file_idx],
                                ph2.getPlaintextHashAlgo(), ph2.getPlaintextHash());
                }
                {
                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx], true /* use_binary */);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                   enc_stream,
                                                                                   silentListener, "BLAKE2b(512)", fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    hash_retest(fname_plaintext_lst[file_idx], fname_decrypted_lst[file_idx],
                                ph2.getPlaintextHashAlgo(), ph2.getPlaintextHash());
                }
            }
        }
        void hash_retest(const std::string& orig_file, const std::string& hashed_decrypted_file,
                         const std::string& hash_algo, const std::vector<uint8_t>& hash_value)
        {
            const std::string suffix = cipherpack::hash_util::file_suffix(hash_algo);
            const std::string out_file = hashed_decrypted_file + "." + suffix;
            jau::fs::remove( out_file );
            REQUIRE( true == cipherpack::hash_util::append_to_file(out_file, hashed_decrypted_file, hash_value) );

            std::unique_ptr<jau::io::ByteInStream> orig_in = jau::io::to_ByteInStream(orig_file);
            REQUIRE( nullptr != orig_in );
            const jau::fraction_timespec _t0 = jau::getMonotonicTime();
            std::unique_ptr<std::vector<uint8_t>> orig_hash_value = cipherpack::hash_util::calc(hash_algo, *orig_in);
            REQUIRE( nullptr != orig_hash_value );
            REQUIRE( hash_value == *orig_hash_value );

            const jau::fraction_i64 _td = ( jau::getMonotonicTime() - _t0 ).to_fraction_i64();
            jau::io::print_stats("Hash '"+hash_algo+"'", orig_in->content_size(), _td);
            jau::PLAIN_PRINT(true, "");
        }

        void test02_enc_dec_file_error() {
            const size_t file_idx = IDX_11kiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                     silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph1.toString(true, true).c_str());
            REQUIRE( ph1.isValid() == true );

            {
                // Error: Not encrypted for terminal key 4
                const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx], true /* use_binary */);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
        }

        void test11_dec_http_ok() {
            if( !jau::io::uri_tk::protocol_supported("http:") ) {
                jau::PLAIN_PRINT(true, "http not supported, abort\n");
                return;
            }
            httpd_start();

            const size_t file_idx = IDX_11kiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                     silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test11_dec_http_ok: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph1.toString(true, true).c_str());
            REQUIRE( ph1.isValid() == true );

            const std::string uri_encrypted = url_input_root + fname_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
            {
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
            {
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
        }

        void test12_dec_http_ok() {
            if( !jau::io::uri_tk::protocol_supported("http:") ) {
                jau::PLAIN_PRINT(true, "http not supported, abort\n");
                return;
            }
            httpd_start();

            const size_t file_idx = IDX_65MiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                     silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test12_dec_http_ok: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test12_dec_http_ok: %s\n", ph1.toString(true, true).c_str());
            REQUIRE( ph1.isValid() == true );

            const std::string uri_encrypted = url_input_root + fname_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_ok: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
            }
        }

        void test13_dec_http_error() {
            if( !jau::io::uri_tk::protocol_supported("http:") ) {
                jau::PLAIN_PRINT(true, "http not supported, abort\n");
                return;
            }
            httpd_start();

            const size_t file_idx = IDX_11kiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                     silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test13_dec_http_error: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test13_dec_http_error: %s\n", ph1.toString(true, true).c_str());
            REQUIRE( ph1.isValid() == true );

            const std::string uri_encrypted = url_input_root + fname_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                // Error: Not encrypted for terminal key 4
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test13_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test13_dec_http_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test13_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test13_dec_http_error: %s\n", ph2.toString(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
            }
            {
                // Error: URL file doesn't exist
                const std::string uri_encrypted_err = url_input_root + "doesnt_exists.enc";
                jau::io::ByteInStream_URL enc_stream(uri_encrypted_err, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              silentListener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test13_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test13_dec_http_error: %s\n", ph2.toString(true, true).c_str());
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
                    jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                    cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                             enc_pub_keys,
                                                                             sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                             source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                             silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph1.toString(true, true).c_str());
                    REQUIRE( ph1.isValid() == true );
                }
                {
                    // throttled, no content size, interruptReader() via set_eof() will avoid timeout
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_00, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                }
                {
                    // throttled, with content size
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_01, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                }
            }
            {
                const size_t file_idx = IDX_65MiB;
                {
                    jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                    cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                             enc_pub_keys,
                                                                             sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                             source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                             silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: %s\n", ph1.toString(true, true).c_str());
                    REQUIRE( ph1.isValid() == true );
                }
                {
                    // full speed, with content size
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_10, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
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
                    jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                    cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                             enc_pub_keys,
                                                                             sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                             source, fname_plaintext_lst[file_idx], "test_case", plaintext_version, plaintext_version_parent,
                                                                             silentListener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: %s\n", ph1.toString(true, true).c_str());
                    REQUIRE( ph1.isValid() == true );
                }
                {
                    // full speed, no content size, interrupting @ 1024 bytes within our header
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_20, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                }
                {
                    // full speed, with content size, interrupting 1/4 way
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_21, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  silentListener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test22_enc_dec_fed_irq: %s\n", ph2.toString(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                }
            }
        }

        const std::string root = "test_data";
        // submodule location with jaulib directly hosted below main project
        const std::string project_root2 = "../../../jaulib/test_data";

        void test50_copy_and_verify() {
            const std::string title("test50_copy_and_verify");
            const std::string hash_file = title+".hash";

            jau::fprintf_td(stderr, "\n");
            jau::fprintf_td(stderr, "%s\n", title.c_str());

            jau::fs::remove(hash_file);

            jau::fs::file_stats source_stats(project_root2);
            REQUIRE( true == source_stats.exists() );
            REQUIRE( true == source_stats.is_dir() );

            uint64_t source_bytes_hashed = 0;
            std::unique_ptr<std::vector<uint8_t>> source_hash = cipherpack::hash_util::calc(cipherpack::default_hash_algo(), source_stats.path(), source_bytes_hashed);
            REQUIRE( nullptr != source_hash );
            REQUIRE( true == cipherpack::hash_util::append_to_file(hash_file, source_stats.path(), *source_hash));

            // copy folder
            const std::string dest = root+"_copy_verify_test50";
            {
                const jau::fs::copy_options copts = jau::fs::copy_options::recursive |
                                                    jau::fs::copy_options::preserve_all |
                                                    jau::fs::copy_options::sync |
                                                    jau::fs::copy_options::verbose;
                jau::fs::remove(dest, jau::fs::traverse_options::recursive);
                REQUIRE( true == jau::fs::copy(source_stats.path(), dest, copts) );
            }
            jau::fs::file_stats dest_stats(dest);
            REQUIRE( true == dest_stats.exists() );
            REQUIRE( true == dest_stats.ok() );
            REQUIRE( true == dest_stats.is_dir() );

            uint64_t dest_bytes_hashed = 0;
            std::unique_ptr<std::vector<uint8_t>> dest_hash = cipherpack::hash_util::calc(cipherpack::default_hash_algo(), dest_stats.path(), dest_bytes_hashed);
            REQUIRE( nullptr != dest_hash );
            REQUIRE( true == cipherpack::hash_util::append_to_file(hash_file, dest_stats.path(), *dest_hash));

            // actual validation of hash values, i.e. same content
            REQUIRE( *source_hash == *dest_hash );
            REQUIRE( source_bytes_hashed == dest_bytes_hashed );

            jau::fprintf_td(stderr, "%s: bytes %s, '%s'\n", title.c_str(),
                    jau::to_decstring(dest_bytes_hashed).c_str(),
                    jau::bytesHexString(dest_hash->data(), 0, dest_hash->size(), true /* lsbFirst */, true /* lowerCase */).c_str());

            REQUIRE( true == jau::fs::remove(dest, jau::fs::traverse_options::recursive) );
        }

};

std::vector<std::string> Test01Cipherpack::fname_plaintext_lst;
std::vector<std::string> Test01Cipherpack::fname_encrypted_lst;
std::vector<std::string> Test01Cipherpack::fname_decrypted_lst;

METHOD_AS_TEST_CASE( Test01Cipherpack::test01_enc_dec_file_ok,    "CipherPack 01 test01_enc_dec_file_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test02_enc_dec_file_error, "CipherPack 01 test02_enc_dec_file_error");

METHOD_AS_TEST_CASE( Test01Cipherpack::test11_dec_http_ok,        "CipherPack 02 test11_dec_http_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test12_dec_http_ok,        "CipherPack 02 test12_dec_http_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test13_dec_http_error,     "CipherPack 02 test13_dec_http_error");

METHOD_AS_TEST_CASE( Test01Cipherpack::test21_enc_dec_fed_ok,     "CipherPack 03 test21_enc_dec_fed_ok");
METHOD_AS_TEST_CASE( Test01Cipherpack::test22_enc_dec_fed_irq,    "CipherPack 03 test22_enc_dec_fed_irq");

METHOD_AS_TEST_CASE( Test01Cipherpack::test50_copy_and_verify,    "CipherPack 03 test50_copy_and_verify");
