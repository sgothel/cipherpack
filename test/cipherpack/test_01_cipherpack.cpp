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
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <sys/wait.h>
    #include <unistd.h>
}

#include <fstream>
#include <iostream>


#if defined(__FreeBSD__)
    constexpr inline std::string_view mini_httpd_exe = "/usr/local/sbin/mini_httpd";
#else
    constexpr inline std::string_view mini_httpd_exe = "/usr/sbin/mini_httpd";
#endif

using namespace jau::fractions_i64_literals;

class Test01Cipherpack : public TestData {
    private:
        const std::string plaintext_version = "0";
        const std::string plaintext_version_parent = "0";

        // const size_t IDX_0B = 0;
        // const size_t IDX_1B = 1;
        const size_t IDX_11kiB = 2;
        const size_t IDX_xbuffersz = 3;
        // const size_t IDX_xbuffersz_minus_tag = 4;
        // const size_t IDX_xbuffersz_plus_tag = 5;
        const size_t IDX_65MiB = 6;

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

                        size_t written=0;
                        for(; written+one_line.size() <= size; written+=one_line.size()) {
                            ofs.write(reinterpret_cast<const char*>(one_line.data()), one_line.size());
                        }
                        if( size-written > 0 ) {
                            ofs.write(reinterpret_cast<const char*>(one_line.data()), size-written);
                        }
                    }
                    jau::fs::file_stats stats(name);
                    REQUIRE( stats.is_file() );
                    REQUIRE( size == stats.size() );
                    fname_plaintext_lst.push_back(name);
                    fname_encrypted_lst.push_back(name+".enc");
                    fname_decrypted_lst.push_back(name+".enc.dec");
                }
                data() {
                    // setenv("cipherpack.debug", "true", 1 /* overwrite */);
                    // setenv("cipherpack.verbose", "true", 1 /* overwrite */);

                    int i=0;

                    // Zero size .. Single finish chunk of less than buffer_size including the 16 bytes TAG
                    add_test_file("test_cipher_0"+std::to_string(i++)+"_0B.bin", 0);

                    // One byte .. Single finish chunk of less than buffer_size including the 16 bytes TAG
                    add_test_file("test_cipher_0"+std::to_string(i++)+"_1B.bin", 1);

                    // Single finish chunk of less than buffer_size including the 16 bytes TAG
                    add_test_file("test_cipher_0"+std::to_string(i++)+"_11kiB.bin", 1024*11+1);

                    // Will end up in a finish chunk of just 16 bytes TAG
                    size_t xbuffersz = 4 * cipherpack::Constants::buffer_size;
                    add_test_file("test_cipher_0"+std::to_string(i++)+"_xbuffsz_"+std::to_string(xbuffersz/1024)+"kiB.bin", xbuffersz);

                    // Will end up in a finish chunk of buffer_size including the 16 bytes TAG
                    size_t xbuffersz_minus = 4 * cipherpack::Constants::buffer_size - 16;
                    add_test_file("test_cipher_0"+std::to_string(i++)+"_xbuffsz_"+std::to_string(xbuffersz/1024)+"kiB_sub16.bin", xbuffersz_minus);

                    // Will end up in a finish chunk of 1 byte + 16 bytes TAG
                    size_t xbuffersz_plus = 4 * cipherpack::Constants::buffer_size + 1;
                    add_test_file("test_cipher_0"+std::to_string(i++)+"_xbuffsz_"+std::to_string(xbuffersz/1024)+"kiB_add1.bin", xbuffersz_plus);

                    // 65MB big file: Will end up in a finish chunk of 1 byte + 16 bytes TAG, 4160 chunks @ 16384
                    add_test_file("test_cipher_0"+std::to_string(i++)+"_65MiB.bin", 1024*1024*65+1);
                }
            public:
                static const data& get() {
                    static data instance;
                    return instance;
                }
        };

        class LoggingCipherpackListener : public cipherpack::CipherpackListener {
            private:
                std::string name;
                bool send_content;
                bool abort_header;
                bool abort_progress;
                bool abort_content;

            public:
                jau::relaxed_atomic_int count_error;
                jau::relaxed_atomic_int count_header;
                jau::relaxed_atomic_int count_progress;
                jau::relaxed_atomic_int count_end;
                jau::relaxed_atomic_uint64 count_content;

                LoggingCipherpackListener(const std::string& name_, const bool send_content_=false) noexcept
                : name(name_), send_content(send_content_),
                  abort_header( false ),
                  abort_progress( false ),
                  abort_content( false ),
                  count_error(0), count_header(0),
                  count_progress(0), count_end(0), count_content(0)
                {}

                void set_abort(const int what) noexcept {
                    switch( what ) {
                        case 1: set_abort_header(true); break;
                        case 2: set_abort_progress(true); break;
                        case 3: set_abort_content(true); break;
                        default:
                            REQUIRE( false );
                    }
                }
                void set_abort_header(const bool v) noexcept { abort_header = v; }
                void set_abort_progress(const bool v) noexcept { abort_progress = v; }
                void set_abort_content(const bool  v) noexcept { abort_content = v; }

                void check_counter_end(const uint64_t min_content=0) noexcept {
                    jau::PLAIN_PRINT(true, "CL::Check: %s", toString().c_str());
                    if( abort_header ) {
                        REQUIRE( 0 == count_error );
                        REQUIRE( 1 == count_header );
                        REQUIRE( 0 == count_progress );
                        REQUIRE( 0 == count_end );
                    } else if( abort_progress ) {
                        REQUIRE( 0 == count_error );
                        REQUIRE( 1 == count_header );
                        REQUIRE( 1 == count_progress );
                        REQUIRE( 0 == count_end );
                    } else if( abort_content ) {
                        REQUIRE( 0 == count_error );
                        REQUIRE( 1 == count_header );
                        REQUIRE( 0 == count_progress );
                        REQUIRE( 0 == count_end );
                    } else if( 0 < count_error ) {
                        if( 0 != count_header && 1 != count_header ) {
                            REQUIRE( false );
                        }
                        if( 0 != count_end && 1 != count_end ) {
                            REQUIRE( false );
                        }
                        REQUIRE( 0 <= count_progress );
                    } else {
                        REQUIRE( 1 == count_header );
                        REQUIRE( 1 == count_end );
                        REQUIRE( 0 < count_progress );
                    }
                    if( send_content ) {
                        REQUIRE( min_content <= count_content );
                    } else {
                        REQUIRE( 0 == count_content );
                    }
                }

                void notifyError(const bool decrypt_mode, const cipherpack::PackHeader& header, const std::string& msg) noexcept override {
                    count_error++;
                    (void)decrypt_mode;
                    jau::PLAIN_PRINT(true, "CL::Error: %s[%d]: %s, %s", name.c_str(), count_error.load(), msg.c_str(), header.to_string(true, true).c_str());
                }

                bool notifyHeader(const bool decrypt_mode, const cipherpack::PackHeader& header) noexcept override {
                    count_header++;
                    (void)decrypt_mode;
                    (void)header;
                    // jau::PLAIN_PRINT(true, "CL::Header: %s[%d]: %s", name.c_str(), count_header.load(), header.to_string(true, true).c_str());
                    return abort_header ? false : true;
                }

                bool notifyProgress(const bool decrypt_mode, const uint64_t plaintext_size, const uint64_t bytes_processed) noexcept override {
                    count_progress++;
                    (void)decrypt_mode;
                    (void)plaintext_size;
                    (void)bytes_processed;
                    return abort_progress ? false : true;
                }

                void notifyEnd(const bool decrypt_mode, const cipherpack::PackHeader& header) noexcept override {
                    count_end++;
                    (void)decrypt_mode;
                    (void)header;
                    // jau::PLAIN_PRINT(true, "CL::End: %s[%d]: %s", name.c_str(), count_end.load(), header.to_string(true, true).c_str());
                }

                bool getSendContent(const bool decrypt_mode) const noexcept override {
                    (void)decrypt_mode;
                    return send_content;
                }

                bool contentProcessed(const bool decrypt_mode, const content_type ctype, cipherpack::secure_vector<uint8_t>& data, const bool is_final) noexcept override {
                    count_content.fetch_add( data.size() );
                    (void)decrypt_mode;
                    (void)ctype;
                    (void)data;
                    (void)is_final;
                    return abort_content ? false : true;
                }
                std::string toString() const noexcept override {
                    return "LoggingCipherpackListener["+name+
                            "]{abort[header "+std::to_string(abort_header)+
                            ", progress "+std::to_string(abort_progress)+
                            ", content "+std::to_string(abort_content)+
                            "], count[error "+std::to_string(count_error)+
                            ", header "+std::to_string(count_header)+
                            ", progress "+std::to_string(count_progress)+
                            ", content "+std::to_string(count_content)+"]}";
                }
        };
        typedef std::shared_ptr<LoggingCipherpackListener> LoggingCipherpackListenerRef;

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
                int res = std::system("killall mini_httpd"); // NOLINT(clang-analyzer-deadcode.DeadStores)
                const std::string cwd = jau::fs::get_cwd();
                const std::string cmd = std::string(mini_httpd_exe)+" -p 8080 -l "+cwd+"/mini_httpd.log";
                jau::PLAIN_PRINT(true, "%s", cmd.c_str());
                res = std::system(cmd.c_str());
                (void)res;
            }
        }

        void hash_retest(const std::string& hash_algo,
                         const std::string& orig_file, const std::vector<uint8_t>& hash_value_p1,
                         const std::string& hashed_decrypted_file, const std::vector<uint8_t>& hash_value_p2)
        {
            REQUIRE( hash_value_p1 == hash_value_p2 );

            const std::string suffix = cipherpack::hash_util::file_suffix(hash_algo);
            const std::string out_file = hashed_decrypted_file + "." + suffix;
            jau::fs::remove( out_file );
            REQUIRE( true == cipherpack::hash_util::append_to_file(out_file, hashed_decrypted_file, hash_algo, hash_value_p2) );

            std::unique_ptr<jau::io::ByteInStream> orig_in = jau::io::to_ByteInStream(orig_file);
            REQUIRE( nullptr != orig_in );
            const jau::fraction_timespec _t0 = jau::getMonotonicTime();
            std::unique_ptr<std::vector<uint8_t>> orig_hash_value = cipherpack::hash_util::calc(hash_algo, *orig_in);
            REQUIRE( nullptr != orig_hash_value );
            REQUIRE( hash_value_p2 == *orig_hash_value );

            if( jau::environment::get().verbose ) {
                const jau::fraction_i64 _td = ( jau::getMonotonicTime() - _t0 ).to_fraction_i64();
                jau::io::print_stats("Hash '"+hash_algo+"'", orig_in->content_size(), _td);
                jau::PLAIN_PRINT(true, "");
            }
            (void)_t0;
        }

        void hash_retest(const std::string& hash_algo,
                         const std::string& orig_file,
                         const std::string& hashed_decrypted_file, const std::vector<uint8_t>& hash_value_p2)
        {
            const std::string suffix = cipherpack::hash_util::file_suffix(hash_algo);
            const std::string out_file = hashed_decrypted_file + "." + suffix;
            jau::fs::remove( out_file );
            REQUIRE( true == cipherpack::hash_util::append_to_file(out_file, hashed_decrypted_file, hash_algo, hash_value_p2) );

            std::unique_ptr<jau::io::ByteInStream> orig_in = jau::io::to_ByteInStream(orig_file);
            REQUIRE( nullptr != orig_in );
            const jau::fraction_timespec _t0 = jau::getMonotonicTime();
            std::unique_ptr<std::vector<uint8_t>> orig_hash_value = cipherpack::hash_util::calc(hash_algo, *orig_in);
            REQUIRE( nullptr != orig_hash_value );
            REQUIRE( hash_value_p2 == *orig_hash_value );

            if( jau::environment::get().verbose ) {
                const jau::fraction_i64 _td = ( jau::getMonotonicTime() - _t0 ).to_fraction_i64();
                jau::io::print_stats("Hash '"+hash_algo+"'", orig_in->content_size(), _td);
                jau::PLAIN_PRINT(true, "");
            }
            (void)_t0;
        }

        void test00_enc_dec_file_single() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                const size_t file_idx = IDX_11kiB;
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test00.enc", true /* send_content */);
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test00.dec", true /* send_content */);
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test00_enc_dec_file_single(", plaintext_version, plaintext_version_parent,
                                                                         enc_listener,
                                                                         cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test00_enc_dec_file_single: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test00_enc_dec_file_single: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end(source.content_size());

                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, ph1.plaintext_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test00_enc_dec_file_single: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test00_enc_dec_file_single: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end(ph2.plaintext_size());

                hash_retest(ph1.plaintext_hash_algo(),
                            fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                            fname_decrypted_lst[file_idx], ph2.plaintext_hash());
            }
        }

        void test01_enc_dec_all_files() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            for(size_t file_idx = 0; file_idx < fname_plaintext_lst.size(); ++file_idx) {
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test01.enc."+std::to_string(file_idx), true /* send_content */);
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test01_enc_dec_all_files", plaintext_version, plaintext_version_parent,
                                                                         enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_all_files: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_all_files: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end(source.content_size());

                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test01.dec."+std::to_string(file_idx), true /* send_content */);
                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, ph1.plaintext_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test01_enc_dec_all_files: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test01_enc_dec_all_files: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end(ph2.plaintext_size());

                hash_retest(ph1.plaintext_hash_algo(),
                            fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                            fname_decrypted_lst[file_idx], ph2.plaintext_hash());
            }
        }

        void test02_enc_dec_file_misc() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                const size_t file_idx = IDX_11kiB;
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test02.enc.1."+std::to_string(file_idx));
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test02.dec.1."+std::to_string(file_idx));
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test02_enc_dec_file_misc", plaintext_version, plaintext_version_parent,
                                                                         enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_misc: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_misc: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end();

                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, ph1.plaintext_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_misc: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_misc: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end();

                hash_retest(ph1.plaintext_hash_algo(),
                            fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                            fname_decrypted_lst[file_idx], ph2.plaintext_hash());
            }
            {
                const size_t file_idx = IDX_11kiB;
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test02.enc.2."+std::to_string(file_idx));
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test02.dec.2."+std::to_string(file_idx));
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key2_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test02_enc_dec_file_misc", plaintext_version, plaintext_version_parent,
                                                                         enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_misc: Encrypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_misc: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end();

                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, ph1.plaintext_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_misc: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test02_enc_dec_file_misc: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end();

                hash_retest(ph1.plaintext_hash_algo(),
                            fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                            fname_decrypted_lst[file_idx], ph2.plaintext_hash());
            }
        }

        void test03_enc_dec_file_perf() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                const size_t file_idx = IDX_65MiB;
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test03.enc."+std::to_string(file_idx));
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key3_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test03_enc_dec_file_perf", plaintext_version, plaintext_version_parent,
                                                                         enc_listener, "", fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end();

                {
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test03.dec.none."+std::to_string(file_idx));
                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                   enc_stream,
                                                                                   dec_listener, "", fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: %s\n", ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    dec_listener->check_counter_end();
                    jau::PLAIN_PRINT(true, "");
                }
                {
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test03.dec.sha256."+std::to_string(file_idx));
                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                   enc_stream,
                                                                                   dec_listener, "SHA-256", fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: %s\n", ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    dec_listener->check_counter_end();
                    hash_retest(ph2.plaintext_hash_algo(),
                                fname_plaintext_lst[file_idx],
                                fname_decrypted_lst[file_idx], ph2.plaintext_hash());
                }
                {
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test03.dec.sha512."+std::to_string(file_idx));
                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                   enc_stream,
                                                                                   dec_listener, "SHA-512", fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: %s\n", ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    dec_listener->check_counter_end();
                    hash_retest(ph2.plaintext_hash_algo(),
                                fname_plaintext_lst[file_idx],
                                fname_decrypted_lst[file_idx], ph2.plaintext_hash());
                }
                {
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test03.dec.blake2b."+std::to_string(file_idx));

                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                                   enc_stream,
                                                                                   dec_listener, "BLAKE2b(512)", fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test03_enc_dec_file_perf: %s\n", ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    dec_listener->check_counter_end();
                    hash_retest(ph2.plaintext_hash_algo(),
                                fname_plaintext_lst[file_idx],
                                fname_decrypted_lst[file_idx], ph2.plaintext_hash());
                }
            }
        }

        void test04_enc_dec_file_error() {
            const size_t file_idx = IDX_11kiB;
            LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test04.enc."+std::to_string(file_idx));
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_plaintext_lst[file_idx], "test04_enc_dec_file_error", plaintext_version, plaintext_version_parent,
                                                                     enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test04_enc_dec_file_error: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test04_enc_dec_file_error: %s\n", ph1.to_string(true, true).c_str());
            REQUIRE( ph1.isValid() == true );
            enc_listener->check_counter_end();

            {
                // Error: Not encrypted for terminal key 4
                const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test04.dec.e01."+std::to_string(file_idx));
                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test04_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test04_enc_dec_file_error: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
                dec_listener->check_counter_end();
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test04.dec.e02."+std::to_string(file_idx));
                jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test04_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test04_enc_dec_file_error: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
                dec_listener->check_counter_end();
            }
        }

        void test11_dec_http_all_files() {
            if( !jau::io::uri_tk::protocol_supported("http:") ) {
                jau::PLAIN_PRINT(true, "http not supported, abort\n");
                return;
            }
            httpd_start();

            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            for(size_t file_idx = 0; file_idx < fname_plaintext_lst.size(); ++file_idx) {
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test11.enc."+std::to_string(file_idx));
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test11.dec."+std::to_string(file_idx));
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test11_dec_http_all_files", plaintext_version, plaintext_version_parent,
                                                                         enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test11_dec_http_all_files: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_all_files: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end();

                const std::string uri_encrypted = url_input_root + fname_encrypted_lst[file_idx];
                const std::string file_decrypted = fname_encrypted_lst[file_idx]+".dec";

                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, ph1.plaintext_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test11_dec_http_all_files: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test11_dec_http_all_files: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end();

                hash_retest(ph1.plaintext_hash_algo(),
                            fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                            fname_decrypted_lst[file_idx], ph2.plaintext_hash());
            }
        }

        void test12_dec_http_misc() {
            if( !jau::io::uri_tk::protocol_supported("http:") ) {
                jau::PLAIN_PRINT(true, "http not supported, abort\n");
                return;
            }
            httpd_start();

            const size_t file_idx = IDX_11kiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test12.enc."+std::to_string(file_idx));
            jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_plaintext_lst[file_idx], "test12_dec_http_misc", plaintext_version, plaintext_version_parent,
                                                                     enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test12_dec_http_misc: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test12_dec_http_misc: %s\n", ph1.to_string(true, true).c_str());
            REQUIRE( ph1.isValid() == true );
            enc_listener->check_counter_end();

            const std::string uri_encrypted = url_input_root + fname_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test12.dec.a."+std::to_string(file_idx));
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test12_dec_http_misc: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test12_dec_http_misc: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end();
            }
            {
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test12.dec.b."+std::to_string(file_idx));
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test12_dec_http_misc: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test12_dec_http_misc: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end();
            }
            {
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test12.dec.c."+std::to_string(file_idx));
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test12_dec_http_misc: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test12_dec_http_misc: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end();
            }
        }

        void test13_dec_http_perf() {
            if( !jau::io::uri_tk::protocol_supported("http:") ) {
                jau::PLAIN_PRINT(true, "http not supported, abort\n");
                return;
            }
            httpd_start();

            const size_t file_idx = IDX_65MiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test13.enc."+std::to_string(file_idx));
            jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_plaintext_lst[file_idx], "test13_dec_http_perf", plaintext_version, plaintext_version_parent,
                                                                     enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test13_dec_http_perf: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test13_dec_http_perf: %s\n", ph1.to_string(true, true).c_str());
            REQUIRE( ph1.isValid() == true );
            enc_listener->check_counter_end();

            const std::string uri_encrypted = url_input_root + fname_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test13.dec.hash."+std::to_string(file_idx));
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, ph1.plaintext_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test13_dec_http_perf: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test13_dec_http_perf: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end();

                hash_retest(ph1.plaintext_hash_algo(),
                            fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                            fname_decrypted_lst[file_idx], ph2.plaintext_hash());
            }
            {
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test13.dec.none."+std::to_string(file_idx));
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, "", file_decrypted);
                jau::PLAIN_PRINT(true, "test13_dec_http_perf: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test13_dec_http_perf: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == true );
                dec_listener->check_counter_end();
            }
        }

        void test14_dec_http_error() {
            if( !jau::io::uri_tk::protocol_supported("http:") ) {
                jau::PLAIN_PRINT(true, "http not supported, abort\n");
                return;
            }
            httpd_start();

            const size_t file_idx = IDX_11kiB;
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test14.enc."+std::to_string(file_idx));
            jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
            cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                     enc_pub_keys,
                                                                     sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                     source, fname_plaintext_lst[file_idx], "test14_dec_http_error", plaintext_version, plaintext_version_parent,
                                                                     enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
            jau::PLAIN_PRINT(true, "test14_dec_http_error: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
            jau::PLAIN_PRINT(true, "test14_dec_http_error: %s\n", ph1.to_string(true, true).c_str());
            REQUIRE( ph1.isValid() == true );
            enc_listener->check_counter_end();

            const std::string uri_encrypted = url_input_root + fname_encrypted_lst[file_idx];
            const std::string file_decrypted = fname_encrypted_lst[file_idx]+".dec";

            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                // Error: Not encrypted for terminal key 4
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test14.dec.e1."+std::to_string(file_idx));
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test14_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test14_dec_http_error: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
                dec_listener->check_counter_end();
            }
            {
                // Error: Not signed from host key 4
                const std::vector<std::string> sign_pub_keys_nope { sign_pub_key4_fname };
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test14.dec.e2."+std::to_string(file_idx));
                jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test14_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test14_dec_http_error: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
                dec_listener->check_counter_end();
            }
            {
                // Error: URL file doesn't exist
                const std::string uri_encrypted_err = url_input_root + "doesnt_exists.enc";
                LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test14.dec.e3."+std::to_string(file_idx));
                jau::io::ByteInStream_URL enc_stream(uri_encrypted_err, io_timeout);
                cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                              enc_stream,
                                                                              dec_listener, cipherpack::default_hash_algo(), file_decrypted);
                jau::PLAIN_PRINT(true, "test14_dec_http_error: Decypted %s to %s\n", uri_encrypted.c_str(), file_decrypted.c_str());
                jau::PLAIN_PRINT(true, "test14_dec_http_error: %s\n", ph2.to_string(true, true).c_str());
                REQUIRE( ph2.isValid() == false );
                dec_listener->check_counter_end();
            }
        }

        static constexpr const size_t slow_buffer_sz = 1024;
        static constexpr const jau::fraction_i64 slow_delay = 8_ms;

        /**
         * Automated test using a pipe input file descriptor
         * w/o content-size knowledge on the receiving side.
         */
        cipherpack::PackHeader test_pipe_to_decrypt(const std::string test_name,
                                                    const std::string input_fname, const std::string output_fname,
                                                    const size_t chunck_sz, const jau::fraction_i64 chunck_sleep,
                                                    const std::string& hash_algo,
                                                    const std::vector<uint8_t>& exp_hash_value) {
            cipherpack::PackHeader ph2;
            errno = 0;

            int pipe_fds[2];
            REQUIRE( 0 == ::pipe(pipe_fds) );
            ::pid_t pid = ::fork();

            if( 0 == pid ) {
                // child process: WRITE
                ::close(pipe_fds[0]); // close unused read end
                const int new_stdout = pipe_fds[1];
                const std::string fd_stdout = jau::fs::to_named_fd(new_stdout);

                jau::fs::file_stats stats_stdout(fd_stdout);
                jau::fprintf_td(stderr, "Child: stats_stdout %s\n", stats_stdout.to_string().c_str());
                if( !stats_stdout.exists() || !stats_stdout.has_fd() || new_stdout != stats_stdout.fd() ) {
                    jau::fprintf_td(stderr, "Child: Error: stats_stdout %s\n", stats_stdout.to_string().c_str());
                    ::_exit(EXIT_FAILURE);
                }
                std::ofstream outfile(fd_stdout, std::ios::out | std::ios::binary);
                if( !outfile.good() || !outfile.is_open() ) {
                    jau::fprintf_td(stderr, "Child: Error: outfile bad\n");
                    ::_exit(EXIT_FAILURE);
                }

                jau::io::ByteInStream_File infile(input_fname);
                {
                    std::vector<uint8_t> buffer;
                    buffer.reserve(chunck_sz);
                    uint64_t sent=0;
                    while( sent < infile.content_size() && !infile.end_of_data() && !outfile.fail() ) {
                        const size_t chunck_sz_max = std::min(chunck_sz, infile.content_size()-sent);
                        buffer.resize(buffer.capacity());
                        const uint64_t got = infile.read(buffer.data(), chunck_sz_max);
                        buffer.resize(got);
                        outfile.write((char*)buffer.data(), got);
                        sent += got;
                        if( chunck_sleep > jau::fractions_i64::zero ) {
                            jau::sleep_for( chunck_sleep );
                        }
                    }
                }

                infile.close();
                outfile.close();
                ::close(pipe_fds[1]);

                if( outfile.fail() ) {
                    jau::fprintf_td(stderr, "Child: Error: outfile failed after write/closure\n");
                    ::_exit(EXIT_FAILURE);
                }
                if( infile.fail() ) {
                    jau::fprintf_td(stderr, "Child: Error: infile failed after write/closure: %s\n", infile.to_string().c_str());
                    ::_exit(EXIT_FAILURE);
                }
                jau::fprintf_td(stderr, "Child: Done\n");
                ::_exit(EXIT_SUCCESS);

            } else if( 0 < pid ) {
                // parent process: READ
                ::close(pipe_fds[1]); // close unused write end
                const int new_stdin = pipe_fds[0]; // dup2(fd[0], 0);
                const std::string fd_stdin = jau::fs::to_named_fd(new_stdin);

                jau::fs::file_stats stats_stdin(fd_stdin);
                jau::fprintf_td(stderr, "Parent: stats_stdin %s\n", stats_stdin.to_string().c_str());
                REQUIRE(  stats_stdin.exists() );
                REQUIRE(  stats_stdin.has_access() );
                REQUIRE( !stats_stdin.is_socket() );
                REQUIRE( !stats_stdin.is_block() );
                REQUIRE( !stats_stdin.is_dir() );
                REQUIRE( !stats_stdin.is_file() );
                const bool fifo_or_char = stats_stdin.is_fifo() || stats_stdin.is_char();
                REQUIRE(  true == fifo_or_char );
                REQUIRE(  stats_stdin.has_fd() );
                REQUIRE(  new_stdin == stats_stdin.fd() );
                REQUIRE( 0 == stats_stdin.size() );

                // capture stdin
                jau::io::ByteInStream_File infile(fd_stdin);
                jau::fprintf_td(stderr, "Parent: infile %s\n", infile.to_string().c_str());
                REQUIRE( !infile.fail() );

                {
                    const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
                    const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>(test_name+".dec");

                    ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                           infile,
                                                           dec_listener, hash_algo, output_fname);
                    jau::PLAIN_PRINT(true, "%s: Decypted %s to %s\n", test_name.c_str(), infile.to_string().c_str(), output_fname.c_str());
                    jau::PLAIN_PRINT(true, "%s: %s\n", test_name.c_str(), ph2.to_string(true, true).c_str());
                    dec_listener->check_counter_end();
                }
                // having already finished up decrypting, i.e. all data has been sent from child - child has already ended.

                int pid_status = 0;
                ::pid_t child_pid = ::waitpid(pid, &pid_status, 0);
                if( 0 > child_pid ) {
                    jau::fprintf_td(stderr, "Parent: Error: wait(%d) failed: child_pid %d\n", pid, child_pid);
                    REQUIRE_MSG("wait for child failed", false);
                } else {
                    if( child_pid != pid ) {
                        jau::fprintf_td(stderr, "Parent: Error: wait(%d) terminated child_pid pid %d\n", pid, child_pid);
                        REQUIRE(child_pid == pid);
                    }
                    if( !WIFEXITED(pid_status) ) {
                        jau::fprintf_td(stderr, "Parent: Error: wait(%d) terminated abnormally child_pid %d, pid_status %d\n", pid, child_pid, pid_status);
                        REQUIRE(true == WIFEXITED(pid_status));
                    }
                    if( EXIT_SUCCESS != WEXITSTATUS(pid_status) ) {
                        jau::fprintf_td(stderr, "Parent: Error: wait(%d) exit with failure child_pid %d, exit_code %d\n", pid, child_pid, WEXITSTATUS(pid_status));
                        REQUIRE(EXIT_SUCCESS == WEXITSTATUS(pid_status));
                    }
                }
            } else {
                // fork failed
                jau::fprintf_td(stderr, "fork failed %d, %s\n", errno, ::strerror(errno));
                REQUIRE_MSG( "fork failed", false );
            }
            return ph2;
        }

        void test21_dec_from_pipe_slow() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            for(size_t file_idx = 0; file_idx < fname_plaintext_lst.size(); ++file_idx) {
                if( IDX_65MiB == file_idx ) {
                    continue; // skip big file, too slow -> takes too long time to test
                }
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test21.enc."+std::to_string(file_idx));
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test21_dec_from_pipe_slow", plaintext_version, plaintext_version_parent,
                                                                         enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test21_dec_from_pipe: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test21_dec_from_pipe: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end();

                cipherpack::PackHeader ph2 = test_pipe_to_decrypt("test21", fname_encrypted_lst[file_idx], fname_decrypted_lst[file_idx],
                                     slow_buffer_sz, slow_delay,
                                     ph1.plaintext_hash_algo(), ph1.plaintext_hash());
                REQUIRE( ph2.isValid() == true );

                hash_retest(ph1.plaintext_hash_algo(),
                            fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                            fname_decrypted_lst[file_idx], ph2.plaintext_hash());
            }
        }

        void test22_dec_from_pipe_fast() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            for(size_t file_idx = 0; file_idx < fname_plaintext_lst.size(); ++file_idx) {
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test22.enc."+std::to_string(file_idx));
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test22_dec_from_pipe_fast", plaintext_version, plaintext_version_parent,
                                                                         enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test22_dec_from_pipe: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test22_dec_from_pipe: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end();

                cipherpack::PackHeader ph2 = test_pipe_to_decrypt("test22", fname_encrypted_lst[file_idx], fname_decrypted_lst[file_idx],
                                     cipherpack::Constants::buffer_size, jau::fractions_i64::zero,
                                     ph1.plaintext_hash_algo(), ph1.plaintext_hash());
                REQUIRE( ph2.isValid() == true );

                hash_retest(ph1.plaintext_hash_algo(),
                            fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                            fname_decrypted_lst[file_idx], ph2.plaintext_hash());
            }
        }

        // throttled, no content size, interruptReader() via set_eof() will avoid timeout
        static void feed_source_00_nosize_slow(jau::io::ByteInStream_Feed * enc_feed) {
            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id());
            while( !enc_stream.end_of_data() ) {
                uint8_t buffer[slow_buffer_sz];
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                    jau::sleep_for( slow_delay );
                }
            }
            (void)xfer_total;
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed->set_eof( enc_stream.fail() ? jau::io::async_io_result_t::FAILED : jau::io::async_io_result_t::SUCCESS );
        }

        // throttled, with content size
        static void feed_source_01_sized_slow(jau::io::ByteInStream_Feed * enc_feed) {
            jau::fs::file_stats fs_feed(enc_feed->id());
            const uint64_t file_size = fs_feed.size();
            enc_feed->set_content_size( file_size );

            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id());
            while( !enc_stream.end_of_data() && xfer_total < file_size ) {
                uint8_t buffer[slow_buffer_sz];
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                    jau::sleep_for( slow_delay );
                }
            }
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed->set_eof( xfer_total == file_size ? jau::io::async_io_result_t::SUCCESS : jau::io::async_io_result_t::FAILED );
        }

        // full speed, no content size
        static void feed_source_10_nosize_fast(jau::io::ByteInStream_Feed * enc_feed) {
            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id());
            while( !enc_stream.end_of_data() ) {
                uint8_t buffer[cipherpack::Constants::buffer_size];
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                }
            }
            (void)xfer_total;
            enc_feed->set_eof( enc_stream.fail() ? jau::io::async_io_result_t::FAILED : jau::io::async_io_result_t::SUCCESS );
        }

        // full speed, with content size
        static void feed_source_11_sized_fast(jau::io::ByteInStream_Feed * enc_feed) {
            jau::fs::file_stats fs_feed(enc_feed->id());
            const uint64_t file_size = fs_feed.size();
            enc_feed->set_content_size( file_size );

            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id());
            while( !enc_stream.end_of_data() && xfer_total < file_size ) {
                uint8_t buffer[cipherpack::Constants::buffer_size];
                size_t count = enc_stream.read(buffer, sizeof(buffer));
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed->write(buffer, count);
                }
            }
            enc_feed->set_eof( xfer_total == file_size ? jau::io::async_io_result_t::SUCCESS : jau::io::async_io_result_t::FAILED );
        }

        // full speed, no content size, interrupting @ 1024 bytes within our header
        static void feed_source_20_nosize_irqed_1k(jau::io::ByteInStream_Feed * enc_feed) {
            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id());
            while( !enc_stream.end_of_data() ) {
                uint8_t buffer[1024];
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
        static void feed_source_21_sized_irqed_quarter(jau::io::ByteInStream_Feed * enc_feed) {
            jau::fs::file_stats fs_feed(enc_feed->id());
            const uint64_t file_size = fs_feed.size();
            enc_feed->set_content_size( file_size );

            uint64_t xfer_total = 0;
            jau::io::ByteInStream_File enc_stream(enc_feed->id());
            while( !enc_stream.end_of_data() ) {
                uint8_t buffer[1024];
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

        void test31_fed_all_files() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            for(size_t file_idx = 0; file_idx < fname_plaintext_lst.size(); ++file_idx) {
                LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test31.enc."+std::to_string(file_idx));
                jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                         enc_pub_keys,
                                                                         sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                         source, fname_plaintext_lst[file_idx], "test31_fed_all_files", plaintext_version, plaintext_version_parent,
                                                                         enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                jau::PLAIN_PRINT(true, "test31_fed_all_files: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                jau::PLAIN_PRINT(true, "test31_fed_all_files: %s\n", ph1.to_string(true, true).c_str());
                REQUIRE( ph1.isValid() == true );
                enc_listener->check_counter_end();

                typedef std::function<void(jau::io::ByteInStream_Feed *)> feed_func_t;
                std::vector<feed_func_t> feed_funcs = { feed_source_00_nosize_slow, feed_source_01_sized_slow, feed_source_10_nosize_fast, feed_source_11_sized_fast };
                std::vector<std::string> feed_funcs_suffix = { "nosize_slow", "sized_slow", "nosize_fast", "sized_fast" };
                for(size_t func_idx=0; func_idx < feed_funcs.size(); ++func_idx) {
                    feed_func_t feed_func = feed_funcs[func_idx];
                    if( IDX_65MiB == file_idx && ( func_idx == 0 || func_idx == 1 ) ) {
                        continue; // skip big file, too slow -> takes too long time to test
                    }
                    std::string suffix = feed_funcs_suffix[func_idx];
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test31.dec."+std::to_string(file_idx)+"."+std::to_string(func_idx));
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(feed_func, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  dec_listener, ph1.plaintext_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test31_fed_all_files %s: Decypted %s to %s\n", suffix.c_str(), fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test31_fed_all_files %s: %s\n", suffix.c_str(), ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == true );
                    dec_listener->check_counter_end();

                    hash_retest(ph1.plaintext_hash_algo(),
                                fname_plaintext_lst[file_idx], ph1.plaintext_hash(),
                                fname_decrypted_lst[file_idx], ph2.plaintext_hash());
                }
            }
        }

        void test34_enc_dec_fed_irq() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            {
                const size_t file_idx = IDX_65MiB;
                {
                    LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test34.enc."+std::to_string(file_idx));
                    jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                    cipherpack::PackHeader ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                             enc_pub_keys,
                                                                             sign_sec_key1_fname, sign_sec_key_passphrase,
                                                                             source, fname_plaintext_lst[file_idx], "test34_enc_dec_fed_irq", plaintext_version, plaintext_version_parent,
                                                                             enc_listener, cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test34_enc_dec_fed_irq: Encrypted %s to %s\n", fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test34_enc_dec_fed_irq: %s\n", ph1.to_string(true, true).c_str());
                    REQUIRE( ph1.isValid() == true );
                    enc_listener->check_counter_end();
                }
                {
                    // full speed, no content size, interrupting @ 1024 bytes within our header
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test34.dec.e1."+std::to_string(file_idx));
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_20_nosize_irqed_1k, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  dec_listener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test34_enc_dec_fed_irq: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test34_enc_dec_fed_irq: %s\n", ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                    dec_listener->check_counter_end();
                }
                {
                    // full speed, with content size, interrupting 1/4 way
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test34.dec.e2."+std::to_string(file_idx));
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_21_sized_irqed_quarter, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  dec_listener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test34_enc_dec_fed_irq: Decypted %s to %s\n", fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test34_enc_dec_fed_irq: %s\n", ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                    dec_listener->check_counter_end();
                }
            }
        }

        void test41_abort_stream() {
            const std::vector<std::string> enc_pub_keys { enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname };
            const std::vector<std::string> sign_pub_keys { sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname };
            for(int abort_item=1; abort_item<=3; ++abort_item) {
                const size_t file_idx = IDX_xbuffersz;
                cipherpack::PackHeader ph1;
                {
                    LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test41.enc.1."+std::to_string(abort_item), true /* send_content */);
                    enc_listener->set_abort(abort_item);
                    jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                    ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                      enc_pub_keys,
                                                      sign_sec_key1_fname, sign_sec_key_passphrase,
                                                      source, fname_plaintext_lst[file_idx], "test41_enc_1."+std::to_string(abort_item), plaintext_version, plaintext_version_parent,
                                                      enc_listener,
                                                      cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test41_enc_1.%d: Encrypted %s to %s\n", abort_item, fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test41_enc_1.%d: %s\n", abort_item, ph1.to_string(true, true).c_str());
                    REQUIRE( ph1.isValid() == false );
                    enc_listener->check_counter_end(0);
                }
                {
                    LoggingCipherpackListenerRef enc_listener = std::make_shared<LoggingCipherpackListener>("test41.enc.2."+std::to_string(abort_item), true /* send_content */);
                    jau::io::ByteInStream_File source(fname_plaintext_lst[file_idx]);
                    ph1 = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                      enc_pub_keys,
                                                      sign_sec_key1_fname, sign_sec_key_passphrase,
                                                      source, fname_plaintext_lst[file_idx], "test41_enc_2."+std::to_string(abort_item), plaintext_version, plaintext_version_parent,
                                                      enc_listener,
                                                      cipherpack::default_hash_algo(), fname_encrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test41_enc_2.%d: Encrypted %s to %s\n", abort_item, fname_plaintext_lst[file_idx].c_str(), fname_encrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test41_enc_2.%d: %s\n", abort_item, ph1.to_string(true, true).c_str());
                    REQUIRE( ph1.isValid() == true );
                    enc_listener->check_counter_end(source.content_size());
                }
                {
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test41.dec.1."+std::to_string(abort_item), true /* send_content */);
                    dec_listener->set_abort(abort_item);
                    jau::io::ByteInStream_File enc_stream(fname_encrypted_lst[file_idx]);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_stream,
                                                                                  dec_listener, ph1.plaintext_hash_algo(), fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test41_dec.1.%d: Decypted %s to %s\n", abort_item, fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test41_dec.1.%d: %s\n", abort_item, ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                    dec_listener->check_counter_end(0);
                }
                if( !jau::io::uri_tk::protocol_supported("http:") ) {
                    jau::PLAIN_PRINT(true, "http not supported, abort\n");
                } else {
                    httpd_start();
                    const std::string uri_encrypted = url_input_root + fname_encrypted_lst[file_idx];
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test41.dec.2."+std::to_string(abort_item), true /* send_content */);
                    dec_listener->set_abort(abort_item);
                    jau::io::ByteInStream_URL enc_stream(uri_encrypted, io_timeout);
                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_stream,
                                                                                  dec_listener, ph1.plaintext_hash_algo(), fname_decrypted_lst[file_idx]);
                    jau::PLAIN_PRINT(true, "test41_dec.2.%d: Decypted %s to %s\n", abort_item, fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test41_dec.2.%d: %s\n", abort_item, ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                    dec_listener->check_counter_end(0);
                }
                {
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test41.dec.3."+std::to_string(abort_item), true /* send_content */);
                    dec_listener->set_abort(abort_item);
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_11_sized_fast, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  dec_listener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        enc_feed.close(); // ends feeder_thread loop
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test41_dec.3.%d: Decypted %s to %s\n", abort_item, fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test41_dec.3.%d: %s\n", abort_item, ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                    dec_listener->check_counter_end(0);
                }
                {
                    LoggingCipherpackListenerRef dec_listener = std::make_shared<LoggingCipherpackListener>("test41.dec.4."+std::to_string(abort_item), true /* send_content */);
                    dec_listener->set_abort(abort_item);
                    jau::io::ByteInStream_Feed enc_feed(fname_encrypted_lst[file_idx], io_timeout);
                    std::thread feeder_thread= std::thread(&feed_source_10_nosize_fast, &enc_feed);

                    cipherpack::PackHeader ph2 = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                                  enc_feed,
                                                                                  dec_listener, cipherpack::default_hash_algo(), fname_decrypted_lst[file_idx]);
                    if( feeder_thread.joinable() ) {
                        enc_feed.close(); // ends feeder_thread loop
                        feeder_thread.join();
                    }
                    jau::PLAIN_PRINT(true, "test41_dec.4.%d: Decypted %s to %s\n", abort_item, fname_encrypted_lst[file_idx].c_str(), fname_decrypted_lst[file_idx].c_str());
                    jau::PLAIN_PRINT(true, "test41_dec.4.%d: %s\n", abort_item, ph2.to_string(true, true).c_str());
                    REQUIRE( ph2.isValid() == false );
                    dec_listener->check_counter_end(0);
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
            REQUIRE( true == cipherpack::hash_util::append_to_file(hash_file, source_stats.path(), cipherpack::default_hash_algo(), *source_hash));

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
            REQUIRE( true == cipherpack::hash_util::append_to_file(hash_file, dest_stats.path(), cipherpack::default_hash_algo(), *dest_hash));

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

METHOD_AS_TEST_CASE( Test01Cipherpack::test00_enc_dec_file_single,"test00_enc_dec_file_single",   "[file][file_ok][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test01_enc_dec_all_files,  "test01_enc_dec_all_files",   "[file][file_ok][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test02_enc_dec_file_misc,  "test02_enc_dec_file_misc",   "[file][file_ok][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test03_enc_dec_file_perf,  "test03_enc_dec_file_perf",   "[file][file_ok][file_fast][fast][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test04_enc_dec_file_error, "test04_enc_dec_file_error",  "[file][file_error][error]");

METHOD_AS_TEST_CASE( Test01Cipherpack::test11_dec_http_all_files, "test11_dec_http_all_files",  "[http][http_ok][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test12_dec_http_misc,      "test12_dec_http_misc",       "[http][http_ok][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test13_dec_http_perf,      "test13_dec_http_perf",       "[http][http_ok][http_fast][fast][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test14_dec_http_error,     "test14_dec_http_error",      "[http][http_error][error]");

METHOD_AS_TEST_CASE( Test01Cipherpack::test21_dec_from_pipe_slow, "test21_dec_from_pipe_slow",  "[pipe][pipe_ok][pipe_slow][slow][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test22_dec_from_pipe_fast, "test22_dec_from_pipe_fast",  "[pipe][pipe_ok][pipe_fast][fast][ok]");

METHOD_AS_TEST_CASE( Test01Cipherpack::test31_fed_all_files,      "test31_fed_all_files",       "[feed][feed_ok][ok]");
METHOD_AS_TEST_CASE( Test01Cipherpack::test34_enc_dec_fed_irq,    "test34_enc_dec_fed_irq",     "[feed][feed_error][error]");

METHOD_AS_TEST_CASE( Test01Cipherpack::test41_abort_stream,       "test41_abort_stream",          "[abort][error]");

METHOD_AS_TEST_CASE( Test01Cipherpack::test50_copy_and_verify,    "test50_copy_and_verify",     "[copy][file][ok]");
