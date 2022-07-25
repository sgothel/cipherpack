/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#include <iostream>
#include <cassert>
#include <cinttypes>
#include <cstring>

#include <cipherpack/cipherpack.hpp>

#include <jau/debug.hpp>

extern "C" {
    #include <unistd.h>
}

using namespace jau::fractions_i64_literals;

static void print_usage(const char* progname) {
    std::string bname = jau::fs::basename(progname);
    fprintf(stderr, "Usage %s pack [-epk <enc-pub-key>]+ -ssk <sign-sec-key> [-sskp <sign-sec-key-passphrase>]? "
                    "[-target_path <target-path-filename>]? [-subject <string>]? [-version <file-version-str>]? [-version_parent <file-version-parent-str>]? "
                    "[-hash <plaintext-hash-algo>]? [-hashout <plaintext-hash-outfile>]? [-verbose]? [-out <output-filename>]? [<input-source>]?\n", bname.c_str());
    fprintf(stderr, "Usage %s unpack [-spk <sign-pub-key>]+ -dsk <dec-sec-key> [-dskp <dec-sec-key-passphrase>]? "
                    "[-hash <plaintext-hash-algo>]? [-hashout <plaintext-hash-outfile>]? [-verbose]? [-out <output-filename>]? [<input-source>]?\n", bname.c_str());
    fprintf(stderr, "Usage %s hash [-hash <hash-algo>]? [-verbose]? [-out <output-filename>]? [<input-source>]?\n", bname.c_str());
    fprintf(stderr, "Usage %s hashcheck [-verbose]? [<input-hash-signatures-file>]?\n", bname.c_str());
}

/**
 * cipherpack command line tool.
 *
 * Examples:
 * - File based operation
 *   - `cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 -out a.enc plaintext.bin`
 *   - `cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 -out a.dec a.enc`
 *   - `cipherpack hash -out a.hash jaulib/test_data`
 * - Pipe based operation
 *   - `cat plaintext.bin | cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 > a.enc`
 *   - `cat a.enc | cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 > a.dec`
 *   - `cat a.dec | cipherpack hash jaulib/test_data`
 * - Pipe based full streaming
 *   - `cat plaintext.bin | cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 | cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 > a.dec`
 *
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[])
{
    cipherpack::environment::get();
#if 0
    fprintf(stderr, "Called '%s' with %d arguments:\n", (argc>0?argv[0]:"exe"), argc-1);
    for(int i=1; i<argc; i++) {
        fprintf(stderr, "[%d] '%s'\n", i, argv[i]);
    }
    fprintf(stderr, "\n");
#endif
    int argi = 1;

    if( argi >= argc ) {
        print_usage(argv[0]);
        return -1;
    }
    const std::string command = argv[argi++];

    if( command == "pack") {
        std::vector<std::string> enc_pub_keys;
        std::string sign_sec_key_fname;
        jau::io::secure_string sign_sec_key_passphrase;
        std::string target_path;
        std::string subject;
        std::string plaintext_version = "0";
        std::string plaintext_version_parent = "0";
        std::string plaintext_hash_algo(cipherpack::default_hash_algo());
        std::string plaintext_fname_output; // none
        bool verbose = false;
        std::string fname_output = "/dev/stdout"; // stdout default
        std::string fname_input = "/dev/stdin"; // stdin default
        for(; argi < argc; ++argi) {
            if( 0 == strcmp("-epk", argv[argi]) && argi + 1 < argc ) {
                enc_pub_keys.push_back( argv[++argi] );
            } else if( 0 == strcmp("-ssk", argv[argi]) && argi + 1 < argc ) {
                sign_sec_key_fname = argv[++argi];
            } else if( 0 == strcmp("-sskp", argv[argi]) && argi + 1 < argc ) {
                char* argv_pp = argv[++argi];
                size_t pp_len = strlen(argv_pp);
                sign_sec_key_passphrase = jau::io::secure_string(argv_pp, pp_len);
                ::explicit_bzero(argv_pp, pp_len);
            } else if( 0 == strcmp("-target_path", argv[argi]) && argi + 1 < argc ) {
                target_path = argv[++argi];
            } else if( 0 == strcmp("-subject", argv[argi]) && argi + 1 < argc ) {
                subject = argv[++argi];
            } else if( 0 == strcmp("-version", argv[argi]) && argi + 1 < argc ) {
                plaintext_version = argv[++argi];
            } else if( 0 == strcmp("-version_parent", argv[argi]) && argi + 1 < argc ) {
                plaintext_version_parent = argv[++argi];
            } else if( 0 == strcmp("-hash", argv[argi]) && argi + 1 < argc ) {
                plaintext_hash_algo = argv[++argi];
            } else if( 0 == strcmp("-hashout", argv[argi]) && argi + 1 < argc ) {
                plaintext_fname_output = argv[++argi];
            } else if( 0 == strcmp("-out", argv[argi]) && argi + 1 < argc ) {
                fname_output = argv[++argi];
            } else if( 0 == strcmp("-verbose", argv[argi]) ) {
                verbose = true;
            } else if( argi == argc - 1 ) {
                fname_input = argv[argi];
            }
        }
        if( target_path.empty() ) {
            target_path = fname_input;
        }
        if( 0 == enc_pub_keys.size() ||
            sign_sec_key_fname.empty() )
        {
            jau::PLAIN_PRINT(true, "Pack: Error: Arguments incomplete");
            print_usage(argv[0]);
            return -1;
        }

        std::unique_ptr<jau::io::ByteInStream> input = jau::io::to_ByteInStream(fname_input); // 20_s default timeout if uri
        if( nullptr == input ) {
            jau::PLAIN_PRINT(true, "Pack: Error: source '%s' failed to open", fname_input.c_str());
            return -1;
        }
        cipherpack::PackHeader ph = cipherpack::encryptThenSign(cipherpack::CryptoConfig::getDefault(),
                                                                enc_pub_keys, sign_sec_key_fname, sign_sec_key_passphrase,
                                                                *input, target_path, subject,
                                                                plaintext_version, plaintext_version_parent,
                                                                std::make_shared<cipherpack::CipherpackListener>(),
                                                                plaintext_hash_algo, fname_output);
        if( !plaintext_fname_output.empty() ) {
            cipherpack::hash_util::append_to_file(plaintext_fname_output, fname_input, ph.getPlaintextHashAlgo(), ph.getPlaintextHash());
        }
        if( verbose ) {
            jau::PLAIN_PRINT(true, "Pack: Encrypted %s to %s", fname_input.c_str(), fname_output.c_str());
            jau::PLAIN_PRINT(true, "Pack: %s", ph.toString(true, true).c_str());
        }
        return ph.isValid() ? 0 : -1;
    }
    if( command == "unpack") {
        std::vector<std::string> sign_pub_keys;
        std::string dec_sec_key_fname;
        jau::io::secure_string dec_sec_key_passphrase;
        std::string plaintext_hash_algo(cipherpack::default_hash_algo());
        std::string plaintext_fname_output; // none
        bool verbose = false;
        std::string fname_output = "/dev/stdout"; // stdout default
        std::string fname_input = "/dev/stdin"; // stdin default
        for(; argi < argc; ++argi) {
            if( 0 == strcmp("-spk", argv[argi]) && argi + 1 < argc ) {
                sign_pub_keys.push_back( argv[++argi] );
            } else if( 0 == strcmp("-dsk", argv[argi]) && argi + 1 < argc ) {
                dec_sec_key_fname = argv[++argi];
            } else if( 0 == strcmp("-dskp", argv[argi]) && argi + 1 < argc ) {
                char* argv_pp = argv[++argi];
                size_t pp_len = strlen(argv_pp);
                dec_sec_key_passphrase = jau::io::secure_string(argv_pp, pp_len);
                ::explicit_bzero(argv_pp, pp_len);
            } else if( 0 == strcmp("-hash", argv[argi]) && argi + 1 < argc ) {
                plaintext_hash_algo = argv[++argi];
            } else if( 0 == strcmp("-hashout", argv[argi]) && argi + 1 < argc ) {
                plaintext_fname_output = argv[++argi];
            } else if( 0 == strcmp("-out", argv[argi]) && argi + 1 < argc ) {
                fname_output = argv[++argi];
            } else if( 0 == strcmp("-verbose", argv[argi]) ) {
                verbose = true;
            } else if( argi == argc - 1 ) {
                fname_input = argv[argi];
            }
        }
        if( 0 == sign_pub_keys.size() ||
            dec_sec_key_fname.empty() )
        {
            jau::PLAIN_PRINT(true, "Unpack: Error: Arguments incomplete");
            print_usage(argv[0]);
            return -1;
        }

        std::unique_ptr<jau::io::ByteInStream> input = jau::io::to_ByteInStream(fname_input); // 20_s default timeout if uri
        if( nullptr == input ) {
            jau::PLAIN_PRINT(true, "Unpack: Error: source '%s' failed to open", fname_input.c_str());
            return -1;
        }
        cipherpack::PackHeader ph = cipherpack::checkSignThenDecrypt(sign_pub_keys, dec_sec_key_fname, dec_sec_key_passphrase,
                                                                     *input,
                                                                     std::make_shared<cipherpack::CipherpackListener>(),
                                                                     plaintext_hash_algo, fname_output);
        if( !plaintext_fname_output.empty() ) {
            cipherpack::hash_util::append_to_file(plaintext_fname_output, ph.getTargetPath(), ph.getPlaintextHashAlgo(), ph.getPlaintextHash());
        }
        // dec_sec_key_passphrase.resize(0);
        if( verbose ) {
            jau::PLAIN_PRINT(true, "Unpack: Decypted %s to %s", fname_input.c_str(), fname_output.c_str());
            jau::PLAIN_PRINT(true, "Unpack: %s", ph.toString(true, true).c_str());
        }
        return ph.isValid() ? 0 : -1;
    }
    if( command == "hash") {
        std::string hash_algo(cipherpack::default_hash_algo());
        bool verbose = false;
        std::string fname_output = "/dev/stdout"; // stdout default
        std::string fname_input = "/dev/stdin"; // stdin default
        for(; argi < argc; ++argi) {
            if( 0 == strcmp("-hash", argv[argi]) && argi + 1 < argc ) {
                hash_algo = argv[++argi];
            } else if( 0 == strcmp("-out", argv[argi]) && argi + 1 < argc ) {
                fname_output = argv[++argi];
            } else if( 0 == strcmp("-verbose", argv[argi]) ) {
                verbose = true;
            } else if( argi == argc - 1 ) {
                fname_input = argv[argi];
            }
        }
        uint64_t bytes_hashed = 0;
        std::unique_ptr<std::vector<uint8_t>> hash = cipherpack::hash_util::calc(hash_algo, fname_input, bytes_hashed); // 20_s default timeout if uri
        if( nullptr != hash ) {
            std::string hash_str = jau::bytesHexString(hash->data(), 0, hash->size(), true /* lsbFirst */, true /* lowerCase */);
            cipherpack::hash_util::append_to_file(fname_output, fname_input, hash_algo, *hash);
            if( verbose ) {
                jau::PLAIN_PRINT(true, "Hash: algo '%s', bytes %s, '%s' of '%s'", hash_algo.c_str(), jau::to_decstring(bytes_hashed).c_str(),
                        hash_str.c_str(), fname_input.c_str());
            }
            return 0;
        }
        return -1;
    }
    if( command == "hashcheck") {
        bool verbose = false;
        std::string fname_input = "/dev/stdin"; // stdin default
        for(; argi < argc; ++argi) {
            if( 0 == strcmp("-verbose", argv[argi]) ) {
                verbose = true;
            } else if( argi == argc - 1 ) {
                fname_input = argv[argi];
            }
        }
        std::ifstream in(fname_input, std::ios::in | std::ios::binary);
        if( in.bad() ) {
            jau::PLAIN_PRINT(true, "HashCheck: Error: Couldn't open file '%s'", fname_input.c_str());
            return -1;
        }
        int line_no = 0;
        std::string hash_line;
        while( std::getline(in, hash_line) ) {
            ++line_no;
            std::string hash_algo;
            std::string hash_value;
            std::string hashed_file;
            char* haystack = const_cast<char*>( hash_line.data() );
            {
                char* p = std::strstr(haystack, " ");
                if( nullptr == p ) {
                    jau::PLAIN_PRINT(true, "HashCheck: Error: %s:%d: No separator to hash value found", fname_input.c_str(), line_no);
                    return -1;
                }
                *p = 0; // EOS
                hash_algo = std::string(haystack);
                haystack = p + 1;
            }
            {
                char* p = std::strstr(haystack, " *");
                if( nullptr == p ) {
                    jau::PLAIN_PRINT(true, "HashCheck: Error: %s:%d: No separator to hashed file found", fname_input.c_str(), line_no);
                    return -1;
                }
                *p = 0; // EOS
                hash_value = std::string(haystack);
                haystack = p + 2;
            }
            hashed_file = std::string(haystack);
            {
                jau::fs::file_stats hashed_file_stats(hashed_file);
                if( hashed_file_stats.is_fd() ) {
                    jau::PLAIN_PRINT(true, "HashCheck: Ignored: %s:%d: Named file descriptor: %s",
                            fname_input.c_str(), line_no, hashed_file_stats.to_string().c_str());
                    continue;
                }
            }
            const std::string hash_line2 = hash_algo+" "+hash_value+" *"+hashed_file;
            uint64_t bytes_hashed = 0;
            std::unique_ptr<std::vector<uint8_t>> hash2 = cipherpack::hash_util::calc(hash_algo, hashed_file, bytes_hashed); // 20_s default timeout if uri
            if( nullptr == hash2 ) {
                jau::PLAIN_PRINT(true, "HashCheck: Error: %s:%d: Bad format: %s", fname_input.c_str(), line_no, hash_line2.c_str());
                return -1;
            }
            const std::string hash_value2 = jau::bytesHexString(hash2->data(), 0, hash2->size(), true /* lsbFirst */, true /* lowerCase */);
            if( hash_value2 != hash_value ) {
                const std::string hash_line3 = hash_algo+" "+hash_value2+" *"+hashed_file;
                jau::PLAIN_PRINT(true, "HashCheck: Error: %s:%d: Hash value mismatch", fname_input.c_str(), line_no);
                jau::PLAIN_PRINT(true,"- expected: %s", hash_line2.c_str());
                jau::PLAIN_PRINT(true,"- produced: %s", hash_line3.c_str());
                return -1;
            } else if( verbose ) {
                const std::string hash_line3 = hash_algo+" "+hash_value2+" *"+hashed_file;
                jau::PLAIN_PRINT(true, "HashCheck: OK: %s:%d: %s", fname_input.c_str(), line_no, hash_line3.c_str());
            }
        }
        return 0;
    }
    jau::PLAIN_PRINT(true, "Pack: Error: Unknown command");
    print_usage(argv[0]);
    return -1;
}
