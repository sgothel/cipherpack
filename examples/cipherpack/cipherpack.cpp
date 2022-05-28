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
using namespace jau::fractions_i64_literals;

static void print_usage(const char* progname) {
    fprintf(stderr, "Usage %s pack [-epk <enc-pub-key>]+ -ssk <sign-sec-key> -sskp <sign-sec-key-passphrase> -in <input-filename> -target_path <target-path-filename> "
                    "-intention <string> -version <file-version> -version_parent <file-version-parent> -out <output-filename>\n", progname);
    fprintf(stderr, "Usage %s unpack [-spk <sign-pub-key>]+ -dsk <dec-sec-key> -dskp <dec-sec-key-passphrase> -in <input-source> -out <output-filename>\n", progname);
}

int main(int argc, char *argv[])
{
    fprintf(stderr, "Called %s with %d arguments: ", (argc>0?argv[0]:"exe"), argc-1);
    for(int i=0; i<argc; i++) {
        fprintf(stderr, "%s ", argv[i]);
    }
    fprintf(stderr, "\n");
    int argi = 0;

    if( 1+1 >= argc ) {
        print_usage(argv[0]);
        return -1;
    }
    const bool overwrite = true;
    const std::string command = argv[++argi];

    if( command == "pack") {
        std::vector<std::string> enc_pub_keys;
        std::string sign_sec_key_fname;
        std::string sign_sec_key_passphrase;
        std::string fname_input;
        std::string target_path;
        std::string intention;
        uint64_t payload_version = 0;
        uint64_t payload_version_parent = 0;
        std::string fname_output;
        for(int i=argi; i + 1 < argc; ++i) {
            if( 0 == strcmp("-epk", argv[i]) ) {
                enc_pub_keys.push_back( argv[++i] );
            } else if( 0 == strcmp("-ssk", argv[i]) ) {
                sign_sec_key_fname = argv[++i];
            } else if( 0 == strcmp("-sskp", argv[i]) ) {
                sign_sec_key_passphrase = argv[++i];
            } else if( 0 == strcmp("-in", argv[i]) ) {
                fname_input = argv[++i];
            } else if( 0 == strcmp("-target_path", argv[i]) ) {
                target_path = argv[++i];
            } else if( 0 == strcmp("-intention", argv[i]) ) {
                intention = argv[++i];
            } else if( 0 == strcmp("-version", argv[i]) ) {
                payload_version = (uint64_t)atoll(argv[++i]);
            } else if( 0 == strcmp("-version_parent", argv[i]) ) {
                payload_version_parent = (uint64_t)atoll(argv[++i]);
            } else if( 0 == strcmp("-out", argv[i]) ) {
                fname_output = argv[++i];
            }
        }
        if( 0 == enc_pub_keys.size() ||
            sign_sec_key_fname.empty() ||
            fname_input.empty() ||
            target_path.empty() ||
            fname_output.empty() )
        {
            jau::PLAIN_PRINT(true, "Pack: Error: Arguments incomplete\n");
            print_usage(argv[0]);
            return -1;
        }

        cipherpack::PackInfo pinfo = cipherpack::encryptThenSign_RSA1(cipherpack::CryptoConfig::getDefault(),
                                                                      enc_pub_keys, sign_sec_key_fname, sign_sec_key_passphrase,
                                                                      fname_input, target_path, intention,
                                                                      payload_version, payload_version_parent,
                                                                      fname_output, overwrite);
        jau::PLAIN_PRINT(true, "Pack: Encrypted %s to %s\n", fname_input.c_str(), fname_output.c_str());
        jau::PLAIN_PRINT(true, "Pack: %s\n", pinfo.toString(true, true).c_str());
        return pinfo.isValid() ? 0 : -1;
    }
    if( command == "unpack") {
        std::vector<std::string> sign_pub_keys;
        std::string dec_sec_key_fname;
        std::string dec_sec_key_passphrase;
        std::string source;
        std::string fname_output;
        for(int i=argi; i + 1 < argc; ++i) {
            if( 0 == strcmp("-spk", argv[i]) ) {
                sign_pub_keys.push_back( argv[++i] );
            } else if( 0 == strcmp("-dsk", argv[i]) ) {
                dec_sec_key_fname = argv[++i];
            } else if( 0 == strcmp("-dskp", argv[i]) ) {
                dec_sec_key_passphrase = argv[++i];
            } else if( 0 == strcmp("-in", argv[i]) ) {
                source = argv[++i];
            } else if( 0 == strcmp("-out", argv[i]) ) {
                fname_output = argv[++i];
            }
        }
        if( 0 == sign_pub_keys.size() ||
            dec_sec_key_fname.empty() ||
            source.empty() ||
            fname_output.empty() )
        {
            jau::PLAIN_PRINT(true, "Unpack: Error: Arguments incomplete\n");
            print_usage(argv[0]);
            return -1;
        }

        std::unique_ptr<io::ByteStream> enc_stream;
        const std::string proto = source.substr(0, 5);
        if( proto == "http:" ) {
            enc_stream = std::make_unique<io::ByteStream_URL>(source, 20_s);
        } else {
            enc_stream = std::make_unique<io::ByteStream_File>(source, true /* use_binary */);
        }
        cipherpack::PackInfo pinfo = cipherpack::checkSignThenDecrypt_RSA1(sign_pub_keys, dec_sec_key_fname, dec_sec_key_passphrase,
                                                                           *enc_stream, fname_output, overwrite);
        // dec_sec_key_passphrase.resize(0);
        jau::PLAIN_PRINT(true, "Unpack: Decypted %s to %s\n", source.c_str(), fname_output.c_str());
        jau::PLAIN_PRINT(true, "Unpack: %s\n", pinfo.toString(true, true).c_str());
        return pinfo.isValid() ? 0 : -1;
    }
    jau::PLAIN_PRINT(true, "Pack: Error: Unknown command\n");
    print_usage(argv[0]);
    return -1;
}
