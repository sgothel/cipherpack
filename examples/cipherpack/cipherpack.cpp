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

static void print_usage(const char* progname) {
    fprintf(stderr, "Usage %s pack <enc-pub-key> <sign-sec-key> <sign-sec-key-passphrase> <input-filename> <header-filename> "
                    "<file-version> <file-version-parent> <output-filename>\n", progname);
    fprintf(stderr, "Usage %s unpack <sign-pub-key> <dec-sec-key> <dec-sec-key-passphrase> <input-source> <output-filename>\n", progname);
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
        if( 8+1+1 != argc ) {
            print_usage(argv[0]);
            return -1;
        }
        const std::string enc_pub_key_fname = argv[++argi];
        const std::string sign_sec_key_fname = argv[++argi];
        std::string sign_sec_key_passphrase = argv[++argi];
        const std::string fname_input = argv[++argi];
        const std::string fname_header = argv[++argi];
        uint64_t payload_version = (uint64_t)atoll(argv[++argi]);
        uint64_t payload_version_parent = (uint64_t)atoll(argv[++argi]);
        const std::string fname_output = argv[++argi];

        Cipherpack::PackInfo pinfo = Cipherpack::encryptThenSign_RSA1(enc_pub_key_fname, sign_sec_key_fname, sign_sec_key_passphrase,
                                                                      fname_input, fname_header,
                                                                      payload_version, payload_version_parent,
                                                                      fname_output, overwrite);
        jau::PLAIN_PRINT(true, "Pack: Encrypted %s to %s\n", fname_input.c_str(), fname_output.c_str());
        jau::PLAIN_PRINT(true, "Pack: %s\n", pinfo.toString().c_str());
        return pinfo.isValid() ? 0 : -1;
    }
    if( command == "unpack") {
        if( 5+1+1 != argc ) {
            print_usage(argv[0]);
            return -1;
        }
        const std::string sign_pub_key_fname = argv[++argi];
        const std::string dec_sec_key_fname = argv[++argi];
        std::string dec_sec_key_passphrase = argv[++argi];
        const std::string source = argv[++argi];
        const std::string fname_output = argv[++argi];

        std::unique_ptr<Botan::DataSource> enc_stream;
        const std::string proto = source.substr(0, 5);
        if( proto == "http:" ) {
            enc_stream = std::make_unique<DataSource_Http>(source);
        } else {
            enc_stream = std::make_unique<Botan::DataSource_Stream>(source, true /* use_binary */);
        }
        Cipherpack::PackInfo pinfo = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_key_fname, dec_sec_key_fname, dec_sec_key_passphrase,
                                                                           *enc_stream, fname_output, overwrite);
        // dec_sec_key_passphrase.resize(0);
        jau::PLAIN_PRINT(true, "Unpack: Decypted %s to %s\n", source.c_str(), fname_output.c_str());
        jau::PLAIN_PRINT(true, "Unpack: %s\n", pinfo.toString().c_str());
        return pinfo.isValid() ? 0 : -1;
    }
    return -1;
}
