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

static const std::string opt_deconly("-deconly");

int main(int argc, char *argv[])
{
    bool dec_only = false;
    std::string fname_payload;
    fprintf(stderr, "Called Elevate::Crypt %s with %d arguments: ", (argc>0?argv[0]:"exe"), argc-1);
    for(int i=0; i<argc; i++) {
        fprintf(stderr, "%s ", argv[i]);
    }
    fprintf(stderr, "\n");
    argc--; // main
    int argi = 0;

    if( 0 == argc ) {
        fprintf(stderr, "Elevate::Crypt Usage %s [-deconly] <input>\n", argv[0]);
        return -1;
    }
    if( 1 <= argc && opt_deconly== argv[argi+1] ) {
        dec_only = true;
        fprintf(stderr, "Called Elevate::Crypt %s decrypt-only\n", argv[0]);
        argi++;
        argc--;
    }
    if( 1 <= argc ) {
        fname_payload = argv[++argi];
        fprintf(stderr, "Called Elevate::Crypt %s input %s\n", argv[0], fname_payload.c_str());
        argc--;
    }

    const bool overwrite = true;
    const std::string enc_pub_key_fname("../keys/terminal_rsa.pub.pem");
    const std::string dec_sec_key_fname("../keys/terminal_rsa");
    const std::string dec_sec_key_passphrase("");
    const std::string sign_pub_key_fname("../keys/host_rsa.pub.pem");
    const std::string sign_sec_key_fname("../keys/host_rsa");
    const std::string sign_sec_key_passphrase("");
    const std::string fname_encrypted = dec_only ? fname_payload : fname_payload+".enc";
    const std::string fname_decrypted = dec_only ? "out.dec" : fname_encrypted+".dec";

    bool res_enc;
    if( dec_only ) {
        res_enc = true;
    } else {
        res_enc = Cipherpack::encryptThenSign_RSA1(enc_pub_key_fname, sign_sec_key_fname, sign_sec_key_passphrase, fname_payload, fname_encrypted, overwrite);
        jau::PLAIN_PRINT(true, "Encrypt1 result: Output encrypted file %s: Result %d\n", fname_encrypted.c_str(), res_enc);
    }
    if( res_enc ) {
        std::unique_ptr<Botan::DataSource> enc_stream;
        const std::string proto = fname_encrypted.substr(0, 5);
        if( proto == "http:" ) {
            enc_stream = std::make_unique<DataSource_Http>(fname_encrypted);
        } else {
            enc_stream = std::make_unique<Botan::DataSource_Stream>(fname_encrypted, true /* use_binary */);
        }
        bool res_dec = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_key_fname, dec_sec_key_fname, dec_sec_key_passphrase, *enc_stream, fname_decrypted, overwrite);
        jau::PLAIN_PRINT(true, "Decrypted1 result: Output decrypted file %s: Result %d\n", fname_decrypted.c_str(), res_dec);
    }

    return 0;
}
