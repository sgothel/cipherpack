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

int main(int argc, char *argv[])
{
    std::string fname_payload;
    fprintf(stderr, "Called Elevate::Crypt %s with %d arguments: ", (argc>0?argv[0]:"exe"), argc-1);
    for(int i=0; i<argc; i++) {
        fprintf(stderr, "%s ", argv[i]);
    }
    fprintf(stderr, "\n");
    argc--; // main
    int argi = 0;

    if( 0 == argc ) {
        fprintf(stderr, "Elevate::Crypt Usage %s <payload-filename>\n", argv[0]);
        return -1;
    }
    if( 1 <= argc ) {
        fname_payload = argv[++argi];
        fprintf(stderr, "Called Elevate::Crypt %s payload %s\n", argv[0], fname_payload.c_str());
        argc--;
    }

#if 0
    int mode = 1;
    if( 1 <= argc ) {
        const char* a = argv[++argi];
        if( nullptr != a && 0 == strcmp("-old", a) ) {
            mode = 0;
        }
        fprintf(stderr, "Called Elevate::Crypt %s mode=0 (old)\n", argv[0]);
        argc--;
    }
#endif

    const bool overwrite = true;
    const std::string enc_pub_key_fname("keys/terminal_rsa.pub.pem");
    const std::string dec_sec_key_fname("keys/terminal_rsa");
    const std::string dec_sec_key_passphrase("");
    const std::string sign_pub_key_fname("keys/host_rsa.pub.pem");
    const std::string sign_sec_key_fname("keys/host_rsa");
    const std::string sign_sec_key_passphrase("");
    const std::string fname_encrypted(fname_payload+".enc");
    const std::string fname_decrypted(fname_encrypted+".dec");

#if 0
    if( 0 == mode ) {
        bool res_enc = Cipherpack::encrypt_RSA(enc_pub_key_fname, fname_payload, fname_encrypted, overwrite);
        jau::fprintf_td(stderr, "Encrypt0 result: Output encrypted file %s: Result %d\n", fname_encrypted.c_str(), res_enc);
        if( res_enc ) {
            bool res_dec = Cipherpack::decrypt_RSA(dec_sec_key_fname, dec_sec_key_passphrase, fname_encrypted, fname_decrypted, overwrite);
            jau::fprintf_td(stderr, "Decrypted0 result: Output decrypted file %s: Result %d\n", fname_decrypted.c_str(), res_dec);
        }
    } else {
#endif
        bool res_enc = Cipherpack::encryptThenSign_RSA1(enc_pub_key_fname, sign_sec_key_fname, sign_sec_key_passphrase, fname_payload, fname_encrypted, overwrite);
        jau::fprintf_td(stderr, "Encrypt1 result: Output encrypted file %s: Result %d\n", fname_encrypted.c_str(), res_enc);
        if( res_enc ) {
            bool res_dec = Cipherpack::checkSignThenDecrypt_RSA1(sign_pub_key_fname, dec_sec_key_fname, dec_sec_key_passphrase, fname_encrypted, fname_decrypted, overwrite);
            jau::fprintf_td(stderr, "Decrypted1 result: Output decrypted file %s: Result %d\n", fname_decrypted.c_str(), res_dec);
        }
#if 0
    }
#endif

    return 0;
}
