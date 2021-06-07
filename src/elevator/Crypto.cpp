/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#include <fstream>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

#include <botan_all.h>

using namespace elevator;

const std::string Cipherpack::package_magic      = "ZAF_ELEVATOR_0001";

const std::string Cipherpack::rsa_padding_algo   = "OAEP"; // or "EME1"
const std::string Cipherpack::rsa_hash_algo      = "SHA-256";
const std::string Cipherpack::rsa_sign_algo      = "EMSA1(SHA-256)";

const std::string Cipherpack::aead_cipher_algo   = "ChaCha20Poly1305"; // or "AES-256/GCM"
const std::string Cipherpack::simple_cipher_algo = "ChaCha(20)";

std::unique_ptr<Botan::Public_Key> Cipherpack::load_public_key(const std::string& pubkey_fname) {
    Botan::DataSource_Stream key_data(pubkey_fname, false /* use_binary */);
    std::unique_ptr<Botan::Public_Key> key(Botan::X509::load_key(key_data));
    if( !key ) {
        ERR_PRINT("Couldn't load Key %s", pubkey_fname.c_str());
        return std::unique_ptr<Botan::Public_Key>();
    }
    if( key->algo_name() != "RSA" ) {
        ERR_PRINT("Key doesn't support RSA %s", pubkey_fname.c_str());
        return std::unique_ptr<Botan::Public_Key>();
    }
    return key;
}

std::unique_ptr<Botan::Private_Key> Cipherpack::load_private_key(const std::string& privatekey_fname, const std::string& passphrase) {
    Botan::DataSource_Stream key_data(privatekey_fname, false /* use_binary */);
    std::unique_ptr<Botan::Private_Key> key;
    if( passphrase.empty() ) {
        key = Botan::PKCS8::load_key(key_data);
    } else {
        key = Botan::PKCS8::load_key(key_data, passphrase);
    }
    if( !key ) {
        ERR_PRINT("Couldn't load Key %s", privatekey_fname.c_str());
        return std::unique_ptr<Botan::Private_Key>();
    }
    if( key->algo_name() != "RSA" ) {
        ERR_PRINT("Key doesn't support RSA %s", privatekey_fname.c_str());
        return std::unique_ptr<Botan::Private_Key>();
    }
    return key;
}

std::string Cipherpack::PackInfo::toString() const noexcept {
    std::string res = "PackInfo[";
    res += "filename "+filename;
    res += ", payload[version "+std::to_string(payload_version)+
           ", parent_version "+std::to_string(payload_version_parent)+
           ", size "+std::to_string(payload_size)+"], ";
    {
        std::time_t t0 = static_cast<std::time_t>(ts_creation_sec);
        struct std::tm tm_0;
        if( nullptr == ::gmtime_r( &t0, &tm_0 ) ) {
            res += "1970-01-01 00:00:00"; // 19 + 1
        } else {
            char b[20];
            strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &tm_0);
            res += std::string(b);
        }
    }
    res += ", valid "+std::to_string( isValid() )+"]";
    return res;
}
