/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#include <fstream>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

#include <botan_all.h>

using namespace elevator;

const std::string Cipherpack::package_magic      = "ZAF_ELEVATOR_0002";

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

std::string Cipherpack::PackInfo::getCreationTimeString(const bool local) const noexcept {
    return IOUtil::getTimestampString(ts_creation_sec, local);
}

std::string Cipherpack::PackInfo::toString() const noexcept {
    std::string source_enc_s = source_enc ? " (E)" : "";
    std::string stored_enc_s = stored_enc ? " (E)" : "";
    std::string res = "PackInfo[";
    res += "source "+source+source_enc_s+
           ", filename[header "+header_filename+", stored "+stored_filename+stored_enc_s+
           "], creation "+getCreationTimeString(false)+
           " UTC, version["+std::to_string(payload_version)+
           ", parent "+std::to_string(payload_version_parent)+
           "], valid "+std::to_string( isValid() )+"]";
    return res;
}
