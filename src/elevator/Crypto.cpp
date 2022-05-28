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

#include <fstream>

#include <elevator/elevator.hpp>

#include <jau/debug.hpp>

#include <botan_all.h>

using namespace elevator::cipherpack;

const std::string Constants::package_magic              = "ZAF_ELEVATOR_0006";

static const std::string default_pk_type                = "RSA";
static const std::string default_pk_fingerprt_hash_algo = "SHA-256";
static const std::string default_pk_enc_padding_algo    = "OAEP"; // or "EME1"
static const std::string default_pk_enc_hash_algo       = "SHA-256";
static const std::string default_pk_sign_algo           = "EMSA1(SHA-256)";

static const std::string default_sym_enc_mac_algo       = "ChaCha20Poly1305"; // or "AES-256/GCM"

/**
 * Symmetric Encryption nonce size in bytes.
 *
 * We only process one message per 'encrypted_key', hence small nonce size of 64 bit.
 *
 * ChaCha Nonce Sizes are usually: 64-bit classic, 96-bit IETF, 192-bit big
 */
static constexpr const size_t ChaCha_Nonce_BitSize = 64;

CryptoConfig CryptoConfig::getDefault() noexcept {
    return CryptoConfig (
        default_pk_type, default_pk_fingerprt_hash_algo,
        default_pk_enc_padding_algo, default_pk_enc_hash_algo,
        default_pk_sign_algo, default_sym_enc_mac_algo, ChaCha_Nonce_BitSize/8
    );
}

bool CryptoConfig::valid() const noexcept {
    return !pk_type.empty() &&
           !pk_fingerprt_hash_algo.empty() &&
           !pk_enc_padding_algo.empty() &&
           !pk_enc_hash_algo.empty() &&
           !pk_sign_algo.empty() &&
           !sym_enc_algo.empty() &&
           sym_enc_nonce_bytes > 0;
}

std::string CryptoConfig::toString() const noexcept {
    return "CCfg[pk[type '"+pk_type+"', fingerprt_hash '"+pk_fingerprt_hash_algo+"', enc_padding '"+pk_enc_padding_algo+
            "', enc_hash '"+pk_enc_hash_algo+"', sign '"+pk_sign_algo+
            "'], sym['"+sym_enc_algo+"', nonce "+std::to_string(sym_enc_nonce_bytes)+" byte]]";
}

std::shared_ptr<Botan::Public_Key> elevator::cipherpack::load_public_key(const std::string& pubkey_fname) {
    io::ByteStream_File key_data(pubkey_fname, false /* use_binary */);
    std::shared_ptr<Botan::Public_Key> key(Botan::X509::load_key(key_data));
    if( !key ) {
        ERR_PRINT("Couldn't load Key %s", pubkey_fname.c_str());
        return std::shared_ptr<Botan::Public_Key>();
    }
    if( key->algo_name() != "RSA" ) {
        ERR_PRINT("Key doesn't support RSA %s", pubkey_fname.c_str());
        return std::shared_ptr<Botan::Public_Key>();
    }
    return key;
}

std::shared_ptr<Botan::Private_Key> elevator::cipherpack::load_private_key(const std::string& privatekey_fname, const std::string& passphrase) {
    io::ByteStream_File key_data(privatekey_fname, false /* use_binary */);
    std::shared_ptr<Botan::Private_Key> key;
    if( passphrase.empty() ) {
        key = Botan::PKCS8::load_key(key_data);
    } else {
        key = Botan::PKCS8::load_key(key_data, passphrase);
    }
    if( !key ) {
        ERR_PRINT("Couldn't load Key %s", privatekey_fname.c_str());
        return std::shared_ptr<Botan::Private_Key>();
    }
    if( key->algo_name() != "RSA" ) {
        ERR_PRINT("Key doesn't support RSA %s", privatekey_fname.c_str());
        return std::shared_ptr<Botan::Private_Key>();
    }
    return key;
}

std::string PackHeader::toString(const bool show_crypto_algos, const bool force_all_fingerprints) const noexcept {
    const std::string crypto_str = show_crypto_algos ? crypto_cfg.toString() : "";

    std::string term_fingerprint;
    {
        if( 0 <= term_key_fingerprint_used_idx ) {
            term_fingerprint += "dec '"+term_keys_fingerprint.at(term_key_fingerprint_used_idx)+"', ";
        }
        if( force_all_fingerprints || 0 > term_key_fingerprint_used_idx ) {
            term_fingerprint += "enc[";
            int i = 0;
            for(const std::string& tkf : term_keys_fingerprint) {
                if( 0 < i ) {
                    term_fingerprint += ", ";
                }
                term_fingerprint += "'"+tkf+"'";
                ++i;
            }
            term_fingerprint += "]";
        }
    }

    std::string res = "Header[";
    res += "valid "+std::to_string( isValid() )+
           ", file[target_path "+target_path+", net_size "+jau::to_decstring(net_file_size).c_str()+
           "], creation "+ts_creation.to_iso8601_string(true)+" UTC, intention '"+intention+"', "+
           " version["+std::to_string(payload_version)+
           ", parent "+std::to_string(payload_version_parent)+crypto_str+
           "], fingerprints[sign/host '"+host_key_fingerprint+
           "', term["+term_fingerprint+
           "]]]";
    return res;
}

std::string PackInfo::toString(const bool show_crypto_algos, const bool force_all_fingerprints) const noexcept {
    std::string source_enc_s = source_enc ? " (E)" : "";
    std::string stored_enc_s = stored_enc ? " (E)" : "";
    std::string res = "Info["+header.toString(show_crypto_algos, force_all_fingerprints);
    res += ", source "+source+source_enc_s+
           ", stored "+stored_file_stats.to_string(true)+stored_enc_s+"]";
    return res;
}
