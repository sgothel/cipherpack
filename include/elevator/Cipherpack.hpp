/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#ifndef CRYPTO_HPP_
#define CRYPTO_HPP_

#include <string>
#include <cstdint>
#include <functional>

#include <jau/basic_types.hpp>

#include <botan_all.h>

namespace elevator {

/**
 * Cipherpack, a secure packaging utility utilizing RSA encryption and signatures to ensure
 * privacy and authenticity of the package's source.
 * <p>
 * The package's header handle the personalized public- and private-key mechanism,
 * securing the high-performance symmetric encryption for the high volume payload.
 * </p>
 * See {@link Cipherpack#encryptThenSign_RSA1()}.
 */
class Cipherpack {
    public:
        class PackInfo {
            private:
                std::string filename;
                uint32_t payload_version;
                uint32_t payload_version_parent;
                uint64_t payload_size;
                uint64_t ts_creation_sec;
                bool valid;

            public:
                PackInfo()
                : payload_version(0), payload_version_parent(0),
                  payload_size(0),
                  ts_creation_sec( jau::getWallClockSeconds() ),
                  valid(false)
                { }

                PackInfo(const uint32_t pversion, const uint32_t pversion_parent)
                : payload_version(pversion), payload_version_parent(pversion_parent),
                  payload_size(0),
                  ts_creation_sec( jau::getWallClockSeconds() ),
                  valid(false) // FIXME
                { }

                constexpr uint32_t getPayloadVersion() const noexcept { return payload_version;}
                constexpr uint32_t getPayloadVersionParent() const noexcept { return payload_version_parent;}
                constexpr uint64_t getPayloadSize() const noexcept { return payload_size;}

                /** Returns the creation timestamp in seconds since Unix epoch */
                constexpr uint64_t getCreationTime() const noexcept { return ts_creation_sec; }

                std::string toString() const noexcept;

                bool isValid() const noexcept { return valid; }
        };

    private:
        /** Intermediate copy buffer size of {@code 4096 bytes}, usually the page-size. */
        constexpr static const size_t buffer_size = 4096;

        /**
         * We only process one message per 'encrypted_key', hence small nonce size of 64 bit.
         * <p>
         * ChaCha Nonce Sizes are usually: 64-bit classic, 96-bit IETF, 192-bit big
         * </p>
         */
        constexpr static const size_t ChaCha_Nonce_Size = 64 / 8;

        static std::unique_ptr<Botan::Public_Key> load_public_key(const std::string& pubkey_fname);
        static std::unique_ptr<Botan::Private_Key> load_private_key(const std::string& privatekey_fname, const std::string& passphrase);

        /**
         * Package magic {@code ZAF_ELEVATOR_0002}.
         */
        static const std::string package_magic;

        /**
         * RSA padding algorithm is {@code OAEP}.
         */
        static const std::string rsa_padding_algo;
        /**
         * RSA hash algorithm is {@code SHA-256}.
         */
        static const std::string rsa_hash_algo;

        /**
         * RSA hash algorithm is {@code EMSA1(SHA-256)}.
         */
        static const std::string rsa_sign_algo;

        /**
         * Authenticated Encryption with Additional Data (AEAD) encryption+MAC cipher algo is {@code ChaCha20Poly1305}.
         */
        static const std::string aead_cipher_algo;

        /**
         * Simple encryption cipher algo is {@code ChaCha(20)} used for Encrypt-Then-Sign and CheckSign-Then-Decrypt
         */
        static const std::string simple_cipher_algo;

    public:
        /**
         * Implementation uses an Authenticated Encryption with Additional Data (AEAD) encryption+MAC cipher algo,
         * i.e. {@link #aead_cipher_algo}.
         *
         * <p>
         * READY TO USE
         * </p>
         *
         * <p>
         * The following RSA encryption + signature and symmetric payload operations are performed:
         * <ul>
         *   <li>Writing a DER Header-1, containing the encrypted symmetric key using `enc_pub_key_fname` and further {@link PackInfo} details.</li>
         *   <li>Writing a DER Header-2, containing the DER-Header-1 signature using `sign_sec_key_fname`, authenticating the complete Header-1. </li>
         *   <li>The encrypted payload, i.e. the ciphertext using Encryption + MAC via AEAD `ChaCha20Poly1305`.</li>
         * </ul>
         * Implementation performs all operation `in-place` without redundant copies.
         * </p>
         *
         * <p>
         * See {@link #checkSignThenDecrypt_RSA1()}.
         * </p>
         *
         * The encrypted stream will be produced as follows:
         * <pre>
         * DER Header 1 {
         *     ASN1_Type::OctetString               package_magic
         *     ASN1_Type::OctetString               filename
         *     ASN1_Type::Integer                   payload_version
         *     ASN1_Type::Integer                   payload_version_parent
         *     ASN1_Type::[ObjectId|OctetString]    sign_algo_[oid|name] = "EMSA1(SHA-256)",
         *     ASN1_Type::ObjectId                  pk_alg_id 'AlgorithmIdentifier' = ( "RSA/OAEP" + "SHA-256" ),
         *     ASN1_Type::ObjectId                  cipher_algo_oid = "ChaCha20Poly1305",
         *     ASN1_Type::OctetString               encrypted_key,
         *     ASN1_Type::OctetString               nonce,
         * },
         * DER Header 2 {
         *     ASN1_Type::OctetString               header_signature (of wired DER encoded data)
         * },
         * uint8_t encrypted_data[]
         * </pre>
         *
         * @param enc_pub_key_fname The public key of the receiver (terminal device), used to encrypt the symmetric key.
         * @param sign_sec_key_fname The private key of the host (pack provider), used to sign the DER-Header-1 incl encrypted symmetric key for authenticity.
         * @param passphrase The passphrase for `sign_sec_key_fname`, may be an empty string for no passphrase.
         * @param data_fname The filename of the plaintext payload.
         * @param outfilename The filename of the ciphertext pack file target.
         * @param overwrite If true, overwrite a potentially existing `outfilename`.
         * @return true if successful, otherwise false.
         *
         * @see #checkSignThenDecrypt_RSA1()
         */
        static bool encryptThenSign_RSA1(const std::string &enc_pub_key_fname,
                                         const std::string &sign_sec_key_fname, const std::string &passphrase,
                                         const std::string &data_fname,
                                         const std::string &outfilename, const bool overwrite);

        /**
         * See {@link #encryptThenSign_RSA1()} for details.
         *
         * @param sign_pub_key_fname The public key of the host (pack provider), used to verify the DER-Header-1 signature
         *                           and hence the encrypted symmetric key. Proves authenticity of the file.
         * @param dec_sec_key_fname  The private key of the receiver (terminal device), used to decrypt the symmetric key.
         * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty string for no passphrase.
         * @param source             The Botan::DataSource of the ciphertext pack file source, containing the payload.
         * @param outfilename        The filename of the resulting plaintext target.
         * @param overwrite If true, overwrite a potentially existing `outfilename`.
         * @return true if successful, otherwise false.
         */
        static bool checkSignThenDecrypt_RSA1(const std::string &sign_pub_key_fname,
                                              const std::string &dec_sec_key_fname, const std::string &passphrase,
                                              Botan::DataSource &source,
                                              const std::string &outfilename, const bool overwrite);
};

} // namespace elevator

#endif /* CRYPTO_HPP_ */
