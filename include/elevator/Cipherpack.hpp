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

#ifndef CRYPTO_HPP_
#define CRYPTO_HPP_

#include <string>
#include <cstdint>
#include <functional>

#include <jau/basic_types.hpp>
#include <jau/file_util.hpp>

#include <elevator/data_source.hpp>

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
        /**
         * Simple package information POD, capturing an invalid or valid
         * processed package creation (encryption) or un-packaging (decryption).
         * <pre>
         * VENDOR_VERSION: major-version . minor.version - client . client-build
         * Example: '1.0-0.5'
         * </pre>
         */
        class PackInfo {
            private:
                jau::fraction_timespec ts_creation;
                std::string source;
                bool source_enc;
                jau::fs::file_stats stored_file_stats;
                bool stored_enc;
                std::string target_path;
                std::string intention;
                uint32_t payload_version; // FIXME: std::string  VENDOR_VERSION
                uint32_t payload_version_parent; // FIXME: std::string VENDOR_VERSION
                std::string host_key_fingerprint;
                std::string term_key_fingerprint;
                bool valid;

            public:
                /** default ctor, denoting an invalid package information */
                PackInfo()
                : ts_creation( jau::getWallClockTime() ),
                  source("none"), source_enc(false),
                  stored_file_stats(), stored_enc(false),
                  target_path("none"),
                  intention("none"),
                  payload_version(0), payload_version_parent(0),
                  host_key_fingerprint(), term_key_fingerprint(),
                  valid(false)
                { }

                /** Source ctor, denoting an invalid package information */
                PackInfo(const jau::fraction_timespec ts_creation_, const std::string& source_, const bool source_enc_)
                : ts_creation(ts_creation_),
                  source(source_), source_enc(source_enc_),
                  stored_file_stats(), stored_enc(false),
                  target_path("none"),
                  intention("none"),
                  payload_version(0), payload_version_parent(0),
                  host_key_fingerprint(), term_key_fingerprint(),
                  valid(false)
                { }

                /** Complete ctor, denoting a valid package information */
                PackInfo(const jau::fraction_timespec ts_creation_,
                         const std::string& source_, const bool source_enc_,
                         const jau::fs::file_stats& stored_file_stats_, bool stored_enc_,
                         const std::string& target_path_,
                         const std::string& intention_,
                         const uint32_t pversion, const uint32_t pversion_parent,
                         const std::string& host_key_fingerprint_,
                         const std::string& term_key_fingerprint_ )
                : ts_creation(ts_creation_),
                  source(source_), source_enc(source_enc_),
                  stored_file_stats(stored_file_stats_), stored_enc(stored_enc_),
                  target_path(target_path_),
                  intention(intention_),
                  payload_version(pversion), payload_version_parent(pversion_parent),
                  host_key_fingerprint(host_key_fingerprint_), term_key_fingerprint(term_key_fingerprint_),
                  valid(true)
                { }

                /** Returns the creation time since Unix epoch */
                constexpr const jau::fraction_timespec& getCreationTime() const noexcept { return ts_creation; }

                const std::string& getSource() const noexcept { return source; }
                bool isSourceEncrypted() const noexcept { return source_enc; }

                /** Returns the full file_stats for the stored target file, incl. validated size etc. */
                const jau::fs::file_stats& getStoredFileStats() const noexcept { return stored_file_stats; }
                /** Returns the stored file's size in bytes. */
                size_t getStoredFileSize() const noexcept { return stored_file_stats.size(); }
                /** Returns the stored file's path. */
                std::string getStoredFilePath() const noexcept { return stored_file_stats.path(); }
                bool isStoredFileEncrypted() const noexcept { return stored_enc; }

                /** Returns the designated decrypted target path of the file from DER-Header-1. */
                const std::string& getTargetPath() const noexcept { return target_path; }

                constexpr uint32_t getPayloadVersion() const noexcept { return payload_version;}
                constexpr uint32_t getPayloadVersionParent() const noexcept { return payload_version_parent;}

                /** Return the used host key fingerprint used to sign. If decrypting indicates the matching host key. */
                const std::string& getHostKeyFingerprint() const noexcept { return host_key_fingerprint; }

                /** If decrypting, return the used terminal key fingerprint used to decrypt. Otherwise empty. */
                const std::string& getTermKeyFingerprint()  const noexcept { return term_key_fingerprint; }

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

        static std::shared_ptr<Botan::Public_Key> load_public_key(const std::string& pubkey_fname);
        static std::shared_ptr<Botan::Private_Key> load_private_key(const std::string& privatekey_fname, const std::string& passphrase);

        /**
         * Package magic {@code ZAF_ELEVATOR_0005}.
         */
        static const std::string package_magic;

        /**
         * Public key fingerprint hash algorithm is {@code SHA-256}.
         */
        static const std::string fingerprint_hash_algo;

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
         *     ASN1_Type::OctetString               target_path            // designated target path for file
         *     ASN1_Type::OctetString               intention              // designated intention of payload for application
         *     ASN1_Type::Integer                   net_file_size          // file size of decrypted payload
         *     ASN1_Type::Integer                   creation_timestamp_sec
         *     ASN1_Type::Integer                   payload_version
         *     ASN1_Type::Integer                   payload_version_parent
         *     ASN1_Type::[ObjectId|OctetString]    sign_algo_[oid|name] = "EMSA1(SHA-256)",
         *     ASN1_Type::ObjectId                  pk_alg_id 'AlgorithmIdentifier' = ( "RSA/OAEP" + "SHA-256" ),
         *     ASN1_Type::ObjectId                  cipher_algo_oid = "ChaCha20Poly1305",
         *     ASN1_Type::OctetString               fingerprt_host,        // fingerprint of public host key used for header signature
         *     ASN1_Type::Integer                   encrypted_fkey_count,  // number of encrypted file-keys
         *     ASN1_Type::OctetString               fingerprt_term_1,      // fingerprint of public terminal key_1 used for encrypted_fkey_term_1
         *     ASN1_Type::OctetString               encrypted_fkey_term_1, // encrypted file-key with public terminal key_1, decrypted with secret terminal key_1
         *     ASN1_Type::OctetString               fingerprt_term_2,      // fingerprint of public terminal key_1 used for encrypted_fkey_term_2
         *     ASN1_Type::OctetString               encrypted_fkey_term_2, // encrypted file-key with public terminal key_1, decrypted with secret terminal key_1
         *     ....
         *     ASN1_Type::OctetString               nonce,
         * },
         * DER Header 2 {
         *     ASN1_Type::OctetString               header_sign_host       // signed with secret host key and using public host key to verify, matching fingerprt_host
         * },
         * uint8_t encrypted_data[]
         * </pre>
         *
         * @param enc_pub_keys           The public keys of the receiver (terminal device), used to encrypt the file-key for multiple parties.
         * @param sign_sec_key_fname     The private key of the host (pack provider), used to sign the DER-Header-1 incl encrypted file-key for authenticity.
         * @param passphrase             The passphrase for `sign_sec_key_fname`, may be an empty string for no passphrase.
         * @param input_fname            The filename of the plaintext payload.
         * @param designated_fname           The designated filename for the decrypted file as written in the DER-Header-1
         * @param payload_version        The version of this payload
         * @param payload_version_parent The version of this payload's parent
         * @param output_fname           The filename of the ciphertext pack file target.
         * @param overwrite              If true, overwrite a potentially existing `outfilename`.
         * @return PackInfo, which is PackInfo::isValid() if successful, otherwise not.
         *
         * @see #checkSignThenDecrypt_RSA1()
         */
        static PackInfo encryptThenSign_RSA1(const std::vector<std::string> &enc_pub_keys,
                                             const std::string &sign_sec_key_fname, const std::string &passphrase,
                                             const std::string &input_fname,
                                             const std::string &target_path, const std::string &intention,
                                             const uint64_t payload_version,
                                             const uint64_t payload_version_parent,
                                             const std::string &output_fname, const bool overwrite);

        /**
         * See {@link #encryptThenSign_RSA1()} for details.
         *
         * @param sign_pub_keys      The potential public keys used by the host (pack provider) to verify the DER-Header-1 signature
         *                           and hence the authenticity of the encrypted file-key. Proves authenticity of the file.
         * @param dec_sec_key_fname  The private key of the receiver (terminal device), used to decrypt the file-key.
         *                           It shall match one of the keys used to encrypt.
         * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty string for no passphrase.
         * @param source             The DataSource_Closeable of the ciphertext pack file source, containing the payload.
         * @param output_fname       The filename of the resulting plaintext target.
         * @param overwrite If true, overwrite a potentially existing `outfilename`.
         * @return PackInfo, which is PackInfo::isValid() if successful, otherwise not.
         */
        static PackInfo checkSignThenDecrypt_RSA1(const std::vector<std::string>& sign_pub_keys,
                                                  const std::string &dec_sec_key_fname, const std::string &passphrase,
                                                  io::DataSource_Closeable &source,
                                                  const std::string &output_fname, const bool overwrite);
};

} // namespace elevator

#endif /* CRYPTO_HPP_ */
