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

#ifndef JAU_CIPHERPACK_HPP_
#define JAU_CIPHERPACK_HPP_

#include <string>
#include <cstdint>
#include <functional>

#include <botan_all.h>

#include <jau/basic_types.hpp>
#include <jau/file_util.hpp>
#include <jau/byte_stream.hpp>
#include <jau/io_util.hpp>
#include <jau/environment.hpp>
#include <jau/java_uplink.hpp>

/**
 * @anchor cipherpack_overview
 * ### Cipherpack Overview
 * Cipherpack, a secure packaging utility utilizing RSA encryption and signatures to ensure
 * privacy and authenticity of the package's source.
 *
 * The package's header handle the personalized public- and private-key mechanism,
 * securing the high-performance symmetric encryption for the high volume payload.
 *
 * Implementation uses an Authenticated Encryption with Additional Data (AEAD) encryption+MAC cipher algo,
 * i.e. {@link cipherpack::constants::aead_cipher_algo}.
 *
 * ### Cipherpack Implementation
 * #### Implementation Status
 * READY TO USE
 *
 * #### Cipherpack Operations
 * The following RSA encryption + signature and symmetric payload operations are performed:
 * - Writing a DER Header-1, containing the encrypted symmetric file-keys for each public terminal key and further {@link PackInfo} details.
 * - Writing a DER Header-2, containing the DER-Header-1 signature using.
 * - The encrypted payload, i.e. the ciphertext using the symmetric file-key for encryption + MAC via AEAD `ChaCha20Poly1305`.
 *
 * Implementation performs all operation `in-place` without redundant copies.
 *
 * @anchor cipherpack_stream
 * #### Cipherpack Data Stream
 * The cipherpack stream will be produced as follows:
 * ```
 * DER Header 1 {
 *     ASN1_Type::OctetString               package_magic
 *     ASN1_Type::OctetString               target_path            // designated target path for file
 *     ASN1_Type::Integer                   content_size           // plain content size, i.e. decrypted payload
 *     ASN1_Type::Integer                   creation_timestamp_sec
 *     ASN1_Type::OctetString               intention              // designated intention of payload for application
 *     ASN1_Type::Integer                   payload_version
 *     ASN1_Type::Integer                   payload_version_parent
 *     ASN1_Type::OctetString               pk_type                // public-key type: "RSA"
 *     ASN1_Type::OctetString               pk_fingerprt_hash_algo // public-key fingerprint hash: "SHA-256"
 *     ASN1_Type::OctetString               pk_enc_padding_algo    // public-key encryption padding: "OAEP"
 *     ASN1_Type::OctetString               pk_enc_hash_algo       // public-key encryption hash: "SHA-256"
 *     ASN1_Type::OctetString               pk_sign_algo           // "EMSA1(SHA-256)",
 *     ASN1_Type::ObjectId                  sym_enc_mac_oid        // "ChaCha20Poly1305",
 *     ASN1_Type::OctetString               nonce,
 *     ASN1_Type::OctetString               fingerprt_host         // fingerprint of public host key used for header signature
 *     ASN1_Type::Integer                   encrypted_fkey_count,  // number of encrypted file-keys
 *     ASN1_Type::OctetString               fingerprt_term_1,      // fingerprint of public terminal key_1 used for encrypted_fkey_term_1
 *     ASN1_Type::OctetString               encrypted_fkey_term_1, // encrypted file-key with public terminal key_1, decrypted with secret terminal key_1
 *     ASN1_Type::OctetString               fingerprt_term_2,      // fingerprint of public terminal key_1 used for encrypted_fkey_term_2
 *     ASN1_Type::OctetString               encrypted_fkey_term_2, // encrypted file-key with public terminal key_1, decrypted with secret terminal key_1
 *     ....
 * },
 * DER Header 2 {
 *     ASN1_Type::OctetString               header_sign_host       // signed with secret host key and using public host key to verify, matching fingerprt_host
 * },
 * uint8_t encrypted_data[]
 * ```
 *
 * @see encryptThenSign()
 * @see checkSignThenDecrypt()
 *
 */
namespace cipherpack {


    #define JAVA_MAIN_PACKAGE "org/cipherpack/"

     class Environment {
         public:
             static void env_init() noexcept;
     };

    /**
     * CryptoConfig, contains crypto algorithms settings given at encryption wired via the @see @ref cipherpack_stream "Cipherpack Data Stream",
     * hence received and used at decryption if matching keys are available.
     */
    struct CryptoConfig {
        std::string pk_type;
        std::string pk_fingerprt_hash_algo;
        std::string pk_enc_padding_algo;
        std::string pk_enc_hash_algo;
        std::string pk_sign_algo;
        std::string sym_enc_algo;
        size_t sym_enc_nonce_bytes;

        /**
         * - Public-Key type is {@code RSA}.
         * - Public key fingerprint hash algorithm is {@code SHA-256}.
         * - Public-Key padding algorithm is {@code OAEP}.
         * - Public-Key hash algorithm is {@code SHA-256}.
         * - Public-Key hash algorithm is {@code EMSA1(SHA-256)}.
         * - Symmetric Authenticated Encryption with Additional Data (AEAD) encryption+MAC cipher algo is {@code ChaCha20Poly1305}.
         * - Symmetric AEAD ChaCha Nonce Sizes are usually: 64-bit classic, 96-bit IETF, 192-bit big for one message per file-key.
         */
        static CryptoConfig getDefault() noexcept;

        CryptoConfig() noexcept
        : pk_type(),
          pk_fingerprt_hash_algo(),
          pk_enc_padding_algo(),
          pk_enc_hash_algo(),
          pk_sign_algo(),
          sym_enc_algo(),
          sym_enc_nonce_bytes(0)
        { }

        CryptoConfig(const std::string& pk_type_,
                     const std::string& pk_fingerprt_hash_algo_,
                     const std::string& pk_enc_padding_algo_,
                     const std::string& pk_enc_hash_algo_,
                     const std::string& pk_sign_algo_,
                     const std::string& sym_enc_algo_,
                     const size_t sym_enc_nonce_bitsize_) noexcept
        : pk_type(pk_type_),
          pk_fingerprt_hash_algo(pk_fingerprt_hash_algo_),
          pk_enc_padding_algo(pk_enc_padding_algo_),
          pk_enc_hash_algo(pk_enc_hash_algo_),
          pk_sign_algo(pk_sign_algo_),
          sym_enc_algo(sym_enc_algo_),
          sym_enc_nonce_bytes(sym_enc_nonce_bitsize_)
        { }

        bool valid() const noexcept;

        std::string to_string() const noexcept;
    };

    class Constants {
        public:
            /** Intermediate copy buffer size of {@code 4096 bytes}, usually the page-size. */
            constexpr static const size_t buffer_size = 4096;

            /**
             * Package magic {@code CIPHERPACK_0001}.
             */
            static const std::string package_magic;
    };

    /**
     * Cipherpack header less encrypted keys or signatures as described in @ref cipherpack_stream "Cipherpack Data Stream"
     *
     * @see @ref cipherpack_overview "Cipherpack Overview"
     */
    class PackHeader {
        private:
            std::string target_path;
            uint64_t content_size;
            jau::fraction_timespec ts_creation;
            std::string intention;
            uint32_t payload_version; // FIXME: std::string  VENDOR_VERSION
            uint32_t payload_version_parent; // FIXME: std::string VENDOR_VERSION
            CryptoConfig crypto_cfg;
            std::string host_key_fingerprint;
            std::vector<std::string> term_keys_fingerprint;
            ssize_t term_key_fingerprint_used_idx;
            bool valid;

        public:
            /** default ctor, denoting an invalid package header. */
            PackHeader()
            : target_path("none"),
              content_size(0),
              ts_creation( jau::getWallClockTime() ),
              intention("none"),
              payload_version(0),
              payload_version_parent(0),
              crypto_cfg(),
              host_key_fingerprint(),
              term_keys_fingerprint(),
              term_key_fingerprint_used_idx(-1),
              valid(false)
            { }

            /** ctor, denoting an invalid package header. */
            PackHeader(const jau::fraction_timespec ts_creation_)
            : target_path("none"),
              content_size(0),
              ts_creation( ts_creation_ ),
              intention("none"),
              payload_version(0),
              payload_version_parent(0),
              crypto_cfg(),
              host_key_fingerprint(),
              term_keys_fingerprint(),
              term_key_fingerprint_used_idx(-1),
              valid(false)
            { }

            /** Complete ctor, denoting a complete package header, see @ref cipherpack_stream "Cipherpack Data Stream". */
            PackHeader(const std::string& target_path_,
                       const uint64_t content_size_,
                       const jau::fraction_timespec ts_creation_,
                       const std::string& intention_,
                       const uint32_t pversion, const uint32_t pversion_parent,
                       const CryptoConfig& crypto_cfg_,
                       const std::string& host_key_fingerprint_,
                       const std::vector<std::string>& term_keys_fingerprint_,
                       const size_t term_key_fingerprint_used_idx_,
                       const bool valid_)
            : target_path(target_path_),
              content_size(content_size_),
              ts_creation(ts_creation_),
              intention(intention_),
              payload_version(pversion), payload_version_parent(pversion_parent),
              crypto_cfg(crypto_cfg_),
              host_key_fingerprint(host_key_fingerprint_),
              term_keys_fingerprint(term_keys_fingerprint_),
              term_key_fingerprint_used_idx(term_key_fingerprint_used_idx_),
              valid(valid_)
            { }

            /** Returns the designated decrypted target path of the file from DER-Header-1, see @ref cipherpack_stream "Cipherpack Data Stream". */
            const std::string& getTargetPath() const noexcept { return target_path; }

            /** Returns the plain content size in bytes, i.e. decrypted payload size, see @ref cipherpack_stream "Cipherpack Data Stream". */
            uint64_t getContentSize() const noexcept { return content_size; }

            /** Returns the creation time since Unix epoch, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const jau::fraction_timespec& getCreationTime() const noexcept { return ts_creation; }

            /** Returns the intention of the file from DER-Header-1, see @ref cipherpack_stream "Cipherpack Data Stream". */
            const std::string& getIntention() const noexcept { return intention; }

            /** Returns the payload version, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr uint32_t getPayloadVersion() const noexcept { return payload_version;}

            /** Returns the payload's parent version, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr uint32_t getPayloadVersionParent() const noexcept { return payload_version_parent;}

            const CryptoConfig& getCryptoConfig() const noexcept { return crypto_cfg; }

            /**
             * Return the used host key fingerprint used to sign, see @ref cipherpack_stream "Cipherpack Data Stream".
             */
            const std::string& getHostKeyFingerprint() const noexcept { return host_key_fingerprint; }

            /**
             * Return the list of public keys fingerprints used to encrypt the file-key, see @ref cipherpack_stream "Cipherpack Data Stream".
             */
            const std::vector<std::string>& getTermKeysFingerprint() const noexcept { return term_keys_fingerprint; }

            /**
             * Return the index of the matching public key fingerprints used to decrypt the file-key, see @ref cipherpack_stream "Cipherpack Data Stream".
             *
             * @return the fingerprint index of getTermKeysFingerprint(), or -1 if not found or performing the encryption operation.
             */
            ssize_t getUsedTermKeyFingerprintIndex() const noexcept { return term_key_fingerprint_used_idx; }

            /**
             * Return a string representation
             * @param show_crypto_algos pass true if used crypto algos shall be shown, otherwise suppressed (default).
             * @param force_all_fingerprints if true always show all getTermKeysFingerprint(), otherwise show only the getTermKeysFingerprint() if >= 0 (default).
             * @return string representation
             */
            std::string toString(const bool show_crypto_algos=false, const bool force_all_fingerprints=false) const noexcept;

            void setValid(const bool v) { valid = v; }
            bool isValid() const noexcept { return valid; }
    };

    /**
     * Cipherpack info with PackHeader as described in @ref cipherpack_stream "Cipherpack Data Stream"
     * and additional operational data.
     */
    class PackInfo {
        private:
            PackHeader header;
            std::string source;
            bool source_enc;
            std::string destination;
            bool stored_enc;

        public:
            /** default ctor, denoting an invalid package information */
            PackInfo()
            : header(),
              source("none"), source_enc(false),
              destination(), stored_enc(false)
            { }

            /** Source ctor, denoting an invalid package information */
            PackInfo(const PackHeader& header_, const std::string& source_, const bool source_enc_)
            : header(header_),
              source(source_), source_enc(source_enc_),
              destination(), stored_enc(false)
            { header.setValid(false); }

            /** Complete ctor, denoting a valid package information */
            PackInfo(const PackHeader& header_,
                     const std::string& source_, const bool source_enc_,
                     const std::string& destination_, bool stored_enc_)
            : header(header_),
              source(source_), source_enc(source_enc_),
              destination(destination_), stored_enc(stored_enc_)
            { }

            /** Returns the PackHeader information, see @ref cipherpack_stream "Cipherpack Data Stream". */
            const PackHeader& getHeader() const noexcept { return header; }

            bool isValid() const noexcept { return header.isValid(); }

            const std::string& getSource() const noexcept { return source; }
            bool isSourceEncrypted() const noexcept { return source_enc; }

            const std::string& getDestination() const noexcept { return destination; }
            void setDestination(const std::string& v) noexcept { destination=v; }
            bool isStoredFileEncrypted() const noexcept { return stored_enc; }

            /**
             * Return a string representation
             * @param show_crypto_algos pass true if used crypto algos shall be shown, otherwise suppressed (default).
             * @param force_all_fingerprints if true always show all getTermKeysFingerprint(), otherwise show only the getTermKeysFingerprint() if >= 0 (default).
             * @return string representation
             */
            std::string toString(const bool show_crypto_algos=false, const bool force_all_fingerprints=false) const noexcept;
    };

    std::shared_ptr<Botan::Public_Key> load_public_key(const std::string& pubkey_fname);
    std::shared_ptr<Botan::Private_Key> load_private_key(const std::string& privatekey_fname, const std::string& passphrase);

    class CipherpackListener : public jau::JavaUplink {
        public:
            /**
             * Informal user notification about an error via text message.
             *
             * This message will be send before a subsequent notifyHeader() and notifyEnd() with an error indication.
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param msg the error message
             */
            virtual void notifyError(const bool decrypt_mode, const std::string& msg) noexcept {
                (void)decrypt_mode;
                (void)msg;
            }

            /**
             * User notification of PackHeader
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param header the PackHeader
             * @param verified true if header signature is verified and deemed valid, otherwise false regardless of true == PackHeader::isValid().
             */
            virtual void notifyHeader(const bool decrypt_mode, const PackHeader& header, const bool verified) noexcept {
                (void)decrypt_mode;
                (void)header;
                (void)verified;
            }

            /**
             * User notification about content streaming progress.
             *
             * In case contentProcessed() gets called, notifyProgress() is called thereafter.
             *
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param content_size the unencrypted content size
             * @param bytes_processed the number of unencrypted bytes processed
             * @see contentProcessed()
             */
            virtual void notifyProgress(const bool decrypt_mode, const uint64_t content_size, const uint64_t bytes_processed) noexcept {
                (void)decrypt_mode;
                (void)content_size;
                (void)bytes_processed;
            }

            /**
             * User notification of process completion.
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param header the PackHeader
             * @param success true if process has successfully completed and result is deemed valid, otherwise result is invalid regardless of true == PackHeader::isValid().
             */
            virtual void notifyEnd(const bool decrypt_mode, const PackHeader& header, const bool success) noexcept {
                (void)decrypt_mode;
                (void)header;
                (void)success;
            }

            /**
             * User provided information whether process shall send the processed content via contentProcessed() or not
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @return true if process shall call contentProcessed(), otherwise false (default)
             * @see contentProcessed()
             */
            virtual bool getSendContent(const bool decrypt_mode) const noexcept {
                (void)decrypt_mode;
                return false;
            }

            /**
             * User callback to receive the actual processed content, either the generated cipherpack or plaintext content depending on decrypt_mode.
             *
             * This callback is only enabled if getSendContent() returns true.
             *
             * In case contentProcessed() gets called, notifyProgress() is called thereafter.
             *
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param is_header true if passed data is part of the header, otherwise false. Always false if decrypt_mode is true.
             * @param data the processed content, either the generated cipherpack or plaintext content depending on decrypt_mode.
             * @param is_final true if this is the last content call, otherwise false
             * @return true to signal continuation, false to end streaming.
             * @see getSendContent()
             */
            virtual bool contentProcessed(const bool decrypt_mode, const bool is_header, jau::io::secure_vector<uint8_t>& data, const bool is_final) noexcept {
                (void)decrypt_mode;
                (void)is_header;
                (void)data;
                (void)is_final;
                return true;
            }

            ~CipherpackListener() noexcept override {}

            std::string toString() const noexcept override { return "CipherpackListener["+jau::to_hexstring(this)+"]"; }

            std::string get_java_class() const noexcept override {
                return java_class();
            }
            static std::string java_class() noexcept {
                return std::string(JAVA_MAIN_PACKAGE "CipherpackListener");
            }

            /**
             * Default comparison operator, merely testing for same memory reference.
             * <p>
             * Specializations may override.
             * </p>
             */
            virtual bool operator==(const CipherpackListener& rhs) const noexcept
            { return this == &rhs; }

            bool operator!=(const CipherpackListener& rhs) const noexcept
            { return !(*this == rhs); }

    };
    typedef std::shared_ptr<CipherpackListener> CipherpackListenerRef;

    /**
     * Encrypt then sign the source producing a cipherpack stream passed to the destination_fn consumer.
     *
     * @param crypto_cfg             The used CryptoConfig, consider using CryptoConfig::getDefault()
     * @param enc_pub_keys           The public keys of the receiver (terminal device), used to encrypt the file-key for multiple parties.
     * @param sign_sec_key_fname     The private key of the host (pack provider), used to sign the DER-Header-1 incl encrypted file-key for authenticity.
     * @param passphrase             The passphrase for `sign_sec_key_fname`, may be an empty string for no passphrase.
     * @param source                 The source jau::io::ByteInStream of the plaintext payload.
     * @param target_path            The designated target_path for the decrypted file as written in the DER-Header-1
     * @param payload_version        The version of this payload
     * @param payload_version_parent The version of this payload's parent
     * @param listener               The CipherpackListener listener used for notifications and optionally
     *                               to send the ciphertext destination bytes via CipherpackListener::contentProcessed()
     * @return PackInfo, which is PackInfo::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see checkSignThenDecrypt()
     */
    PackInfo encryptThenSign(const CryptoConfig& crypto_cfg,
                             const std::vector<std::string>& enc_pub_keys,
                             const std::string& sign_sec_key_fname, const std::string& passphrase,
                             jau::io::ByteInStream& source,
                             const std::string& target_path, const std::string& intention,
                             const uint64_t payload_version,
                             const uint64_t payload_version_parent,
                             CipherpackListenerRef listener);

    /**
     * Encrypt then sign the source producing a cipherpack destination file.
     *
     * @param crypto_cfg             The used CryptoConfig, consider using CryptoConfig::getDefault()
     * @param enc_pub_keys           The public keys of the receiver (terminal device), used to encrypt the file-key for multiple parties.
     * @param sign_sec_key_fname     The private key of the host (pack provider), used to sign the DER-Header-1 incl encrypted file-key for authenticity.
     * @param passphrase             The passphrase for `sign_sec_key_fname`, may be an empty string for no passphrase.
     * @param source                 The source jau::io::ByteInStream of the plaintext payload.
     * @param designated_fname       The designated filename for the decrypted file as written in the DER-Header-1
     * @param payload_version        The version of this payload
     * @param payload_version_parent The version of this payload's parent
     * @param destination_fname      The filename of the ciphertext destination file.
     * @param overwrite              If true, overwrite a potentially existing `outfilename`.
     * @param listener               The CipherpackListener listener used for notifications and optionally
     *                               to send the ciphertext destination bytes via CipherpackListener::contentProcessed()
     * @return PackInfo, which is PackInfo::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see checkSignThenDecrypt()
     */
    PackInfo encryptThenSign(const CryptoConfig& crypto_cfg,
                             const std::vector<std::string>& enc_pub_keys,
                             const std::string& sign_sec_key_fname, const std::string& passphrase,
                             jau::io::ByteInStream& source,
                             const std::string& target_path, const std::string& intention,
                             const uint64_t payload_version,
                             const uint64_t payload_version_parent,
                             const std::string& destination_fname, const bool overwrite,
                             CipherpackListenerRef listener);

    /**
     * Check cipherpack signature of the source then pass decrypted payload to the destination_fn consumer.
     *
     * @param sign_pub_keys      The potential public keys used by the host (pack provider) to verify the DER-Header-1 signature
     *                           and hence the authenticity of the encrypted file-key. Proves authenticity of the file.
     * @param dec_sec_key_fname  The private key of the receiver (terminal device), used to decrypt the file-key.
     *                           It shall match one of the keys used to encrypt.
     * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty string for no passphrase.
     * @param source             The source jau::io::ByteInStream of the cipherpack containing the encrypted payload.
     * @param listener           The CipherpackListener listener used for notifications and optionally
     *                           to send the plaintext destination bytes via CipherpackListener::contentProcessed()
     * @return PackInfo, which is PackInfo::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see encryptThenSign()
     *
     */
    PackInfo checkSignThenDecrypt(const std::vector<std::string>& sign_pub_keys,
                                  const std::string &dec_sec_key_fname, const std::string &passphrase,
                                  jau::io::ByteInStream &source,
                                  CipherpackListenerRef listener);

    /**
     * Check cipherpack signature of the source then decrypt into the plaintext destination file.
     *
     * @param sign_pub_keys      The potential public keys used by the host (pack provider) to verify the DER-Header-1 signature
     *                           and hence the authenticity of the encrypted file-key. Proves authenticity of the file.
     * @param dec_sec_key_fname  The private key of the receiver (terminal device), used to decrypt the file-key.
     *                           It shall match one of the keys used to encrypt.
     * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty string for no passphrase.
     * @param source             The source jau::io::ByteInStream of the cipherpack containing the encrypted payload.
     * @param destination_fname  The filename of the plaintext destination file.
     * @param overwrite If true, overwrite a potentially existing `destination_fname`.
     * @param listener           The CipherpackListener listener used for notifications and optionally
     *                           to send the plaintext destination bytes via CipherpackListener::contentProcessed()
     * @return PackInfo, which is PackInfo::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see encryptThenSign()
     *
     */
    PackInfo checkSignThenDecrypt(const std::vector<std::string>& sign_pub_keys,
                                  const std::string &dec_sec_key_fname, const std::string &passphrase,
                                  jau::io::ByteInStream &source,
                                  const std::string &destination_fname, const bool overwrite,
                                  CipherpackListenerRef listener);

} // namespace cipherpack

#endif /* JAU_CIPHERPACK_HPP_ */
