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

namespace cipherpack {

     /** @defgroup CipherpackAPI Cipherpack General User Level API
      *  General User level Cipherpack API types and functionality, see @ref cipherpack_overview "Cipherpack Overview".
      *
      * @anchor cipherpack_overview
      * ### Cipherpack Overview
      * *Cipherpack*, a secure stream processor utilizing public-key signatures to
      * authenticate the sender and public-key encryption of a symmetric-key for multiple receiver
      * ensuring their privacy and high-performance payload encryption.
      *
      * A *Cipherpack* can be understood as a message, which can be streamed via any media while,
      * file via
      * [ByteInStream_File](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__File.html)
      * and all [*libcurl* network protocols](https://curl.se/docs/url-syntax.html) via
      * [ByteInStream_URL](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__URL.html)
      * are *build-in* and supported.
      *
      * A user may use the media agnostic
      * [ByteInStream_Feed](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__Feed.html)
      * to produce the input stream by injecting data off-thread and a CipherpackListener to receive the processed output stream.
      *
      * *Cipherpack* is implemented using C++17 and accessible via C++ and Java.
      *
      * ### Cipherpack Implementation
      * #### Implementation Status
      * READY TO USE
      *
      * #### Cipherpack Operations
      * The following public-key signature and encryption, as well as symmetric-key payload encryption operations are performed:
      * - Writing a DER Header-1, containing the general message information and receiver count, see {@link PackHeader} details.
      * - Writing a DER Header for each recevr, containing the fingerprint, encrypted symmetric-key and encrypted symmetric-nonce.
      * - Writing a DER Header-2, containing the sender's signature over the whole header
      * - Writing the symmetrically encrypted payload, using the symmetric-key for encryption + MAC via AEAD `ChaCha20Poly1305`.
      *
      * Implementation performs all operation `in-place` without redundant copies, processing the stream.
      *
      * @anchor cipherpack_stream
      * #### Cipherpack Data Stream
      * The stream's header contains the sender's public-key fingerprint
      * and its signature for authentication by the receiving parties.
      *
      * Further, the stream contains triples per receiver, its public-key fingerprint,
      * the encrypted symmetric-key and the encrypted symmetric-nonce for each receiver,
      * allowing a secure messaging between multiple parties:
      * - Symmetric encryption of the actual payload ensures high-performance processing.
      * - Symmetric stream-key is unique for each message
      *
      * Implementation uses an Authenticated Encryption with Additional Data (AEAD) encryption+MAC cipher algo,
      * i.e. {@link cipherpack::constants::aead_cipher_algo}.
      *
      * The random nonce, unique for one message and used for the symmetric encryption is not a secret and doesn't have to be confidential.
      * However, since we already encrypt the symmetric-key for each receiver, we transmit the nonce with it, encrypted.
      *
      * The cipherpack stream will be produced as follows:
      * ```
      * DER Header 1 {
      *     ASN1_Type::OctetString               stream_magic              // simple stream identifier to be matched
      *     ASN1_Type::OctetString               target_path               // designated target path for message
      *     ASN1_Type::Integer                   content_size              // content size of plaintext payload
      *     ASN1_Type::Integer                   creation_timestamp_sec    // message creation timestamp, second component
      *     ASN1_Type::Integer                   creation_timestamp_nsec   // message creation timestamp, nanoseconds component
      *     ASN1_Type::OctetString               subject                   // designated subject of message
      *     ASN1_Type::OctetString               payload_version           // version of this message's payload
      *     ASN1_Type::OctetString               payload_version_parent    // version of the parent's message payload
      *     ASN1_Type::OctetString               pk_type                   // public-key type: "RSA"
      *     ASN1_Type::OctetString               pk_fingerprt_hash_algo    // public-key fingerprint hash: "SHA-256"
      *     ASN1_Type::OctetString               pk_enc_padding_algo       // public-key encryption padding: "OAEP"
      *     ASN1_Type::OctetString               pk_enc_hash_algo          // public-key encryption hash: "SHA-256"
      *     ASN1_Type::OctetString               pk_sign_algo              // public-key signature algorithm: "EMSA1(SHA-256)",
      *     ASN1_Type::ObjectId                  sym_enc_mac_oid           // symmetric-key encryption+MAC algorithm: "ChaCha20Poly1305",
      *     ASN1_Type::OctetString               fingerprt_sender          // fingerprint of public sender key used for header signature
      *     ASN1_Type::Integer                   receiver_count,           // number of receiver triples { fingerprint, encrypted-symmetric-keys, encrypted-nonce }
      * }
      * DER Header recevr_1 {
      *     ASN1_Type::OctetString               fingerprt_recevr_1,       // fingerprint of receiver's public-key_1 used for encrypted_skey_recevr_1
      *     ASN1_Type::OctetString               encrypted_skey_recevr_1,  // encrypted symmetric-key with receiver's public-key_1
      *     ASN1_Type::OctetString               encrypted_nonce_recevr_1, // encrypted symmetric-encryption nonce with receiver's public-key_1
      * },
      * DER Header recevr_2 {
      *     ASN1_Type::OctetString               fingerprt_recevr_2,       // fingerprint of receiver's public-key_1 used for encrypted_skey_recevr_2
      *     ASN1_Type::OctetString               encrypted_skey_recevr_2,  // encrypted symmetric-key with receiver's public-key_2
      *     ASN1_Type::OctetString               encrypted_nonce_recevr_2, // encrypted symmetric-encryption nonce with receiver's public-key_2
      * } ...
      * DER Header 2 {
      *     ASN1_Type::OctetString               sign_sender               // sender's signature over whole header, matching fingerprt_sender
      * },
      * uint8_t encrypted_data[]
      * ```
      *
      * @see encryptThenSign()
      * @see checkSignThenDecrypt()
      *
      * @{
      */

    #define JAVA_MAIN_PACKAGE "org/cipherpack/"

     class Environment {
         public:
             static void env_init() noexcept;
     };

    /**
     * CryptoConfig, contains crypto algorithms settings given at encryption wired via the @ref cipherpack_stream "Cipherpack Data Stream",
     * hence received and used at decryption if matching keys are available.
     *
     * @see @ref cipherpack_overview "Cipherpack Overview"
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
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
         * - Symmetric AEAD ChaCha Nonce Sizes are usually: 64-bit classic, 96-bit IETF, 192-bit big for one message per symmetric-key.
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
                     const size_t sym_enc_nonce_bytes_) noexcept
        : pk_type(pk_type_),
          pk_fingerprt_hash_algo(pk_fingerprt_hash_algo_),
          pk_enc_padding_algo(pk_enc_padding_algo_),
          pk_enc_hash_algo(pk_enc_hash_algo_),
          pk_sign_algo(pk_sign_algo_),
          sym_enc_algo(sym_enc_algo_),
          sym_enc_nonce_bytes(sym_enc_nonce_bytes_)
        { }

        bool valid() const noexcept;

        std::string to_string() const noexcept;
    };

    class Constants {
        public:
            /** Intermediate copy buffer size of {@code 4096 bytes}, usually the page-size. */
            constexpr static const size_t buffer_size = 4096;

            /**
             * Package magic {@code CIPHERPACK_0003}.
             */
            static const std::string package_magic;
    };

    /**
     * Cipherpack header less encrypted keys or signatures as described in @ref cipherpack_stream "Cipherpack Data Stream"
     *
     * @see @ref cipherpack_overview "Cipherpack Overview"
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     */
    class PackHeader {
        private:
            std::string target_path;
            uint64_t content_size;
            jau::fraction_timespec ts_creation;
            std::string subject;
            std::string payload_version;
            std::string payload_version_parent;
            CryptoConfig crypto_cfg;
            std::string sender_fingerprint;
            std::vector<std::string> recevr_fingerprints;
            ssize_t used_recevr_key_idx;
            bool valid;

        public:
            /** default ctor, denoting an invalid package header. */
            PackHeader()
            : target_path("none"),
              content_size(0),
              ts_creation( jau::getWallClockTime() ),
              subject("none"),
              payload_version(),
              payload_version_parent(),
              crypto_cfg(),
              sender_fingerprint(),
              recevr_fingerprints(),
              used_recevr_key_idx(-1),
              valid(false)
            { }

            /** ctor, denoting an invalid package header. */
            PackHeader(const jau::fraction_timespec& ts_creation_)
            : target_path("none"),
              content_size(0),
              ts_creation( ts_creation_ ),
              subject("none"),
              payload_version(),
              payload_version_parent(),
              crypto_cfg(),
              sender_fingerprint(),
              recevr_fingerprints(),
              used_recevr_key_idx(-1),
              valid(false)
            { }

            /** Complete ctor, denoting a complete package header, see @ref cipherpack_stream "Cipherpack Data Stream". */
            PackHeader(const std::string& target_path_,
                       const uint64_t& content_size_,
                       const jau::fraction_timespec& ts_creation_,
                       const std::string& subject_,
                       const std::string& pversion, const std::string& pversion_parent,
                       const CryptoConfig& crypto_cfg_,
                       const std::string& sender_fingerprint_,
                       const std::vector<std::string>& recevr_fingerprints_,
                       const size_t used_recevr_key_idx_,
                       const bool valid_)
            : target_path(target_path_),
              content_size(content_size_),
              ts_creation(ts_creation_),
              subject(subject_),
              payload_version(pversion), payload_version_parent(pversion_parent),
              crypto_cfg(crypto_cfg_),
              sender_fingerprint(sender_fingerprint_),
              recevr_fingerprints(recevr_fingerprints_),
              used_recevr_key_idx(used_recevr_key_idx_),
              valid(valid_)
            { }

            /** Returns the designated target path for message, see @ref cipherpack_stream "Cipherpack Data Stream". */
            const std::string& getTargetPath() const noexcept { return target_path; }

            /** Returns the plaintext content size in bytes, i.e. decrypted payload size, see @ref cipherpack_stream "Cipherpack Data Stream". */
            uint64_t getContentSize() const noexcept { return content_size; }

            /** Returns the creation time since Unix epoch, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const jau::fraction_timespec& getCreationTime() const noexcept { return ts_creation; }

            /** Returns the designated subject of message, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const std::string& getSubject() const noexcept { return subject; }

            /** Returns the payload version, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const std::string& getPayloadVersion() const noexcept { return payload_version;}

            /** Returns the payload's parent version, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const std::string& getPayloadVersionParent() const noexcept { return payload_version_parent;}

            constexpr const CryptoConfig& getCryptoConfig() const noexcept { return crypto_cfg; }

            /**
             * Return the sender's public-key fingerprint used to sign, see @ref cipherpack_stream "Cipherpack Data Stream".
             */
            const std::string& getSenderFingerprint() const noexcept { return sender_fingerprint; }

            /**
             * Return the list of receiver's public-keys fingerprints used to encrypt the symmetric-key, see @ref cipherpack_stream "Cipherpack Data Stream".
             */
            const std::vector<std::string>& getReceiverFingerprints() const noexcept { return recevr_fingerprints; }

            /**
             * Return the index of the matching receiver's public-key fingerprint used to decrypt the symmetric-key, see @ref cipherpack_stream "Cipherpack Data Stream".
             *
             * @return the receiver's key index of getReceiverFingerprints(), or -1 if not found or not decrypting.
             */
            ssize_t getUsedReceiverKeyIndex() const noexcept { return used_recevr_key_idx; }

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
    inline std::string to_string(const PackHeader& ph) noexcept { return ph.toString(true, true); }

    std::shared_ptr<Botan::Public_Key> load_public_key(const std::string& pubkey_fname);
    std::shared_ptr<Botan::Private_Key> load_private_key(const std::string& privatekey_fname, const jau::io::secure_string& passphrase);

    /**
     * Listener for events occurring while processing a cipherpack message via encryptThenSign() and checkSignThenDecrypt().
     *
     * @see @ref cipherpack_overview "Cipherpack Overview"
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     */
    class CipherpackListener : public jau::jni::JavaUplink {
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
     * Encrypt then sign the source producing a cipherpack stream passed to the CipherpackListener if opt-in and also optionally store into destination_fname.
     *
     * @param crypto_cfg             Used CryptoConfig, consider using CryptoConfig::getDefault()
     * @param enc_pub_keys           Public keys of the receiver, used to encrypt the symmetric-key for multiple parties.
     * @param sign_sec_key_fname     Private key of the sender, used to sign the DER-Header-1 incl encrypted symmetric-key for authenticity.
     * @param passphrase             Passphrase for `sign_sec_key_fname`, may be an empty secure_string for no passphrase.
     * @param source                 The source jau::io::ByteInStream of the plaintext payload.
     * @param target_path            Designated target path for the message
     * @param subject                Designated subject of payload from sender
     * @param payload_version        Version of this message's payload
     * @param payload_version_parent Version of the parent's message payload
     * @param listener               CipherpackListener listener used for notifications and optionally
     *                               to send the ciphertext destination bytes via CipherpackListener::contentProcessed()
     * @param destination_fname      Optional filename of the ciphertext destination file, not used if empty (default). If not empty and file already exists, file will be overwritten.
     * @return PackHeader, where true == PackHeader::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_overview "Cipherpack Overview"
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see checkSignThenDecrypt()
     * @see CipherpackListener
     * @see [jau::io::ByteInStream](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream.html#details)
     */
    PackHeader encryptThenSign(const CryptoConfig& crypto_cfg,
                               const std::vector<std::string>& enc_pub_keys,
                               const std::string& sign_sec_key_fname, const jau::io::secure_string& passphrase,
                               jau::io::ByteInStream& source,
                               const std::string& target_path, const std::string& subject,
                               const std::string& payload_version,
                               const std::string& payload_version_parent,
                               CipherpackListenerRef listener,
                               const std::string destination_fname = "");

    /**
     * Verify signature then decrypt the source passing to the CipherpackListener if opt-in and also optionally store into destination file.
     *
     * @param sign_pub_keys      Authorized sender public-keys to verify the sender's signature
     *                           and hence the authenticity of the message incl. encrypted symmetric-key and payload.
     * @param dec_sec_key_fname  Private key of the receiver, used to decrypt the symmetric-key.
     *                           It shall match one of the keys used to encrypt.
     * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty secure_string for no passphrase.
     * @param source             The source jau::io::ByteInStream of the cipherpack containing the encrypted payload.
     * @param listener           The CipherpackListener listener used for notifications and optionally
     *                           to send the plaintext destination bytes via CipherpackListener::contentProcessed()
     * @param destination_fname  Optional filename of the plaintext destination file, not used if empty (default). If not empty and file already exists, file will be overwritten.
     * @return PackHeader, where true == PackHeader::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_overview "Cipherpack Overview"
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see encryptThenSign()
     * @see CipherpackListener
     * @see [jau::io::ByteInStream](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream.html#details)
     */
    PackHeader checkSignThenDecrypt(const std::vector<std::string>& sign_pub_keys,
                                    const std::string& dec_sec_key_fname, const jau::io::secure_string& passphrase,
                                    jau::io::ByteInStream& source,
                                    CipherpackListenerRef listener,
                                    const std::string destination_fname = "");

    /**@}*/

} // namespace cipherpack

 /** \example commandline.cpp
  * This is the commandline version to convert a source from and to a cipherpack, i.e. encrypt and decrypt.
  */

 /** \example test_01_cipherpack.cpp
  * Unit test, testing encrypting to and decrypting from a cipherpack stream using different sources.
  *
  * Unit test also covers error cases.
  */

#endif /* JAU_CIPHERPACK_HPP_ */