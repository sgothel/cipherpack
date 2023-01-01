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

#include <cipherpack/version.hpp>

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
      * ensuring their privacy and high-performance message encryption.
      *
      * *Cipherpack* securely streams messages through any media,
      * via file using
      * [ByteInStream_File](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__File.html)
      * and via all [*libcurl* network protocols](https://curl.se/docs/url-syntax.html)
      * using [ByteInStream_URL](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__URL.html)
      * are *build-in* and supported. <br/>
      * Note: *libcurl* must be enabled via `-DUSE_LIBCURL=ON` at build.
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
      * The following public-key signature and encryption, as well as symmetric-key message encryption operations are performed:
      * - Writing a DER Header-1, containing the general message information and receiver count, see {@link PackHeader} details.
      * - Writing a DER Header for each recevr, containing the fingerprint, encrypted symmetric-key and encrypted symmetric-nonce.
      * - Writing a DER Header-2, containing the sender's signature over the whole header
      * - Writing the symmetrically encrypted message, using the symmetric-key for encryption + MAC via AEAD `ChaCha20Poly1305`.
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
      * - Symmetric encryption of the plaintext message ensures high-performance processing.
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
      *     ASN1_Type::OctetString               target_path               // optional target path for the plaintext message, user application specific.
      *     ASN1_Type::Integer                   plaintext_size            // size in bytes of plaintext message, zero if not determined at start of streaming
      *     ASN1_Type::Integer                   creation_timestamp_sec    // message creation timestamp, second component
      *     ASN1_Type::Integer                   creation_timestamp_nsec   // message creation timestamp, nanoseconds component
      *     ASN1_Type::OctetString               subject                   // optional subject of message, user application specific.
      *     ASN1_Type::OctetString               plaintext_version         // version of this plaintext message, user application specific.
      *     ASN1_Type::OctetString               plaintext_version_parent  // version of this plaintext message's preceding message, user application specific.
      *     ASN1_Type::OctetString               pk_type                   // public-key type. Default `RSA`.
      *     ASN1_Type::OctetString               pk_fingerprt_hash_algo    // public-key fingerprint hash. Default `SHA-256`.
      *     ASN1_Type::OctetString               pk_enc_padding_algo       // public-key encryption padding. Default `OAEP`.
      *     ASN1_Type::OctetString               pk_enc_hash_algo          // public-key encryption hash. Default `SHA-256`.
      *     ASN1_Type::OctetString               pk_sign_algo              // public-key signature algorithm. Default `EMSA1(SHA-256)`.
      *     ASN1_Type::ObjectId                  sym_enc_mac_oid           // symmetric-key encryption+MAC algorithm. Default `ChaCha20Poly1305`.
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
      * uint8_t encrypted_data[ciphertext_size]                            // the encrypted message, `ciphertext_size` bytes resulting to `plaintext_size` plaintext message
      * ```
      *
      * @see encryptThenSign()
      * @see checkSignThenDecrypt()
      *
      * @{
      */

    #define JAVA_MAIN_PACKAGE "org/cipherpack/"

    class environment {
        private:
            environment() noexcept;

        public:
            void print_info() noexcept;

            static environment& get() noexcept {
                /**
                 * Thread safe starting with C++11 6.7:
                 *
                 * If control enters the declaration concurrently while the variable is being initialized,
                 * the concurrent execution shall wait for completion of the initialization.
                 *
                 * (Magic Statics)
                 *
                 * Avoiding non-working double checked locking.
                 */
                static environment e;
                return e;
            }
    };

    template<typename T> using secure_vector = std::vector<T, Botan::secure_allocator<T>>;

    /**
    * This class represents an abstract data source object.
    */
    class WrappingDataSource : public Botan::DataSource
    {
       public:
          jau::io::ByteInStream& in;

          WrappingDataSource(jau::io::ByteInStream& in_)
          : in(in_) {}

          [[nodiscard]] size_t read(uint8_t out[], size_t length) override
          { return in.read(out, length); }

          bool check_available(size_t n) override
          { return in.available(n); }

          [[nodiscard]] size_t peek(uint8_t out[], size_t length, size_t peek_offset) const override
          { return in.peek(out, length, peek_offset); }

          bool end_of_data() const override
          { return !in.good(); }

          std::string id() const override
          { return in.id(); }

          size_t get_bytes_read() const override
          { return static_cast<size_t>( in.tellg() ); }
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
         * Returns default CryptoConfig.
         *
         * - Public-Key type is {@code RSA}.
         * - Public key fingerprint hash algorithm is {@code SHA-256}.
         * - Public-Key padding algorithm is {@code OAEP}.
         * - Public-Key hash algorithm is {@code SHA-256}.
         * - Public-Key signature algorithm is {@code EMSA1(SHA-256)}.
         * - Symmetric Authenticated Encryption with Additional Data (AEAD) encryption+MAC cipher algo is {@code ChaCha20Poly1305}.
         * - Symmetric AEAD ChaCha Nonce size 96 bit for one message per symmetric-key. Sizes are usually: 64-bit classic, 96-bit IETF, 192-bit big.
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
            /** Intermediate copy buffer size of {@code 16384 bytes}, usually the 4 x 4096 bytes page-size. */
            constexpr static const size_t buffer_size = 16384;

            /**
             * Package magic {@code CIPHERPACK_0004}.
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
            std::string target_path_;
            uint64_t plaintext_size_;
            jau::fraction_timespec ts_creation_;
            std::string subject_;
            std::string plaintext_version_;
            std::string plaintext_version_parent_;
            CryptoConfig crypto_cfg_;
            std::vector<uint8_t> sender_fingerprint_;
            std::vector<std::vector<uint8_t>> recevr_fingerprints_;
            ssize_t used_recevr_key_idx_;
            std::string plaintext_hash_algo_;
            std::vector<uint8_t> plaintext_hash_;
            bool valid_;

        public:
            /** default ctor, denoting an invalid package header. */
            PackHeader()
            : target_path_("none"),
              plaintext_size_(0),
              ts_creation_( jau::getWallClockTime() ),
              subject_("none"),
              plaintext_version_(),
              plaintext_version_parent_(),
              crypto_cfg_(),
              sender_fingerprint_(),
              recevr_fingerprints_(),
              used_recevr_key_idx_(-1),
              plaintext_hash_algo_(),
              plaintext_hash_(),
              valid_(false)
            { }

            /** ctor, denoting an invalid package header. */
            PackHeader(const jau::fraction_timespec& ts_creation)
            : target_path_("none"),
              plaintext_size_(0),
              ts_creation_( ts_creation ),
              subject_("none"),
              plaintext_version_(),
              plaintext_version_parent_(),
              crypto_cfg_(),
              sender_fingerprint_(),
              recevr_fingerprints_(),
              used_recevr_key_idx_(-1),
              plaintext_hash_algo_(),
              plaintext_hash_(),
              valid_(false)
            { }

            /** Complete ctor, denoting a complete package header, see @ref cipherpack_stream "Cipherpack Data Stream". */
            PackHeader(const std::string& _target_path,
                       const uint64_t& _plaintext_size,
                       const jau::fraction_timespec& _ts_creation,
                       const std::string& _subject,
                       const std::string& _pversion, const std::string& _pversion_parent,
                       const CryptoConfig& _crypto_cfg,
                       const std::vector<uint8_t>& _sender_fingerprint,
                       const std::vector<std::vector<uint8_t>>& _recevr_fingerprints,
                       const size_t _used_recevr_key_idx,
                       const bool _valid)
            : target_path_(_target_path),
              plaintext_size_(_plaintext_size),
              ts_creation_(_ts_creation),
              subject_(_subject),
              plaintext_version_(_pversion), plaintext_version_parent_(_pversion_parent),
              crypto_cfg_(_crypto_cfg),
              sender_fingerprint_(_sender_fingerprint),
              recevr_fingerprints_(_recevr_fingerprints),
              used_recevr_key_idx_(_used_recevr_key_idx),
              plaintext_hash_algo_(),
              plaintext_hash_(),
              valid_(_valid)
            { }

            /** Returns the designated target path for this plaintext message, see @ref cipherpack_stream "Cipherpack Data Stream". */
            const std::string& target_path() const noexcept { return target_path_; }

            /** Returns the plaintext message size in bytes, zero if not determined yet. See @ref cipherpack_stream "Cipherpack Data Stream". */
            uint64_t plaintext_size() const noexcept { return plaintext_size_; }

            void set_plaintext_size(const uint64_t v) noexcept { plaintext_size_=v; }

            /** Returns the creation time since Unix epoch, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const jau::fraction_timespec& creation_time() const noexcept { return ts_creation_; }

            /** Returns the designated subject of message, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const std::string& subject() const noexcept { return subject_; }

            /** Returns version of this plaintext message, user semantic, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const std::string& plaintext_version() const noexcept { return plaintext_version_;}

            /** Returns version of this plaintext message's preceding message, user semantic, see @ref cipherpack_stream "Cipherpack Data Stream". */
            constexpr const std::string& plaintext_version_parent() const noexcept { return plaintext_version_parent_;}

            constexpr const CryptoConfig& crypto_config() const noexcept { return crypto_cfg_; }

            /**
             * Return the sender's public-key fingerprint used to sign, see @ref cipherpack_stream "Cipherpack Data Stream".
             */
            const std::vector<uint8_t>& sender_fingerprint() const noexcept { return sender_fingerprint_; }

            /**
             * Return the list of receiver's public-keys fingerprints used to encrypt the symmetric-key, see @ref cipherpack_stream "Cipherpack Data Stream".
             */
            const std::vector<std::vector<uint8_t>>& receiver_fingerprints() const noexcept { return recevr_fingerprints_; }

            /**
             * Return the index of the matching receiver's public-key fingerprint used to decrypt the symmetric-key, see @ref cipherpack_stream "Cipherpack Data Stream".
             *
             * @return the receiver's key index of getReceiverFingerprints(), or -1 if not found or not decrypting.
             */
            ssize_t receiver_key_index() const noexcept { return used_recevr_key_idx_; }

            /**
             * Return optional hash algorithm for the plaintext message, produced for convenience and not wired.
             *
             * If not used, returned string is empty.
             *
             * @see getPlaintextHash()
             * @see setPlaintextHash()
             */
            const std::string& plaintext_hash_algo() const noexcept { return plaintext_hash_algo_; }

            /**
             * Return optional hash value of the plaintext message, produced for convenience and not wired.
             *
             * If not used, i.e. getPlaintextHashAlgo() is empty, returned vector has zero size.
             *
             * @see getPlaintextHashAlgo()
             * @see setPlaintextHash()
             */
            const std::vector<uint8_t>& plaintext_hash() const noexcept { return plaintext_hash_; }

            /**
             * Set optional hash-algo and -value of the plaintext messages, produced for convenience and not wired.
             * @see getPlaintextHash()
             * @see getPlaintextHashAlgo()
             */
            void set_plaintext_hash(const std::string& algo, const std::vector<uint8_t>& hash) noexcept {
                plaintext_hash_algo_ = algo;
                plaintext_hash_ = hash;
            }

            /**
             * Return a string representation
             * @param show_crypto_algos pass true if used crypto algos shall be shown, otherwise suppressed (default).
             * @param force_all_fingerprints if true always show all getTermKeysFingerprint(), otherwise show only the getTermKeysFingerprint() if >= 0 (default).
             * @return string representation
             */
            std::string to_string(const bool show_crypto_algos=false, const bool force_all_fingerprints=false) const noexcept;

            void setValid(const bool v) { valid_ = v; }
            bool isValid() const noexcept { return valid_; }
    };
    inline std::string to_string(const PackHeader& ph) noexcept { return ph.to_string(true, true); }

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
            enum class content_type : uint8_t {
                header = 0,
                message = 1
            };

            /**
             * User notification about an error via text message and preliminary PackHeader
             *
             * This message will be send without a subsequent notifyHeader() or notifyEnd() to indicate an error and hence aborts processing.
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param header the preliminary PackHeader
             * @param msg the error message
             */
            virtual void notifyError(const bool decrypt_mode, const PackHeader& header, const std::string& msg) noexcept {
                (void)decrypt_mode;
                (void)msg;
            }

            /**
             * User notification of preliminary PackHeader w/o optional hash of the plaintext message
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param header the preliminary PackHeader
             * @return true to continue processing (default), false to abort.
             */
            virtual bool notifyHeader(const bool decrypt_mode, const PackHeader& header) noexcept {
                (void)decrypt_mode;
                (void)header;
                return true;
            }

            /**
             * User notification about content streaming progress.
             *
             * In case contentProcessed() gets called, notifyProgress() is called thereafter.
             *
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param plaintext_size the plaintext message size, zero if not determined yet
             * @param bytes_processed the number of unencrypted bytes processed
             * @return true to continue processing (default), false to abort.
             * @see contentProcessed()
             */
            virtual bool notifyProgress(const bool decrypt_mode, const uint64_t plaintext_size, const uint64_t bytes_processed) noexcept {
                (void)decrypt_mode;
                (void)plaintext_size;
                (void)bytes_processed;
                return true;
            }

            /**
             * User notification of successful completion.
             * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
             * @param header the final PackHeader
             */
            virtual void notifyEnd(const bool decrypt_mode, const PackHeader& header) noexcept {
                (void)decrypt_mode;
                (void)header;
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
             * @param ctype content_type of passed data. Always content_type::message if decrypt_mode is true.
             * @param data the processed content, either the generated cipherpack or plaintext content depending on decrypt_mode.
             * @param is_final true if this is the last content call, otherwise false
             * @return true to continue processing (default), false to abort.
             * @see getSendContent()
             */
            virtual bool contentProcessed(const bool decrypt_mode, const content_type ctype, cipherpack::secure_vector<uint8_t>& data, const bool is_final) noexcept {
                (void)decrypt_mode;
                (void)ctype;
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
     * Name of default hash algo for the plaintext message,
     * e.g. for encryptThenSign() and checkSignThenDecrypt().
     *
     * Value is `BLAKE2b(512)`.
     *
     * Note:
     * - SHA-256 performs 64 rounds over 512 bits (blocks size) at a time.
     *   - Often better optimized and hardware implemented.
     * - SHA-512 performs 80 rounds over 1024 bits (blocks size) at a time.
     *   - Requires double storage size than SHA-256, i.e. 512/256 bits.
     *   - 25% more rounds, i.e. calculations than SHA-256
     *   - Operating on 64-bit words instead of SHA-256's 32-bit words
     *   - Theoretically shall outperform SHA-256 by 2 / 1.25 = 1.6 on 64-bit architectures,
     *     however, SHA-256 is often better optimized and hardware implemented.
     * - BLAKE2b(512) usually beats both, SHA-256 and SHA-512 on 64-bit machines.
     *   - It even matches their performance if using hardware accelerated implementations.
     */
    std::string_view default_hash_algo() noexcept;

    /**
     * Encrypt then sign the source producing a cipherpack stream passed to the CipherpackListener if opt-in and also optionally store into destination_fname.
     *
     * @param crypto_cfg             Used CryptoConfig, consider using CryptoConfig::getDefault()
     * @param enc_pub_keys           Public keys of the receiver, used to encrypt the symmetric-key for multiple parties.
     * @param sign_sec_key_fname     Private key of the sender, used to sign the DER-Header-1 incl encrypted symmetric-key for authenticity.
     * @param passphrase             Passphrase for `sign_sec_key_fname`, may be an empty secure_string for no passphrase.
     * @param source                 The source jau::io::ByteInStream of the plaintext message.
     * @param target_path            Optional target path for the message, user application specific.
     * @param subject                Optional subject of message, user application specific.
     * @param plaintext_version      Version of this plaintext message, user semantic
     * @param plaintext_version_parent Version of this plaintext message's preceding message, user application specific
     * @param listener               CipherpackListener listener used for notifications and optionally
     *                               to send the ciphertext destination bytes via CipherpackListener::contentProcessed()
     * @param plaintext_hash_algo    Optional hash algorithm for the plaintext message, produced for convenience and not wired. See default_hash_algo().
     *                               Pass an empty string to disable.
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
                               const std::string& plaintext_version,
                               const std::string& plaintext_version_parent,
                               CipherpackListenerRef listener,
                               const std::string_view& plaintext_hash_algo,
                               const std::string destination_fname = "");

    /**
     * Verify signature then decrypt the source passing to the CipherpackListener if opt-in and also optionally store into destination file.
     *
     * @param sign_pub_keys          Authorized sender public-keys to verify the sender's signature
     *                               and hence the authenticity of the message incl. encrypted symmetric-key and ciphertext message.
     * @param dec_sec_key_fname      Private key of the receiver, used to decrypt the symmetric-key.
     *                               It shall match one of the keys used to encrypt.
     * @param passphrase             The passphrase for `dec_sec_key_fname`, may be an empty secure_string for no passphrase.
     * @param source                 The source jau::io::ByteInStream of the cipherpack containing the encrypted message.
     * @param listener               The CipherpackListener listener used for notifications and optionally
     *                               to send the plaintext destination bytes via CipherpackListener::contentProcessed()
     * @param plaintext_hash_algo    Optional hash algorithm for the plaintext message, produced for convenience and not wired. See default_hash_algo().
     *                               Pass an empty string to disable.
     * @param destination_fname      Optional filename of the plaintext destination file, not used if empty (default). If not empty and file already exists, file will be overwritten.
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
                                    const std::string_view& plaintext_hash_algo,
                                    const std::string destination_fname = "");

    /**
     * Hash utility functions to produce a hash file compatible to `sha256sum`
     * as well as to produce the hash value itself for validation.
     */
    namespace hash_util {
        /** Return a lower-case file suffix used to store a `sha256sum` compatible hash signature w/o dot and w/o dashes. */
        std::string file_suffix(const std::string& algo) noexcept;

        /**
         * Append the hash signature to the text file out_file
         *
         * The hash signature is composed as follows
         * - hash algo name
         * - space
         * - hash value
         * - space
         * - `*` to denote binary processing
         * - hashed file name
         *
         * The hash signature is similar to `sha256sum` output, but the added hash algo name upfront.
         *
         * @param out_file the text file to append hash signature of hashed_file.
         * @param hashed_file the file of the hash signature
         * @param hash_algo the hash algo name used
         * @param hash_value the hash value of hashed_file
         * @return true if successful, otherwise false
         */
        bool append_to_file(const std::string& out_file, const std::string& hashed_file, const std::string_view& hash_algo, const std::vector<uint8_t>& hash_value) noexcept;

        /**
         * Return the calculated hash value using given algo name and byte input stream.
         * @param algo the hash algo name
         * @param source the byte input stream
         * @return the calculated hash value or nullptr in case of error
         */
        std::unique_ptr<std::vector<uint8_t>> calc(const std::string_view& algo, jau::io::ByteInStream& source) noexcept;

        /**
         * Return the calculated hash value using given algo name and the bytes of a single file or all files if denoting a directory.
         * @param algo the hash algo name
         * @param path_or_uri given path or uri, either a URI denoting a single file, a single file path or directory path for which all files (not symbolic links) are considered
         * @param bytes_hashed returns overall bytes hashed
         * @param timeout in case `path_or_uri` refers to an URI, timeout is being used as maximum duration to wait for next bytes. Defaults to 20_s.
         * @return the calculated hash value or nullptr in case of error
         */
        std::unique_ptr<std::vector<uint8_t>> calc(const std::string_view& algo, const std::string& path_or_uri, uint64_t& bytes_hashed, jau::fraction_i64 timeout=20_s) noexcept;
    }

    /**@}*/

} // namespace cipherpack

/** \example commandline.cpp
 * cipherpack command line tool.
 *
 * Examples:
 * - File based operation
 *   - `cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 -out a.enc plaintext.bin`
 *   - `cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 -out a.dec a.enc`
 *   - `cipherpack hash -out a.hash jaulib/test_data`
 * - Pipe based operation
 *   - `cat plaintext.bin | cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 > a.enc`
 *   - `cat a.enc | cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 > a.dec`
 *   - `cat a.dec | cipherpack hash jaulib/test_data`
 * - Pipe based full streaming
 *   - `cat plaintext.bin | cipherpack pack -epk test_keys/terminal_rsa1.pub.pem -ssk test_keys/host_rsa1 | cipherpack unpack -spk test_keys/host_rsa1.pub.pem -dsk test_keys/terminal_rsa1 > a.dec`
 *
 */

/** \example test_01_cipherpack.cpp
 * Unit test, testing encrypting to and decrypting from a cipherpack stream using different sources.
 *
 * Unit test also covers error cases.
 */

#endif /* JAU_CIPHERPACK_HPP_ */
