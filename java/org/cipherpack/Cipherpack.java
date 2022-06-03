/**
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2022 Gothel Software e.K.
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
package org.cipherpack;

import java.util.List;

/**
 * @anchor cipherpack_overview
 * ### Cipherpack Overview
 * *Cipherpack*, a secure stream processor utilizing public-key signatures to
 * authenticate the sender and public-key encryption of a symmetric-key for multiple receiver
 * ensuring their privacy and high-performance payload encryption.
 *
 * A *Cipherpack* can be understood as a message, which can be streamed
 * via any media while file and all [*libcurl* notwork protocols](https://curl.se/libcurl/) are *build-in* and supported.
 *
 * A user may utilize the media agnostic API, a ByteInStream_Feed
 * to produce the input stream
 * and a CipherpackListener to receive the processed output stream.
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
 */
public final class Cipherpack {

    /**
     * Encrypt then sign the source producing a cipherpack stream passed to the CipherpackListener if opt-in and also optionally store into destination_fname.
     *
     * @param crypto_cfg             Used CryptoConfig, consider using CryptoConfig::getDefault()
     * @param enc_pub_keys           Public keys of the receiver, used to encrypt the symmetric-key for multiple parties.
     * @param sign_sec_key_fname     Private key of the sender, used to sign the DER-Header-1 incl encrypted symmetric-key for authenticity.
     * @param passphrase             Passphrase for `sign_sec_key_fname`, may be an empty string for no passphrase.
     * @param source_feed            The source ByteInStream_Feed of the cipherpack containing the encrypted payload.
     * @param target_path            Designated target path for the message
     * @param subject                Designated subject of payload from sender
     * @param payload_version        Version of this message's payload
     * @param payload_version_parent Version of the parent's message payload
     * @param listener               CipherpackListener listener used for notifications and optionally
     *                               to send the ciphertext destination bytes via CipherpackListener::contentProcessed()
     * @param destination_fname      Optional filename of the plaintext destination file, not used if null or empty (default). If not empty and file already exists, file will be overwritten.
     * @return PackHeader, where true == PackHeader::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see checkSignThenDecrypt()
     */
    public static PackHeader encryptThenSign(final CryptoConfig crypto_cfg,
                                             final List<String> enc_pub_keys,
                                             final String sign_sec_key_fname, final String passphrase,
                                             final ByteInStream_Feed source_feed,
                                             final String target_path, final String subject,
                                             final String payload_version,
                                             final String payload_version_parent,
                                             final CipherpackListener listener, final String destination_fname) {
        return encryptThenSignImpl1(crypto_cfg,
                                    enc_pub_keys,
                                    sign_sec_key_fname, passphrase,
                                    source_feed,
                                    target_path, subject,
                                    payload_version,
                                    payload_version_parent,
                                    listener, destination_fname);
    }
    private static native PackHeader encryptThenSignImpl1(final CryptoConfig crypto_cfg,
                                                          final List<String> enc_pub_keys,
                                                          final String sign_sec_key_fname, final String passphrase,
                                                          final ByteInStream_Feed source_feed,
                                                          final String target_path, final String subject,
                                                          final String payload_version,
                                                          final String payload_version_parent,
                                                          final CipherpackListener listener, final String destination_fname);

    /**
     * Encrypt then sign the source producing a cipherpack stream passed to the CipherpackListener if opt-in and also optionally store into destination_fname.
     *
     * @param crypto_cfg             Used CryptoConfig, consider using CryptoConfig::getDefault()
     * @param enc_pub_keys           Public keys of the receiver, used to encrypt the symmetric-key for multiple parties.
     * @param sign_sec_key_fname     Private key of the sender, used to sign the DER-Header-1 incl encrypted symmetric-key for authenticity.
     * @param passphrase             Passphrase for `sign_sec_key_fname`, may be an empty string for no passphrase.
     * @param source_loc             The source location of the cipherpack containing the encrypted payload, either a filename or a URL.
     * @param source_timeout_ms      The timeout in milliseconds for waiting on new bytes from source, e.g. if location is a URL
     * @param target_path            Designated target path for the message
     * @param subject                Designated subject of payload from sender
     * @param payload_version        Version of this message's payload
     * @param payload_version_parent Version of the parent's message payload
     * @param listener               CipherpackListener listener used for notifications and optionally
     *                               to send the ciphertext destination bytes via CipherpackListener::contentProcessed()
     * @param destination_fname      Optional filename of the plaintext destination file, not used if null or empty (default). If not empty and file already exists, file will be overwritten.
     * @return PackHeader, where true == PackHeader::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see checkSignThenDecrypt()
     */
    public static PackHeader encryptThenSign(final CryptoConfig crypto_cfg,
                                             final List<String> enc_pub_keys,
                                             final String sign_sec_key_fname, final String passphrase,
                                             final String source_loc, final long source_timeout_ms,
                                             final String target_path, final String subject,
                                             final String payload_version,
                                             final String payload_version_parent,
                                             final CipherpackListener listener, final String destination_fname) {
        return encryptThenSignImpl2(crypto_cfg,
                                    enc_pub_keys,
                                    sign_sec_key_fname, passphrase,
                                    source_loc, source_timeout_ms,
                                    target_path, subject,
                                    payload_version,
                                    payload_version_parent,
                                    listener, destination_fname);
    }
    private static native PackHeader encryptThenSignImpl2(final CryptoConfig crypto_cfg,
                                                          final List<String> enc_pub_keys,
                                                          final String sign_sec_key_fname, final String passphrase,
                                                          final String source_loc, final long source_timeout_ms,
                                                          final String target_path, final String subject,
                                                          final String payload_version,
                                                          final String payload_version_parent,
                                                          final CipherpackListener listener, final String destination_fname);

    /**
     * Verify signature then decrypt the source passing to the CipherpackListener if opt-in and also optionally store into destination file.
     *
     * @param sign_pub_keys      Authorized sender public-keys to verify the sender's signature
     *                           and hence the authenticity of the message incl. encrypted symmetric-key and payload.
     * @param dec_sec_key_fname  Private key of the receiver, used to decrypt the symmetric-key.
     *                           It shall match one of the keys used to encrypt.
     * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty string for no passphrase.
     * @param source_feed        The source ByteInStream_Feed of the cipherpack containing the encrypted payload.
     * @param listener           The CipherpackListener listener used for notifications and optionally
     *                           to send the plaintext destination bytes via CipherpackListener::contentProcessed()
     * @param destination_fname  Optional filename of the plaintext destination file, not used if empty (default). If not empty and file already exists, file will be overwritten.
     * @return PackHeader, where true == PackHeader::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see encryptThenSign()
     *
     */
    public static PackHeader checkSignThenDecrypt(final List<String> sign_pub_keys,
                                                  final String dec_sec_key_fname, final String passphrase,
                                                  final ByteInStream_Feed source_feed,
                                                  final CipherpackListener listener, final String destination_fname) {
        return checkSignThenDecrypt1(sign_pub_keys,
                                     dec_sec_key_fname, passphrase,
                                     source_feed,
                                     listener, destination_fname);
    }
    private static native PackHeader checkSignThenDecrypt1(final List<String> sign_pub_keys,
                                                           final String dec_sec_key_fname, final String passphrase,
                                                           final ByteInStream_Feed source_feed,
                                                           final CipherpackListener listener, final String destination_fname);

    /**
     * Verify signature then decrypt the source passing to the CipherpackListener if opt-in and also optionally store into destination file.
     *
     * @param sign_pub_keys      Authorized sender public-keys to verify the sender's signature
     *                           and hence the authenticity of the message incl. encrypted symmetric-key and payload.
     * @param dec_sec_key_fname  Private key of the receiver, used to decrypt the symmetric-key.
     *                           It shall match one of the keys used to encrypt.
     * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty string for no passphrase.
     * @param source_loc         The source location of the cipherpack containing the encrypted payload, either a filename or a URL.
     * @param source_timeout_ms  The timeout in milliseconds for waiting on new bytes from source, e.g. if location is a URL
     * @param listener           The CipherpackListener listener used for notifications and optionally
     *                           to send the plaintext destination bytes via CipherpackListener::contentProcessed()
     * @param destination_fname  Optional filename of the plaintext destination file, not used if empty (default). If not empty and file already exists, file will be overwritten.
     * @return PackHeader, where true == PackHeader::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see encryptThenSign()
     *
     */
    public static PackHeader checkSignThenDecrypt(final List<String> sign_pub_keys,
                                                  final String dec_sec_key_fname, final String passphrase,
                                                  final String source_loc, final long source_timeout_ms,
                                                  final CipherpackListener listener, final String destination_fname) {
        return checkSignThenDecrypt2(sign_pub_keys,
                                     dec_sec_key_fname, passphrase,
                                     source_loc, source_timeout_ms,
                                     listener, destination_fname);
    }
    private static native PackHeader checkSignThenDecrypt2(final List<String> sign_pub_keys,
                                                           final String dec_sec_key_fname, final String passphrase,
                                                           final String source_loc, final long source_timeout_ms,
                                                           final CipherpackListener listener, final String destination_fname);
}
