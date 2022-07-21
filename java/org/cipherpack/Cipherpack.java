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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.ByteBuffer;
import java.util.List;

import org.jau.io.ByteInStream;
import org.jau.io.ByteInStream_Feed;
import org.jau.io.PrintUtil;
import org.jau.util.BasicTypes;

/**
 * @anchor cipherpack_overview
 * ### Cipherpack Overview
 * *Cipherpack*, a secure stream processor utilizing public-key signatures to
 * authenticate the sender and public-key encryption of a symmetric-key for multiple receiver
 * ensuring their privacy and high-performance payload encryption.
 *
 * A *Cipherpack* can be understood as a message, which can be streamed via any media,
 * while file and all [*libcurl* network protocols](https://curl.se/docs/url-syntax.html) are *build-in* via a location string and supported.
 *
 * A user may use the media agnostic ByteInStream_Feed
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
 *     ASN1_Type::OctetString               pk_type                   // public-key type. Default "RSA".
 *     ASN1_Type::OctetString               pk_fingerprt_hash_algo    // public-key fingerprint hash. Default "SHA-256".
 *     ASN1_Type::OctetString               pk_enc_padding_algo       // public-key encryption padding. Default "OAEP".
 *     ASN1_Type::OctetString               pk_enc_hash_algo          // public-key encryption hash. Default "SHA-256".
 *     ASN1_Type::OctetString               pk_sign_algo              // public-key signature algorithm. Default "EMSA1(SHA-256)".
 *     ASN1_Type::ObjectId                  sym_enc_mac_oid           // symmetric-key encryption+MAC algorithm. Default "ChaCha20Poly1305".
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
 * uint8_t encrypted_data[content_size]                               // the encrypted payload, content_size bytes
 * ```
 *
 * @see encryptThenSign()
 * @see checkSignThenDecrypt()
 */
public final class Cipherpack {

    /**
     * Name of default plaintext payload hash algo,
     * e.g. for {@link #encryptThenSign(CryptoConfig, List, String, ByteBuffer, ByteInStream, String, String, String, String, CipherpackListener, String, String) encryptThenSign()}
     * and {@link #checkSignThenDecrypt(List, String, ByteBuffer, ByteInStream, CipherpackListener, String, String) checkSignThenDecrypt()}.
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
    public static final String default_hash_algo() { return "BLAKE2b(512)"; }

    /**
     * Encrypt then sign the source producing a cipherpack stream passed to the CipherpackListener if opt-in and also optionally store into destination_fname.
     *
     * @param crypto_cfg             Used CryptoConfig, consider using CryptoConfig::getDefault()
     * @param enc_pub_keys           Public keys of the receiver, used to encrypt the symmetric-key for multiple parties.
     * @param sign_sec_key_fname     Private key of the sender, used to sign the DER-Header-1 incl encrypted symmetric-key for authenticity.
     * @param passphrase             Passphrase for `sign_sec_key_fname`, may be null or empty for no passphrase.
     * @param source                 The source ByteInStream of the cipherpack containing the encrypted payload.
     * @param target_path            Designated target path for the message
     * @param subject                Designated subject of payload from sender
     * @param payload_version        Version of this message's payload
     * @param payload_version_parent Version of the parent's message payload
     * @param listener               CipherpackListener listener used for notifications and optionally
     *                               to send the ciphertext destination bytes via CipherpackListener::contentProcessed()
     * @param payload_hash_algo      Optional hash algo name for plaintext payload, computed while encrypting for PackHeader only. See {@link #defPayloadHashAlgo}.
     *                               Set to empty string to disable.
     * @param destination_fname      Optional filename of the plaintext destination file, not used if null or empty (default). If not empty and file already exists, file will be overwritten.
     * @return PackHeader, where true == PackHeader::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_overview "Cipherpack Overview"
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see checkSignThenDecrypt()
     * @see CipherpackListener
     * @see ByteInStream_Feed
     * @see ByteInStream_URL
     * @see ByteInStream
     */
    public static PackHeader encryptThenSign(final CryptoConfig crypto_cfg,
                                             final List<String> enc_pub_keys,
                                             final String sign_sec_key_fname, final ByteBuffer passphrase,
                                             final ByteInStream source,
                                             final String target_path, final String subject,
                                             final String payload_version,
                                             final String payload_version_parent,
                                             final CipherpackListener listener,
                                             final String payload_hash_algo,
                                             final String destination_fname) {
        return encryptThenSignImpl1(crypto_cfg,
                                    enc_pub_keys,
                                    sign_sec_key_fname, passphrase,
                                    source,
                                    target_path, subject,
                                    payload_version,
                                    payload_version_parent,
                                    listener,
                                    payload_hash_algo,
                                    destination_fname);
    }
    private static native PackHeader encryptThenSignImpl1(final CryptoConfig crypto_cfg,
                                                          final List<String> enc_pub_keys,
                                                          final String sign_sec_key_fname,
                                                          final ByteBuffer passphrase,
                                                          final ByteInStream source,
                                                          final String target_path, final String subject,
                                                          final String payload_version,
                                                          final String payload_version_parent,
                                                          final CipherpackListener listener,
                                                          final String payload_hash_algo,
                                                          final String destination_fname);


    /**
     * Verify signature then decrypt the source passing to the CipherpackListener if opt-in and also optionally store into destination file.
     *
     * @param sign_pub_keys      Authorized sender public-keys to verify the sender's signature
     *                           and hence the authenticity of the message incl. encrypted symmetric-key and payload.
     * @param dec_sec_key_fname  Private key of the receiver, used to decrypt the symmetric-key.
     *                           It shall match one of the keys used to encrypt.
     * @param passphrase         The passphrase for `dec_sec_key_fname`, may be null or empty for no passphrase.
     * @param source             The source ByteInStream of the cipherpack containing the encrypted payload.
     * @param listener           The CipherpackListener listener used for notifications and optionally
     *                           to send the plaintext destination bytes via CipherpackListener::contentProcessed()
     * @param payload_hash_algo  Optional hash algo name for plaintext payload, computed while decrypting for PackHeader only. See {@link #defPayloadHashAlgo}.
     *                           Set to empty string to disable.
     * @param destination_fname  Optional filename of the plaintext destination file, not used if empty (default). If not empty and file already exists, file will be overwritten.
     * @return PackHeader, where true == PackHeader::isValid() if successful, otherwise not.
     *
     * @see @ref cipherpack_overview "Cipherpack Overview"
     * @see @ref cipherpack_stream "Cipherpack Data Stream"
     * @see encryptThenSign()
     * @see CipherpackListener
     * @see ByteInStream_Feed
     * @see ByteInStream_URL
     * @see ByteInStream
     */
    public static PackHeader checkSignThenDecrypt(final List<String> sign_pub_keys,
                                                  final String dec_sec_key_fname, final ByteBuffer passphrase,
                                                  final ByteInStream source,
                                                  final CipherpackListener listener,
                                                  final String payload_hash_algo,
                                                  final String destination_fname) {
        return checkSignThenDecrypt1(sign_pub_keys,
                                     dec_sec_key_fname, passphrase,
                                     source,
                                     listener,
                                     payload_hash_algo,
                                     destination_fname);
    }
    private static native PackHeader checkSignThenDecrypt1(final List<String> sign_pub_keys,
                                                           final String dec_sec_key_fname, final ByteBuffer passphrase,
                                                           final ByteInStream source,
                                                           final CipherpackListener listener,
                                                           final String payload_hash_algo,
                                                           final String destination_fname);

    /**
     * Hash utility functions to produce a hash file compatible to `sha256sum`
     * as well as to produce the hash value itself for validation.
     */
    public static final class HashUtil {
        /** Return a lower-case file suffix used to store a `sha256sum` compatible hash signature w/o dot and w/o dashes. */
        public static String fileSuffix(final String algo) {
            return algo.toLowerCase().replace("-", "");
        }

        /**
         * Append the `sha256sum` compatible hash signature of hashedFile to text file outFileName
         * @param outFileName the text file to append the `sha256sum` compatible hash signature of hashedFile.
         * @param hashedFile the file of the hash signature
         * @param hash the hash of hashedFile
         * @return true if successful, otherwise false
         */
        public static boolean appendToFile(final String outFileName, final String hashedFile, final byte[] hash) {
            final String hash_str = BasicTypes.bytesHexString(hash, 0, hash.length, true /* lsbFirst */);
            final String seperator = new String(" *");
            final File file = new File( outFileName );

            try( BufferedWriter out = new BufferedWriter( new FileWriter(file, true) ); ) {
                out.write(hash_str);
                out.write(seperator);
                out.write(hashedFile);
                out.newLine();
                return true;
            } catch (final Exception ex) {
                PrintUtil.println(System.err, "Write hash to file failed: "+outFileName+": "+ex.getMessage());
                ex.printStackTrace();
            }
            return false;
        }

        /**
         * Return the calculated hash value using given algo name and byte input stream.
         * @param algo the hash algo name
         * @param source the byte input stream
         * @return the calculated hash value or null in case of error
         */
        public static byte[] calc(final String algo, final ByteInStream source) {
            return calcImpl1(algo, source);
        }
        private static native byte[] calcImpl1(final String algo, final ByteInStream source);

        /**
         * Return the calculated hash value using given algo name and all actual files (not symbolic links) within the given path.
         * @param algo the hash algo name
         * @param path source path, either a single file or directory for which all files (not symbolic links) are considered
         * @param bytes_hashed returns overall bytes hashed, an array of length 1
         * @return the calculated hash value or nullptr in case of error
         */
        public static byte[] calc(final String algo, final String path, final long bytes_hashed[/*0*/]) {
            return calcImpl2(algo, path, bytes_hashed);
        }
        private static native byte[] calcImpl2(final String algo, final String path, final long bytes_hashed[/*0*/]);
    }
}
