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
public class Cipherpack {

    /**
     * Check cipherpack signature of the source then decrypt into the plaintext destination file.
     *
     * @param sign_pub_keys      The potential public keys used by the host (pack provider) to verify the DER-Header-1 signature
     *                           and hence the authenticity of the encrypted file-key. Proves authenticity of the file.
     * @param dec_sec_key_fname  The private key of the receiver (terminal device), used to decrypt the file-key.
     *                           It shall match one of the keys used to encrypt.
     * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty string for no passphrase.
     * @param source             The source ByteInStream_Feed of the cipherpack containing the encrypted payload.
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
    boolean checkSignThenDecrypt(final List<String> sign_pub_keys,
                                 final String dec_sec_key_fname, final String passphrase,
                                 final ByteInStream_Feed source,
                                 final String destination_fname, final boolean overwrite,
                                 final CipherpackListener listener) {
        return false;
    }

    /**
     * Check cipherpack signature of the source then decrypt into the plaintext destination file.
     *
     * @param sign_pub_keys      The potential public keys used by the host (pack provider) to verify the DER-Header-1 signature
     *                           and hence the authenticity of the encrypted file-key. Proves authenticity of the file.
     * @param dec_sec_key_fname  The private key of the receiver (terminal device), used to decrypt the file-key.
     *                           It shall match one of the keys used to encrypt.
     * @param passphrase         The passphrase for `dec_sec_key_fname`, may be an empty string for no passphrase.
     * @param source             The source location of the cipherpack containing the encrypted payload, either a filename or a URL.
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
    boolean checkSignThenDecrypt(final List<String> sign_pub_keys,
                                 final String dec_sec_key_fname, final String passphrase,
                                 final String source,
                                 final String destination_fname, final boolean overwrite,
                                 final CipherpackListener listener) {
        return false;
    }
}
