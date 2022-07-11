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

/**
 * CryptoConfig, contains crypto algorithms settings given at encryption wired via the @ref cipherpack_stream "Cipherpack Data Stream",
 * hence received and used at decryption if matching keys are available.
 *
 * @see @ref cipherpack_overview "Cipherpack Overview"
 * @see @ref cipherpack_stream "Cipherpack Data Stream"
 */
public class CryptoConfig {
    public final String pk_type;
    public final String pk_fingerprt_hash_algo;
    public final String pk_enc_padding_algo;
    public final String pk_enc_hash_algo;
    public final String pk_sign_algo;
    public final String sym_enc_algo;
    public final long sym_enc_nonce_bytes;

    public CryptoConfig() {
        this.pk_type = "";
        this.pk_fingerprt_hash_algo = "";
        this.pk_enc_padding_algo = "";
        this.pk_enc_hash_algo = "";
        this.pk_sign_algo = "";
        this.sym_enc_algo = "";
        this.sym_enc_nonce_bytes = 0;
    }
    public CryptoConfig(final String pk_type_,
             final String pk_fingerprt_hash_algo_,
             final String pk_enc_padding_algo_,
             final String pk_enc_hash_algo_,
             final String pk_sign_algo_,
             final String sym_enc_algo_,
             final long sym_enc_nonce_bytes_) {
        this.pk_type = pk_type_;
        this.pk_fingerprt_hash_algo = pk_fingerprt_hash_algo_;
        this.pk_enc_padding_algo = pk_enc_padding_algo_;
        this.pk_enc_hash_algo = pk_enc_hash_algo_;
        this.pk_sign_algo = pk_sign_algo_;
        this.sym_enc_algo = sym_enc_algo_;
        this.sym_enc_nonce_bytes = sym_enc_nonce_bytes_;
    }

    public final boolean valid() {
        return !pk_type.isEmpty() &&
               !pk_fingerprt_hash_algo.isEmpty() &&
               !pk_enc_padding_algo.isEmpty() &&
               !pk_enc_hash_algo.isEmpty() &&
               !pk_sign_algo.isEmpty() &&
               !sym_enc_algo.isEmpty() &&
               sym_enc_nonce_bytes > 0;

    }

    @Override
    public final String toString() {
        return "CCfg[pk[type '"+pk_type+"', fingerprt_hash '"+pk_fingerprt_hash_algo+"', enc_padding '"+pk_enc_padding_algo+
                "', enc_hash '"+pk_enc_hash_algo+"', sign '"+pk_sign_algo+
                "'], sym['"+sym_enc_algo+"', nonce "+sym_enc_nonce_bytes+" byte]]";
    }

    private static String default_pk_type                = "RSA";
    private static String default_pk_fingerprt_hash_algo = "SHA-256";
    private static String default_pk_enc_padding_algo    = "OAEP"; // or "EME1"
    private static String default_pk_enc_hash_algo       = "SHA-256";
    private static String default_pk_sign_algo           = "EMSA1(SHA-256)";
    private static String default_sym_enc_mac_algo       = "ChaCha20Poly1305"; // or "AES-256/GCM"
    private static long ChaCha_Nonce_BitSize = 96;

    /**
     * Returns default CryptoConfig.
     *
     * - Public-Key type is {@code RSA}.
     * - Public key fingerprint hash algorithm is {@code SHA-256}.
     * - Public-Key padding algorithm is {@code OAEP}.
     * - Public-Key hash algorithm is {@code SHA-256}.
     * - Public-Key hash algorithm is {@code EMSA1(SHA-256)}.
     * - Symmetric Authenticated Encryption with Additional Data (AEAD) encryption+MAC cipher algo is {@code ChaCha20Poly1305}.
     * - Symmetric AEAD ChaCha Nonce size 96 bit for one message per symmetric-key. Sizes are usually: 64-bit classic, 96-bit IETF, 192-bit big.
     */
    public static CryptoConfig getDefault() {
        return new CryptoConfig (
            default_pk_type, default_pk_fingerprt_hash_algo,
            default_pk_enc_padding_algo, default_pk_enc_hash_algo,
            default_pk_sign_algo, default_sym_enc_mac_algo, ChaCha_Nonce_BitSize/8
        );
    }
}
