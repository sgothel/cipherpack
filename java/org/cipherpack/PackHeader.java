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

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;

import org.jau.util.BasicTypes;

/**
 * Cipherpack header less encrypted keys or signatures as described in @ref cipherpack_stream "Cipherpack Data Stream"
 *
 * @see @ref cipherpack_overview "Cipherpack Overview"
 * @see @ref cipherpack_stream "Cipherpack Data Stream"
 */
public class PackHeader {
    /** Designated target path for this plaintext message, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final String target_path;

    /** Plaintext message size in bytes, zero if not determined yet. See @ref cipherpack_stream "Cipherpack Data Stream". */
    public final long plaintext_size;

    /** Creation time since Unix epoch, second component, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final long ts_creation_sec;

    /** Creation time since Unix epoch, nanosecond component, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final long ts_creation_nsec;

    /** Designated subject of message, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final String subject;

    /** Version of this plaintext message, user semantic, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final String plaintext_version;

    /** Version of this plaintext message's preceding message, user semantic, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final String plaintext_version_parent;

    public final CryptoConfig crypto_cfg;

    /** Sender's public-key fingerprint used to sign, see @ref cipherpack_stream "Cipherpack Data Stream".. */
    public final byte[] sender_fingerprint;

    /** List of receiver's public-keys fingerprints used to encrypt the symmetric-key, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final List<byte[]> recevr_fingerprints;

    /** Index of the matching receiver's public-key fingerprint used to decrypt the symmetric-key, see @ref cipherpack_stream "Cipherpack Data Stream", -1 if not found or not decrypting. */
    public final int used_recevr_key_idx;

    /**
     * Optional hash algorithm for the plaintext message, produced for convenience and not wired.
     *
     * If not used, {@link #plaintext_hash_algo} is empty.
     */
    public final String plaintext_hash_algo;

    /**
     * Optional hash value of the plaintext message, produced for convenience and not wired.
     *
     * If not used, i.e. {@link #plaintext_hash_algo} is empty, array has zero size.
     */
    public final byte[] plaintext_hash;

    /** True if packet is valid, otherwise false. */
    public final boolean valid;

    PackHeader() {
        this.target_path = "";
        this.plaintext_size = 0;
        this.ts_creation_sec = 0;
        this.ts_creation_nsec = 0;
        this.subject = "";
        this.plaintext_version = "0";
        this.plaintext_version_parent = "0";
        this.crypto_cfg = new CryptoConfig();
        this.sender_fingerprint = new byte[0];
        this.recevr_fingerprints = new ArrayList<byte[]>();
        this.used_recevr_key_idx = -1;
        this.plaintext_hash_algo = "";
        this.plaintext_hash = new byte[0];
        this.valid = false;
    }

    PackHeader(final String target_path_,
               final long plaintext_size_,
               final long ts_creation_sec_,
               final long ts_creation_nsec_,
               final String subject_,
               final String pversion, final String pversion_parent,
               final CryptoConfig crypto_cfg_,
               final byte[] sender_key_fingerprint_,
               final List<byte[]> recevr_fingerprint_,
               final int used_recevr_key_idx_,
               final String plaintext_hash_algo_,
               final byte[] plaintext_hash_,
               final boolean valid_) {
        this.target_path = target_path_;
        this.plaintext_size = plaintext_size_;
        this.ts_creation_sec = ts_creation_sec_;
        this.ts_creation_nsec = ts_creation_nsec_;
        this.subject = subject_;
        this.plaintext_version = pversion;
        this.plaintext_version_parent = pversion_parent;
        this.crypto_cfg = crypto_cfg_;
        this.sender_fingerprint = sender_key_fingerprint_;
        this.recevr_fingerprints = recevr_fingerprint_;
        this.used_recevr_key_idx = used_recevr_key_idx_;
        this.plaintext_hash_algo = plaintext_hash_algo_;
        this.plaintext_hash = plaintext_hash_;
        this.valid = valid_;
    }

    /**
     * Return a string representation
     * @param show_crypto_algos pass true if used crypto algos shall be shown, otherwise suppressed (default).
     * @param force_all_fingerprints if true always show all getTermKeysFingerprint(), otherwise show only the getTermKeysFingerprint() if >= 0 (default).
     * @return string representation
     */
    public String toString(final boolean show_crypto_algos, final boolean force_all_fingerprints) {
        final String crypto_str = show_crypto_algos ? ", "+crypto_cfg.toString() : "";

        final StringBuilder recevr_fingerprint = new StringBuilder();
        {
            if( 0 <= used_recevr_key_idx ) {
                final byte[] fp = recevr_fingerprints.get(used_recevr_key_idx);
                recevr_fingerprint.append( "dec '").append(BasicTypes.bytesHexString(fp, 0, fp.length, true /* lsb */)).append("', ");
            }
            if( force_all_fingerprints || 0 > used_recevr_key_idx ) {
                recevr_fingerprint.append("enc[");
                int i = 0;
                for(final byte[] tkf : recevr_fingerprints) {
                    if( 0 < i ) {
                        recevr_fingerprint.append(", ");
                    }
                    recevr_fingerprint.append("'").append(BasicTypes.bytesHexString(tkf, 0, tkf.length, true /* lsb */)).append("'");
                    ++i;
                }
                recevr_fingerprint.append("]");
            }
        }
        final ZonedDateTime utc_creation = Instant.ofEpochSecond(ts_creation_sec, ts_creation_nsec).atZone(ZoneOffset.UTC);
        final String res = "Header[valid "+valid+
               ", file[target_path '"+target_path+"', plaintext_size "+String.format("%,d", plaintext_size)+
               "], creation "+utc_creation.toString()+" , subject '"+subject+"', "+
               " version['"+plaintext_version+
               "', parent '"+plaintext_version_parent+"']"+crypto_str+
               ", fingerprints[sender '"+BasicTypes.bytesHexString(sender_fingerprint, 0, sender_fingerprint.length, true /* lsb */)+
               "', recevr["+recevr_fingerprint+
               "]], phash['"+plaintext_hash_algo+"', sz "+plaintext_hash.length+"]]";
        return res;
    }

    public final boolean isValid() { return valid; }

    /**
     * Return a string representation
     * @return string representation
     */
    @Override
    public String toString() {
        return toString(false, false);
    }
}
