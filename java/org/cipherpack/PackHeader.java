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

public class PackHeader {
    /** Designated decrypted target path of the file from DER-Header-1, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final String target_path;

    /** Plaintext content size in bytes, i.e. decrypted payload size, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final long content_size;

    /** Creation time in milliseconds since Unix epoch, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final long ts_creation;

    /** Intention of the file from DER-Header-1, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final String intention;

    /** Payload version, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final int payload_version; // FIXME: std::string  VENDOR_VERSION

    /** Payload's parent version, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final int payload_version_parent; // FIXME: std::string VENDOR_VERSION

    public final CryptoConfig crypto_cfg;

    /** Used host key fingerprint used to sign, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final String host_key_fingerprint;

    /** List of public keys fingerprints used to encrypt the file-key, see @ref cipherpack_stream "Cipherpack Data Stream". */
    public final List<String> term_keys_fingerprint;

    /** Index of the matching public key fingerprints used to decrypt the file-key or -1 if not found or performing the encryption operation.. */
    public final int term_key_fingerprint_used_idx;

    public final boolean valid;

    PackHeader() {
        this.target_path = "";
        this.content_size = 0;
        this.ts_creation = 0;
        this.intention = "";
        this.payload_version = 0;
        this.payload_version_parent = 0;
        this.crypto_cfg = new CryptoConfig();
        this.host_key_fingerprint = "";
        this.term_keys_fingerprint = new ArrayList<String>();
        this.term_key_fingerprint_used_idx = -1;
        this.valid = false;
    }

    PackHeader(final String target_path_,
               final long content_size_,
               final long ts_creation_,
               final String intention_,
               final int pversion, final int pversion_parent,
               final CryptoConfig crypto_cfg_,
               final String host_key_fingerprint_,
               final List<String> term_keys_fingerprint_,
               final int term_key_fingerprint_used_idx_,
               final boolean valid_) {
        this.target_path = target_path_;
        this.content_size = content_size_;
        this.ts_creation = ts_creation_;
        this.intention = intention_;
        this.payload_version = pversion;
        this.payload_version_parent = pversion_parent;
        this.crypto_cfg = crypto_cfg_;
        this.host_key_fingerprint = host_key_fingerprint_;
        this.term_keys_fingerprint = term_keys_fingerprint_;
        this.term_key_fingerprint_used_idx = term_key_fingerprint_used_idx_;
        this.valid = valid_;
    }

    /**
     * Return a string representation
     * @param show_crypto_algos pass true if used crypto algos shall be shown, otherwise suppressed (default).
     * @param force_all_fingerprints if true always show all getTermKeysFingerprint(), otherwise show only the getTermKeysFingerprint() if >= 0 (default).
     * @return string representation
     */
    public String toString(final boolean show_crypto_algos, final boolean force_all_fingerprints) {
        final String crypto_str = show_crypto_algos ? crypto_cfg.toString() : "";

        final StringBuilder term_fingerprint = new StringBuilder();
        {
            if( 0 <= term_key_fingerprint_used_idx ) {
                term_fingerprint.append( "dec '").append(term_keys_fingerprint.get(term_key_fingerprint_used_idx)).append("', ");
            }
            if( force_all_fingerprints || 0 > term_key_fingerprint_used_idx ) {
                term_fingerprint.append("enc[");
                int i = 0;
                for(final String tkf : term_keys_fingerprint) {
                    if( 0 < i ) {
                        term_fingerprint.append(", ");
                    }
                    term_fingerprint.append("'").append(tkf).append("'");
                    ++i;
                }
                term_fingerprint.append("]");
            }
        }
        final ZonedDateTime utc_creation = Instant.ofEpochMilli(ts_creation).atZone(ZoneOffset.UTC);
        final String res = "Header[valid "+valid+
               ", file[target_path "+target_path+", content_size "+String.format("%,d", content_size)+
               "], creation "+utc_creation.toString()+" , intention '"+intention+"', "+
               " version["+payload_version+
               ", parent "+payload_version_parent+crypto_str+
               "], fingerprints[sign/host '"+host_key_fingerprint+
               "', term["+term_fingerprint+
               "]]]";
        return res;
    }

    /**
     * Return a string representation
     * @return string representation
     */
    @Override
    public String toString() {
        return toString(false, false);
    }

}
