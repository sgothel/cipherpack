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
 * Listener for events occurring while processing a cipherpack message via encryptThenSign() and checkSignThenDecrypt().
 *
 * @see @ref cipherpack_overview "Cipherpack Overview"
 * @see @ref cipherpack_stream "Cipherpack Data Stream"
 */
public class CipherpackListener extends CPNativeDownlink {
    public static enum ContentType {
        HEADER ( (byte)0 ),
        MESSAGE ( (byte)1 );

        /**
         * Maps the specified integer value to a constant of {@link ContentType}.
         * @param value the integer value to be mapped to a constant of this enum type.
         * @return the corresponding constant of this enum type.
         * @throws IllegalArgumentException is value is unknown
         */
        public static ContentType get(final byte value) throws IllegalArgumentException {
            switch(value) {
                case (byte)0x01: return HEADER;
                case (byte)0x02: return MESSAGE;
                default: throw new IllegalArgumentException("Unknown ContentType value "+value);
            }
        }

        ContentType(final byte v) { value = v; }
        final byte value;
    };

    public CipherpackListener() {
        super(); // pending native ctor
        if( CPFactory.isInitialized() ) {
            initDownlink(ctorImpl());
        } else {
            System.err.println("AdapterStatusListener.ctor: CPFactory not initialized, no nativeInstance");
        }
    }
    private native long ctorImpl();

    @Override
    protected native void deleteImpl(long nativeInstance);

    /**
     * Returns true if native instance is valid, otherwise false.
     */
    public final boolean isValid() { return isNativeValid(); }

    /**
     * Informal user notification about an error via text message.
     *
     * This message will be send before a subsequent notifyHeader() and notifyEnd() with an error indication.
     * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
     * @param msg the error message
     */
    public void notifyError(final boolean decrypt_mode, final String msg) { }

    /**
     * User notification of PackHeader
     * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
     * @param header the PackHeader
     * @param verified true if header signature is verified and deemed valid, otherwise false regardless of true == PackHeader::isValid().
     */
    public void notifyHeader(final boolean decrypt_mode, final PackHeader header, final boolean verified) { }

    /**
     * User notification about content streaming progress.
     *
     * In case contentProcessed() gets called, notifyProgress() is called thereafter.
     *
     * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
     * @param plaintext_size the plaintext message size, zero if not determined yet
     * @param bytes_processed the number of unencrypted bytes processed
     * @see contentProcessed()
     */
    public void notifyProgress(final boolean decrypt_mode, final long plaintext_size, final long bytes_processed) { }

    /**
     * User notification of process completion.
     * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
     * @param header the PackHeader
     * @param success true if process has successfully completed and result is deemed valid, otherwise result is invalid regardless of true == PackHeader::isValid().
     */
    public void notifyEnd(final boolean decrypt_mode, final PackHeader header, final boolean success) { }

    /**
     * User provided information whether process shall send the processed content via contentProcessed() or not
     * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
     * @return true if process shall call contentProcessed(), otherwise false (default)
     * @see contentProcessed()
     */
    public boolean getSendContent(final boolean decrypt_mode) { return false; }

    /**
     * User callback to receive the actual processed content, either the generated cipherpack or plaintext content depending on decrypt_mode.
     *
     * This callback is only enabled if getSendContent() returns true.
     *
     * In case contentProcessed() gets called, notifyProgress() is called thereafter.
     *
     * @param decrypt_mode true if sender is decrypting, otherwise sender is encrypting
     * @param ctype content_type of passed data. Always {@link ContentType#MESSAGE} if decrypt_mode is true.
     * @param data the processed content, either the generated cipherpack or plaintext content depending on decrypt_mode.
     * @param is_final true if this is the last content call, otherwise false
     * @return true to signal continuation, false to end streaming.
     * @see getSendContent()
     */
    public boolean contentProcessed(final boolean decrypt_mode, final ContentType ctype, final byte[] data, final boolean is_final) { return true; }

    private final boolean contentProcessedImpl(final boolean decrypt_mode, final boolean is_header, final byte[] data, final boolean is_final) {
        return contentProcessed(decrypt_mode, is_header ? ContentType.HEADER : ContentType.MESSAGE, data, is_final);
    }

    @Override
    public String toString() {
        return "CipherpackListener[valid "+isValid()+"]";
    }
};
