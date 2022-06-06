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
package test.org.cipherpack;

import java.nio.ByteBuffer;

import org.cipherpack.CPFactory;
import org.cipherpack.CPUtils;

import jau.test.junit.util.SingletonJunitCase;

public class data_test extends SingletonJunitCase {
    static {
        {
            // System.setProperty("org.cipherpack.debug", "true"); // java
            // System.setProperty("org.cipherpack.verbose", "true"); // java
            // System.setProperty("cipherpack.debug", "true"); // native
            System.setProperty("cipherpack.verbose", "true"); // native
        }
        CPFactory.checkInitialized();
    }

    public static final long io_timeout = 10000; // 10_s;

    public static final String enc_pub_key1_fname = "../../../test_keys/terminal_rsa1.pub.pem";
    public static final String dec_sec_key1_fname = "../../../test_keys/terminal_rsa1";

    public static final String enc_pub_key2_fname = "../../../test_keys/terminal_rsa2.pub.pem";
    public static final String dec_sec_key2_fname = "../../../test_keys/terminal_rsa2";

    public static final String enc_pub_key3_fname = "../../../test_keys/terminal_rsa3.pub.pem";
    public static final String dec_sec_key3_fname = "../../../test_keys/terminal_rsa3";

    public static final String enc_pub_key4_fname = "../../../test_keys/terminal_rsa4.pub.pem";
    public static final String dec_sec_key4_fname = "../../../test_keys/terminal_rsa4";

    public static final ByteBuffer dec_sec_key_passphrase = null;

    public static final String sign_pub_key1_fname = "../../../test_keys/host_rsa1.pub.pem";
    public static final String sign_sec_key1_fname = "../../../test_keys/host_rsa1";

    public static final String sign_pub_key2_fname = "../../../test_keys/host_rsa2.pub.pem";
    public static final String sign_sec_key2_fname = "../../../test_keys/host_rsa2";

    public static final String sign_pub_key3_fname = "../../../test_keys/host_rsa3.pub.pem";
    public static final String sign_sec_key3_fname = "../../../test_keys/host_rsa3";

    public static final String sign_pub_key4_fname = "../../../test_keys/host_rsa4.pub.pem";
    public static final String sign_sec_key4_fname = "../../../test_keys/host_rsa4";

    public static final ByteBuffer sign_sec_key_passphrase = CPUtils.newDirectByteBuffer(0);

    public static final String url_input_root = "http://localhost:8080/";
}
