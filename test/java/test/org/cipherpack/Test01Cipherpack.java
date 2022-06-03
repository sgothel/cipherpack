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

package test.org.cipherpack;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cipherpack.CPFactory;
import org.cipherpack.CPUtils;
import org.cipherpack.Cipherpack;
import org.cipherpack.CipherpackListener;
import org.cipherpack.CryptoConfig;
import org.cipherpack.PackHeader;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Test01Cipherpack extends data_test {
    static final boolean DEBUG = false;

    static final String payload_version = "0";
    static final String payload_version_parent = "0";

    static final int IDX_11kiB = 0;
    static final int IDX_65MiB = 1;
    static List<String> fname_payload_lst = new ArrayList<String>();
    static List<String> fname_payload_encrypted_lst = new ArrayList<String>();
    static List<String> fname_payload_decrypted_lst = new ArrayList<String>();

    static boolean remove_file(final String name) {
            final File file = new File( name );
            try {
                if( file.exists() ) {
                    if( !file.delete() ) {
                        CPUtils.println(System.err, "Remove.1: Failed deletion of existing file "+name);
                        return false;
                    }
                }
                return true;
            } catch (final Exception ex) {
                CPUtils.println(System.err, "Remove.2: Failed deletion of existing file "+name+": "+ex.getMessage());
                ex.printStackTrace();
            }
            return false;
    }
    static void add_test_file(final String name, final long size) {
            Assert.assertTrue( remove_file(name) );
            Assert.assertTrue( remove_file(name+".enc") );
            Assert.assertTrue( remove_file(name+".enc.dec") );
            {
                final String one_line = "Hello World, this is a test and I like it. Exactly 100 characters long. 0123456780 abcdefghjklmnop..";
                final Charset charset = Charset.forName("ASCII");
                final byte[] one_line_bytes = one_line.getBytes(charset);

                final File file = new File( name );
                OutputStream out = null;
                try {
                    Assert.assertFalse( file.exists() );

                    out = new FileOutputStream(file);

                    for(long i=0; i < size; i+=one_line_bytes.length) {
                        out.write( one_line_bytes );
                    }
                    out.write( (byte)'X' ); // make it odd

                } catch (final Exception ex) {
                    CPUtils.println(System.err, "Write SMPKeyBin: Failed "+name+": "+ex.getMessage());
                    ex.printStackTrace();
                } finally {
                    try {
                        if( null != out ) {
                            out.close();
                        }
                    } catch (final IOException e) {
                        e.printStackTrace();
                    }
                }

            }
            fname_payload_lst.add(name);
            fname_payload_encrypted_lst.add(name+".enc");
            fname_payload_decrypted_lst.add(name+".enc.dec");
    }

    static {
        {
            // System.setProperty("org.cipherpack.debug", "true"); // java
            // System.setProperty("org.cipherpack.verbose", "true"); // java
            // System.setProperty("cipherpack.debug", "true"); // native
            System.setProperty("cipherpack.verbose", "true"); // native
        }
        add_test_file("test_cipher_01_11kiB.bin", 1024*11);
        add_test_file("test_cipher_02_65MiB.bin", 1024*1024*65);
    }

    static boolean system(final String[] command) {
        Process proc = null;
        try{
            proc = Runtime.getRuntime().exec(command);
            proc.waitFor();
            return true;
        }
        catch(final Exception ex)
        {
            if(proc!=null) {
                proc.destroy();
            }
            ex.printStackTrace();
        }
        return false;
    }

    @AfterClass
    public static void httpd_stop() {
        Assert.assertTrue( system(new String[]{"killall", "mini_httpd"}) );
        Assert.assertTrue( system(new String[]{"killall", "mini_httpd"}) );
    }

    static void httpd_start() {
        Assert.assertTrue( system(new String[]{"killall", "mini_httpd"}) );
        Assert.assertTrue( system(new String[]{"killall", "mini_httpd"}) );
        Assert.assertTrue( system(new String[]{"/usr/sbin/mini_httpd", "-p", "8080"}) );
    }

    CipherpackListener silentListener = new CipherpackListener();

    @Test(timeout = 10000)
    public final void test01_enc_dec_file_ok() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final int file_idx = IDX_11kiB;
            final String source_loc = fname_payload_lst.get(file_idx);
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source_loc, io_timeout,
                                                              fname_payload_lst.get(file_idx), "test_case", payload_version, payload_version_parent,
                                                              silentListener, fname_payload_encrypted_lst.get(file_idx));
            CPUtils.fprintf_td(System.err, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_payload_lst.get(file_idx), fname_payload_encrypted_lst.get(file_idx));
            CPUtils.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true));
            Assert.assertTrue( ph1.isValid() );

            final String enc_stream_loc = fname_payload_encrypted_lst.get(file_idx);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream_loc, io_timeout,
                                                                   silentListener, fname_payload_decrypted_lst.get(file_idx));
            CPUtils.fprintf_td(System.err, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_payload_encrypted_lst.get(file_idx), fname_payload_decrypted_lst.get(file_idx));
            CPUtils.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true));
            Assert.assertTrue( ph2.isValid() );
        }
    }

    public static void main(final String args[]) {
        org.junit.runner.JUnitCore.main(Test01Cipherpack.class.getName());
    }
}
